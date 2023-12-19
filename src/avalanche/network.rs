use std::{
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    sync::{mpsc, Arc},
    time::{Duration, SystemTime},
};

use protobuf::Message;
use rustls::{Certificate, ClientConnection, PrivateKey, StreamOwned};
use tokio::sync::Mutex;

use crate::avalanche::{MAX_MESSAGE_LENGTH, MESSAGE_HEADER_LENGTH};

use super::{ConnectionStatus, P2pError};

// Include the protobuf generated code for the Avalanche P2P messages
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

type ReceivedMessageQueue = mpsc::Sender<avalanche::Message>;
type SendMessageQueue = mpsc::Receiver<avalanche::Message>;
type StatusUpdateQueue = mpsc::Sender<ConnectionStatus>;

pub struct NetworkHandler {
    /// Certificate for the TLS connection
    certificate: Certificate,

    /// Private key for the TLS connection.
    private_key: PrivateKey,

    /// MPSC channel sender to queue messages received from the network.
    received_messages_queue: ReceivedMessageQueue,

    /// MPSC channel receiver to queue messages to be sent to the network.
    send_messages_queue: SendMessageQueue,

    /// MPSC channel sender to periodically report information about
    /// the connection status.
    status_update_queue: StatusUpdateQueue,

    /// TLS stream for read/write operations.
    tls_stream: Arc<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>>,
}

impl NetworkHandler {
    /// Creates a new instance of network handler, initializing the MPSC channels for communicating with the layer above.
    pub fn new(
        private_key: PrivateKey,
        certificate: Certificate,
        received_messages_sender: ReceivedMessageQueue,
        send_messages_sender: SendMessageQueue,
        status_update_sender: StatusUpdateQueue,
    ) -> Result<Self, P2pError> {
        Ok(Self {
            certificate,
            private_key,
            received_messages_queue: received_messages_sender,
            send_messages_queue: send_messages_sender,
            status_update_queue: status_update_sender,
            tls_stream: Arc::new(Mutex::new(None)),
        })
    }

    /// Starts a connection to the destination_address and returns a [`NetworkHandler`]
    /// instance. If the connection fails, an error is returned instead.
    pub fn connect(&mut self, destination_address: &str) -> Result<(), P2pError> {
        // Extract the IP address from the destination address ([IP]:[PORT])
        let (ip_address, _) = destination_address
            .split_once(':')
            .ok_or_else(|| P2pError::InvalidAddress(destination_address.to_string()))?;

        let tls_connection = tls::get_tls_connection(
            ip_address,
            self.private_key.clone(),
            self.certificate.clone(),
        )?;
        let stream = TcpStream::connect(destination_address).map_err(|error| {
            P2pError::ConnectionError(destination_address.to_string(), error.to_string())
        })?;
        // Set the stream as non-blocking when performing read/write operations
        stream.set_nonblocking(true).map_err(|error| {
            // Try to close the stream
            _ = stream.shutdown(std::net::Shutdown::Both);
            P2pError::StreamConfigurationError(error.to_string())
        })?;

        self.tls_stream = Arc::new(Mutex::new(Some(StreamOwned::new(tls_connection, stream))));
        _ = self
            .status_update_queue
            .send(ConnectionStatus::Connected(SystemTime::now().into()));

        Ok(())
    }

    /// Async function that runs both read and write threads.
    pub async fn read_and_write(self) -> Result<(), P2pError> {
        // Spawn read/write threads
        let handles = vec![
            tokio::spawn(NetworkHandler::read_bytes(
                self.tls_stream.clone(),
                self.received_messages_queue.clone(),
            )),
            tokio::spawn(NetworkHandler::write_bytes(
                self.tls_stream.clone(),
                self.send_messages_queue,
            )),
        ];

        // Wait for the async tasks to stop
        for handle in handles {
            match handle.await {
                // Return self just in case it is needed for later checks or operations
                Ok(Ok(_)) => {}
                Ok(Err(error)) => return Err(P2pError::StreamError(error.to_string())), // read error
                Err(error) => return Err(P2pError::AsyncOperationError(error)), // Future error
            }
        }

        _ = self
            .status_update_queue
            .send(ConnectionStatus::Closed(SystemTime::now().into()));

        // If the execution reaches this point, the TLS connection was closed.
        Ok(())
    }

    /// Starts reading bytes from the socket until one of the
    /// following things happen:
    /// - an error occurrs
    /// - the connection is closed
    #[allow(clippy::read_zero_byte_vec)] // False positive, see https://github.com/rust-lang/rust-clippy/issues/9274
    async fn read_bytes(
        stream: Arc<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>>,
        received_message_queue: ReceivedMessageQueue,
    ) -> Result<(), P2pError> {
        /// Macro that simplifies the disconnection of the node (for instance, in case of an unrecoverable error or DoS detection).
        macro_rules! disconnect {
            ($tls_stream:expr) => {
                if let Some(stream) = $tls_stream.lock().await.as_mut() {
                    _ = stream.get_mut().shutdown(std::net::Shutdown::Both);
                } else {
                    panic!("Unexpected error: stream Option was None!!!");
                }
            };
        }

        /// Macro that simplifies reading bytes from the stream
        /// 1. In case of success => nothing to do
        /// 2. In case of [`ErrorKind::WouldBlock`] => continue the outer loop
        /// 3. In case of any other stream error => return an error and stop the async task
        ///
        /// There is also a call to [`panic!`] in case the Option stream is not found, but
        /// that should never happen unless there is a major flaw in the code.
        macro_rules! read_exact {
            ($tls_stream:expr, $buffer:expr, $label:tt) => {
                if let Some(stream) = $tls_stream.lock().await.as_mut() {
                    match stream.read_exact(&mut $buffer) {
                        Ok(_) => {},
                        // WouldBlock is returned by non-blocking streams when there is no data to read yet
                        Err(error) if error.kind() == ErrorKind::WouldBlock => continue $label,
                        Err(error) => return Err(P2pError::StreamError(error.to_string()))
                    }
                } else {
                    panic!("Unexpected error: stream Option was None!!!");
                }
            }
        }

        // Use this buffer to read the header of any P2P message.
        // The protocol uses 4 bytes to store the size of the following message.
        let mut message_len_bytes = [0u8; MESSAGE_HEADER_LENGTH];

        // Buffer used to read bytes of a single P2P message.
        // Let's assign the max capacity to avoid continuous reallocations.
        // We use this variable also to understand whether the header has to be read or it's already been
        // read and is it possible to proceed with the payload.
        let mut message_bytes = Vec::<u8>::with_capacity(MAX_MESSAGE_LENGTH);

        // This loop runs both the deserialization of the header and of the payload.
        'read_loop: loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Read the header (message length) only if this is the first iteration or
            // we completed the deserialization of the previous message.
            if message_bytes.is_empty() {
                // Read the "header" of the message, containing the size of the payload
                read_exact!(stream, message_len_bytes, 'read_loop);

                // This is the size of the next message to read
                let message_len = u32::from_be_bytes(message_len_bytes) as usize;

                // IMPORTANT: always validate the message_len as an attacker may cause memory exhaustion
                match message_len {
                    len if len > MAX_MESSAGE_LENGTH => {
                        println!(
                            "Max message size [{} bytes] exceeded [{} bytes], disconnecting...",
                            MAX_MESSAGE_LENGTH, len
                        );

                        // Close the stream as the remote node seems to be acting maliciously
                        disconnect!(stream);

                        return Err(P2pError::InvalidMessageSize(len, MAX_MESSAGE_LENGTH));
                    }
                    0 => {
                        // This is odd, the header includes a "null" size, but it's not possible to have an emptyu message.
                        // We don't expect anything good to come after that, but let's try to be optimistic
                        // and just skip this header instead of closing the connection.
                        continue;
                    }
                    _ => message_bytes.resize(message_len, 0),
                }
            }

            // Reaching this point with an empty buffer would be symptom of a bug in the code
            assert!(!message_bytes.is_empty());

            // Read the payload of the message
            read_exact!(stream, message_bytes, 'read_loop);

            // Attempt of deserializing the message
            let parse_result = avalanche::Message::parse_from_bytes(&message_bytes);

            // Clear the buffer so that at the next iteration we know the header has to be read first.
            message_bytes.clear();

            let message = match parse_result {
                Ok(parsed_message) => parsed_message,
                Err(error) => {
                    println!(
                        "An error occurred while deserializing the message: {:?}",
                        error
                    );

                    // Hopefully the error is recoverable, just ignore the message and continue
                    continue;
                }
            };

            // If queuing the message fails, it means that the top layer stopped listening,
            // so we can stop reading from the socket.
            if received_message_queue.send(message).is_err() {
                disconnect!(stream);
                return Ok(());
            }
        }
    }

    /// Deserializes P2P messages and sent them to the destination peer.
    async fn write_bytes(
        stream: Arc<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>>,
        send_message_queue: SendMessageQueue,
    ) -> Result<(), P2pError> {
        loop {
            // recv() is blocking and seems fine here as the function should do nothing if there are no messages to send.
            let message = match send_message_queue.recv() {
                Ok(message) => message,
                Err(_) => return Ok(()), // The channel has been closed, stop the thread
            };

            // Attempt of serializing the message
            let payload_bytes = match message.write_to_bytes() {
                Ok(payload) => payload,
                Err(error) => {
                    println!(
                        r#"An error occurred while serializing the message, it will be skipped.
                                Error: {}\n
                                {}\n"#,
                        error, message
                    );

                    // A serialization error here would be odd and probably just the tip of the iceberg, but be optimistic and just skip.
                    continue;
                }
            };

            let header_bytes = (payload_bytes.len() as u32).to_be_bytes();
            let message_bytes = [header_bytes.to_vec(), payload_bytes].concat();

            // Lock the stream and write the message.
            if let Some(stream) = stream.lock().await.as_mut() {
                match stream.write_all(message_bytes.as_slice()) {
                    Ok(_) => {}
                    Err(error) => {
                        println!("Write error: {}", error);

                        // A stream error is typically not recoverable (e.g. broken pipe, disconnection, etc.), so we can stop the loop.
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Module containing helper functions to setup TLS connections.
mod tls {
    use std::{sync::Arc, time::SystemTime};

    use rustls::{
        client::ServerCertVerifier, Certificate, ClientConfig, ClientConnection, PrivateKey,
        ServerName,
    };

    use crate::avalanche::P2pError;

    /// Initializes a TLS connection configuration to connect to Avalanche nodes.
    pub fn get_tls_connection(
        ip_address: &str,
        private_key: PrivateKey,
        certificate: Certificate,
    ) -> Result<ClientConnection, P2pError> {
        let server_name = ServerName::try_from(ip_address)
            .map_err(|error| P2pError::InvalidServerName(error.to_string()))?;

        // Prepare a basic configuration
        let config = Arc::new(
            get_default_tls_config((private_key.clone(), certificate.clone())).map_err(
                |error| P2pError::TlsConfigurationError(ip_address.to_string(), error.to_string()),
            )?,
        );

        Ok(ClientConnection::new(config, server_name).map_err(|error| {
            P2pError::TlsConfigurationError(ip_address.to_string(), error.to_string())
        }))?
    }

    /// Returns a basic configuration to establish a TLS connection.
    /// This shouldn't be used in production as, for instance,
    /// the certificate verification is disable (see [`NoCertificateVerification`]).
    fn get_default_tls_config(
        (private_key, certificate): (PrivateKey, Certificate),
    ) -> Result<ClientConfig, String> {
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_client_auth_cert(vec![certificate], private_key)
            .map_err(|error| error.to_string())
    }

    /// Mock struct to disable the verification of TLS certificates.
    /// This is needed as Avalanche nodes may have self-signed certificates.
    struct NoCertificateVerification {}

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}
