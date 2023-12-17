use std::{
    io::{ErrorKind, Read},
    net::TcpStream,
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use protobuf::Message;
use rustls::{Certificate, ClientConnection, PrivateKey, StreamOwned};
use tokio::sync::Mutex;

use crate::avalanche::{MAX_MESSAGE_LENGTH, MESSAGE_HEADER_LENGTH};

use super::{ConnectionStatus, P2pError};

// Include the protobuf generated code for the Avalanche P2P messages
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

type ReceivedMessageQueue = mpsc::Sender<avalanche::Message>;
type StatusUpdateQueue = mpsc::Sender<ConnectionStatus>;

pub struct NetworkHandler {
    /// Certificate for the TLS connection
    certificate: Certificate,

    /// A pair storing the instant in which the connection was established
    /// and the instant in which it was closed. It is useful for
    /// computing the connection duration.
    connection_instants: (Option<Instant>, Option<Instant>),

    /// Private key for the TLS connection.
    private_key: PrivateKey,

    /// MPSC channel sender to queue messages received from the network.
    received_messages_queue: ReceivedMessageQueue,

    /// MPSC channel sender to periodically report information about
    /// the connection status.
    status_update_queue: StatusUpdateQueue,

    /// TLS stream for read/write operations.
    tls_stream: Arc<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>>,
}

impl NetworkHandler {
    /// Creates a new instance of network handler, initializing the MPSC channels for communicating with the layer above.
    pub fn new(
        received_messages_sender: ReceivedMessageQueue,
        status_update_sender: StatusUpdateQueue,
    ) -> Result<Self, P2pError> {
        // Generate a private key and a certificate for establishing the TLS connection
        let (private_key, certificate) = cert_manager::x509::generate_der(None)
            .map_err(|error| P2pError::CertificateGenerationError(error.to_string()))?;

        Ok(Self {
            certificate,
            connection_instants: (None, None),
            private_key,
            received_messages_queue: received_messages_sender,
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
        self.connection_instants = (Some(Instant::now()), None);
        _ = self.status_update_queue.send(self.connection_status());

        Ok(())
    }

    /// Starts reading bytes from the socket until one of the
    /// following things happen:
    /// - an error occurrs
    /// - the connection is closed
    #[allow(clippy::read_zero_byte_vec)] // False positive, see https://github.com/rust-lang/rust-clippy/issues/9274
    pub async fn read_bytes(mut self) -> Result<Self, P2pError> {
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
                        Err(error) => {
                            println!("Unexpected stream error: {:?}", error);

                            // Notify the disconnection and stop the async task
                            self.set_disconnection_instant();
                            return Err(P2pError::StreamError(error.to_string()));
                        }
                    }
                } else {
                    panic!("Unexpected error: stream Option was None!!!");
                }
            }
        }

        let stream = self.tls_stream.clone();

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
            if self.received_messages_queue.send(message).is_err() {
                disconnect!(stream);
                return Ok(self);
            }
        }
    }

    /// Returns the status of the connection (connected or disconnected).
    pub fn connection_status(&self) -> ConnectionStatus {
        match self.connection_instants {
            // If the end instant has been set, then the connection was terminated
            (Some(start_instant), Some(end_instant)) => {
                ConnectionStatus::Closed(end_instant - start_instant)
            }
            // If the end instant has not been set yet, the connection is still open
            (Some(start_instant), None) => {
                ConnectionStatus::Connected(Instant::now() - start_instant)
            }
            (None, _) => ConnectionStatus::NotStarted(),
        }
    }

    /// Updates the disconnection instant with the current time.
    fn set_disconnection_instant(&mut self) {
        let (_, disconnection_instant) = &mut self.connection_instants;
        *disconnection_instant = Some(Instant::now());

        // Notify the eventual receiver
        _ = self.status_update_queue.send(self.connection_status());
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
