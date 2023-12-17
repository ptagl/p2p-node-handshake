use std::{
    error::Error,
    io::{ErrorKind, Read},
    net::TcpStream,
    sync::{mpsc, Arc},
    thread::sleep,
    time::{Duration, Instant},
};

use rustls::{Certificate, ClientConnection, PrivateKey, StreamOwned};
use tokio::sync::Mutex;

use super::{ConnectionStatus, P2pError};

pub struct NetworkHandler {
    /// Certificate for the TLS connection
    certificate: Certificate,

    /// A pair storing the instant in which the connection was established
    /// and the instant in which it was closed. It is useful for
    /// computing the connection duration.
    connection_instants: (Option<Instant>, Option<Instant>),

    /// Private key for the TLS connection.
    private_key: PrivateKey,

    /// MPSC channel sender to periodically report information about
    /// the connection status.
    status_update_sender: mpsc::Sender<ConnectionStatus>,

    /// TLS stream for read/write operations.
    tls_stream: Arc<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>>,
}

impl NetworkHandler {
    pub fn new(sender: mpsc::Sender<ConnectionStatus>) -> Result<Self, P2pError> {
        // Generate a private key and a certificate for establishing the TLS connection
        let (private_key, certificate) = cert_manager::x509::generate_der(None)
            .map_err(|error| P2pError::CertificateGenerationError(error.to_string()))?;

        Ok(Self {
            certificate,
            connection_instants: (None, None),
            private_key,
            status_update_sender: sender,
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
        _ = self.status_update_sender.send(self.connection_status());

        Ok(())
    }

    /// Starts reading bytes from the socket until one of the
    /// following things happen:
    /// - an error occurrs
    /// - the connection is closed
    pub async fn read_bytes(mut self) -> Result<Self, Box<dyn Error + Send>> {
        let mut buffer = [0u8; 1024];
        let stream = self.tls_stream.clone();

        loop {
            sleep(Duration::from_millis(100));

            if let Some(stream) = stream.lock().await.as_mut() {
                match stream.read(&mut buffer) {
                    // EOF, connection closed
                    Ok(0) => break,
                    Ok(read_bytes) => println!("Read {} bytes from the socket", read_bytes),
                    // WouldBlock is returned by non-blocking streams when there is no data to read yet
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) => {
                        println!("Unexpected stream error: {:?}", error);
                        self.set_disconnection_instant();
                        return Err(Box::new(error));
                    }
                }
            } else {
                panic!("Unexpected error: tls_stream Option was None!!!");
            }
        }

        self.set_disconnection_instant();
        Ok(self)
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
        _ = self.status_update_sender.send(self.connection_status());
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
