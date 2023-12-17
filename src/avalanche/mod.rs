pub mod network;

mod p2p;
pub use p2p::AvalancheClient;

use std::{fmt::Display, time::Duration};

use tokio::task::JoinError;

/// Size in bytes of the P2P message header.
const MESSAGE_HEADER_LENGTH: usize = 4;

/// This constant is to prevent DoS attacks from malicious nodes.
/// For instance, we don't want to parse a message whose size is 10 GB and make the application crash.
const MAX_MESSAGE_LENGTH: usize = 1024 * 1024 * 4; // 4 MB

/// P2P errors handled by the network layer.
#[derive(Debug)]
pub enum P2pError {
    /// Error occurred while waiting for an async network task.
    AsyncOperationError(JoinError),
    // Error while trying to generate a certificate for the TLS connection.
    CertificateGenerationError(String),
    /// Error while trying to establish a connection with the remote node.
    ConnectionError(String, String),
    /// Unable to convert the string into a valid [IP]:[PORT] pair.
    InvalidAddress(String),
    /// The P2P message size exceeds the max limit allowed.
    InvalidMessageSize(usize, usize),
    /// Unable to convert the IP address into a server name for the TLS connection.
    InvalidServerName(String),
    /// Error while configuring the socket stream.
    StreamConfigurationError(String),
    /// Unexpected error in the TCP stream.
    StreamError(String),
    /// Unable to initialize the TLS configuration for the connection.
    TlsConfigurationError(String, String),
}

impl Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsyncOperationError(error) => write!(
                f,
                "Async error while waiting for task completion: {}",
                error
            ),
            Self::CertificateGenerationError(error_message) => write!(
                f,
                "Unable to generate a valid certificate for TLS connection: {}",
                error_message
            ),
            Self::ConnectionError(destination_address, error_message) => write!(
                f,
                "Unable to connect to [{}]: {}",
                destination_address, error_message
            ),
            Self::InvalidAddress(destination_address) => write!(
                f,
                "Unable to parse ip address and port, expected [ip]:[port], found {}",
                destination_address
            ),
            Self::InvalidMessageSize(message_size, max_message_size) => write!(
                f,
                "Message size ({} bytes) exceeded max allowed ({} bytes)",
                message_size, max_message_size
            ),
            Self::InvalidServerName(server_name) => {
                write!(f, "Unable to parse server name, input is: {}", server_name)
            }
            Self::StreamConfigurationError(error_message) => {
                write!(f, "Stream configuration error: {}", error_message)
            }
            Self::StreamError(error_message) => {
                write!(f, "Stream error: {}", error_message)
            }
            Self::TlsConfigurationError(ip_address, error_message) => write!(
                f,
                "Error while generating the TLS configuration for connecting to {}: {}",
                ip_address, error_message
            ),
        }
    }
}

/// It represents all the possible statuses for a P2P connection.
pub enum ConnectionStatus {
    /// Connection has not been established yet.
    NotStarted(),
    /// The connection has been established and is currently open.
    /// It includes also the elapsed time (from the instant in which
    /// the connection was established until now).
    Connected(Duration),

    /// The connection was closed. It includes the total time (from
    /// the instant in which the connection was established until it
    /// was closed).
    Closed(Duration),
}

impl Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted() => write!(f, "Not connected yet"),
            Self::Connected(elapsed_time) => {
                write!(f, "Connected for {} seconds", elapsed_time.as_secs())
            }
            Self::Closed(total_time) => write!(f, "Closed after {} seconds", total_time.as_secs()),
        }
    }
}
