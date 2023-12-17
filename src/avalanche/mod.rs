use std::{fmt::Display, time::Duration};

pub mod network;

/// P2P errors handled by the network layer.
#[derive(Debug)]
pub enum P2pError {
    // Error while trying to generate a certificate for the TLS connection.
    CertificateGenerationError(String),
    /// Error while trying to establish a connection with the remote node.
    ConnectionError(String, String),
    /// Unable to convert the string into a valid [IP]:[PORT] pair.
    InvalidAddress(String),
    /// Unable to convert the IP address into a server name for the TLS connection.
    InvalidServerName(String),
    /// Error while configuring the socket stream.
    StreamConfigurationError(String),
    /// Unable to initialize the TLS configuration for the connection.
    TlsConfigurationError(String, String),
}

impl Display for P2pError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            Self::InvalidServerName(server_name) => {
                write!(f, "Unable to parse server name, input is: {}", server_name)
            }
            Self::StreamConfigurationError(error_message) => {
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
