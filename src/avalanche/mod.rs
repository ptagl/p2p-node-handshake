pub mod network;

mod p2p;
use chrono::{DateTime, Utc};
pub use p2p::AvalancheClient;

use std::fmt::Display;

use tokio::task::JoinError;

use self::network::avalanche;

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
    /// Unable to decompress an incoming message
    DecompressionError(Vec<u8>, String),
    /// Unable to convert the string into a valid [IP]:[PORT] pair.
    InvalidAddress(String),
    /// The P2P message size exceeds the max limit allowed.
    InvalidMessageSize(usize, usize),
    /// Unable to convert the IP address into a server name for the TLS connection.
    InvalidServerName(String),
    /// Unable to deserialize the message.
    MessageDeserializationError(Vec<u8>, String),
    /// Error while configuring the socket stream.
    StreamConfigurationError(String),
    /// Unexpected error in the TCP stream.
    StreamError(String),
    /// Unable to initialize the TLS configuration for the connection.
    TlsConfigurationError(String, String),
    /// The received message is not recognized.
    UnknownMessage(Box<Option<avalanche::message::Message>>),
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
            Self::DecompressionError(compressed_bytes, error_message) => write!(
                f,
                r#"Unable to decompress the message: {}

                Compressed bytes:
                {:?}

                "#,
                error_message, compressed_bytes
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
            Self::MessageDeserializationError(bytes, error_message) => {
                write!(
                    f,
                    r#"Unable to deserialize the message: {}

                   Serialized bytes:
                   {:?}

                "#,
                    error_message, bytes,
                )
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
            Self::UnknownMessage(message) => write!(f, "Unknown message received: {:?}", message),
        }
    }
}

/// It represents all the possible statuses for a P2P connection.
pub enum ConnectionStatus {
    /// The connection has been established and is currently open,
    /// but the handshake has not been completed yet.
    Connected(DateTime<Utc>),
    /// The node is performing the handshaking with the remote peer.
    HandshakeStarted(DateTime<Utc>),
    /// The handshaking phase was completed succesfully.
    HandshakeCompleted(DateTime<Utc>),
    /// The connection was closed.
    Closed(DateTime<Utc>),
}

impl Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected(event_time) => write!(f, "[{}] Peer connected", event_time),
            Self::HandshakeStarted(event_time) => write!(f, "[{}] Handshake started", event_time),
            Self::HandshakeCompleted(event_time) => {
                write!(
                    f,
                    r#"[{}] Handshake completed

                            ##############################
                            #   Handshake completed!!!   #
                            ##############################

                        "#,
                    event_time
                )
            }
            Self::Closed(event_time) => write!(f, "[{}] Connection closed", event_time),
        }
    }
}
