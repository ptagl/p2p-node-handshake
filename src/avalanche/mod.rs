pub mod network;

mod p2p;
mod tls;

pub use p2p::AvalancheClient;

use self::network::avalanche;

use chrono::{DateTime, Utc};
use std::fmt::Display;
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
    /// Unable to decompress an incoming message
    DecompressionError(Vec<u8>, String),
    /// Unable to convert the string into a valid [IP]:[PORT] pair.
    InvalidAddress(String),
    /// The P2P message size exceeds the max limit allowed.
    InvalidMessageSize(usize, usize),
    /// Unable to convert the IP address into a server name for the TLS connection.
    InvalidServerName(String, String),
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
    /// An unexpected message was received compared to the order specified by the protocol.
    /// The first type is the expected message, the second is the current one.
    WrongMessageOrder(MessageType, MessageType),
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
            Self::InvalidServerName(server_name, error_message) => {
                write!(
                    f,
                    "Unable to parse server name, input is {}, error: {}",
                    server_name, error_message
                )
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
            Self::WrongMessageOrder(expected, received) => write!(
                f,
                "Wrong message order, expected {:?}, found {:?}",
                expected, received
            ),
        }
    }
}

impl PartialEq for P2pError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AsyncOperationError(l0), Self::AsyncOperationError(r0)) => {
                l0.to_string() == r0.to_string()
            }
            (Self::CertificateGenerationError(l0), Self::CertificateGenerationError(r0)) => {
                l0 == r0
            }
            (Self::ConnectionError(l0, l1), Self::ConnectionError(r0, r1)) => l0 == r0 && l1 == r1,
            (Self::DecompressionError(l0, l1), Self::DecompressionError(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (Self::InvalidAddress(l0), Self::InvalidAddress(r0)) => l0 == r0,
            (Self::InvalidMessageSize(l0, l1), Self::InvalidMessageSize(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (Self::InvalidServerName(l0, l1), Self::InvalidServerName(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (
                Self::MessageDeserializationError(l0, l1),
                Self::MessageDeserializationError(r0, r1),
            ) => l0 == r0 && l1 == r1,
            (Self::StreamConfigurationError(l0), Self::StreamConfigurationError(r0)) => l0 == r0,
            (Self::StreamError(l0), Self::StreamError(r0)) => l0 == r0,
            (Self::TlsConfigurationError(l0, l1), Self::TlsConfigurationError(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (Self::UnknownMessage(l0), Self::UnknownMessage(r0)) => l0 == r0,
            (Self::WrongMessageOrder(l0, l1), Self::WrongMessageOrder(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            _ => false,
        }
    }
}

/// It represents all the possible statuses for a P2P connection.
#[derive(Debug)]
pub enum ConnectionStatus {
    /// The connection has been established and is currently open,
    /// but the handshake has not been completed yet.
    Connected(DateTime<Utc>),
    /// The node is performing the handshaking with the remote peer.
    HandshakeStarted(DateTime<Utc>),
    /// The handshaking phase was completed successfully.
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

/// This enum is used to enforce some basic rules in messages processing,
/// like that any P2P communication must start with a Version message,
/// immediately followed by a PeerList message.
/// This sequence completes the handshake phase.
/// Any other message could be only received after this phase.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    /// The Version message is the first sent in the P2P sequence.
    Version,
    /// The PeerList message is the second in the sequence, it follows the Version one.
    PeerList,
    /// Any message type, it could be sent after having received a PeerList message,
    /// indicating the successful completion of the handshake procedure.
    Any,
}
