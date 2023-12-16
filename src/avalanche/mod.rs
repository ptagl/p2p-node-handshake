use std::{fmt::Display, time::Duration};

pub mod network;

/// It represents all the possible statuses for a P2P connection.
pub enum ConnectionStatus {
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
            Self::Connected(elapsed_time) => {
                write!(f, "Connected for {} seconds", elapsed_time.as_secs())
            }
            Self::Closed(total_time) => write!(f, "Closed after {} seconds", total_time.as_secs()),
        }
    }
}
