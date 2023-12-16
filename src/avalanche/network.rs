use std::{
    error::Error,
    io::{ErrorKind, Read},
    net::TcpStream,
    sync::mpsc,
    thread::sleep,
    time::{Duration, Instant},
};

use super::ConnectionStatus;

pub struct NetworkHandler {
    /// A pair storing the instant in which the connection was established
    /// and the instant in which it was closed. It is useful for
    /// computing the connection duration.
    connection_instants: (Option<Instant>, Option<Instant>),

    /// MPSC channel sender to periodically report information about
    /// the connection status.
    status_update_sender: mpsc::Sender<ConnectionStatus>,

    /// Network stream for read/write operations.
    stream: Option<TcpStream>,
}

impl NetworkHandler {
    pub fn new(sender: mpsc::Sender<ConnectionStatus>) -> Self {
        Self {
            connection_instants: (None, None),
            status_update_sender: sender,
            stream: None,
        }
    }

    /// Starts a connection to the destination_address and returns a [`NetworkHandler`]
    /// instance. If the connection fails, an error is returned instead.
    pub fn connect(&mut self, destination_address: &str) -> Result<(), Box<dyn Error>> {
        self.stream = Some(TcpStream::connect(destination_address)?);
        self.connection_instants = (Some(Instant::now()), None);
        _ = self.status_update_sender.send(self.connection_status());

        // Set the stream as non-blocking when performing read/write operations
        self.stream.as_mut().unwrap().set_nonblocking(true)?;

        Ok(())
    }

    /// Starts reading bytes from the socket until one of the
    /// following things happen:
    /// - an error occurrs
    /// - the connection is closed
    pub async fn read_bytes(mut self) -> Result<Self, Box<dyn Error + Send>> {
        let mut buffer = [0u8; 1024];
        let stream = self.stream.as_mut().unwrap();

        loop {
            sleep(Duration::from_millis(100));

            match stream.read(&mut buffer) {
                // EOF, connection closed
                Ok(0) => break,
                Ok(read_bytes) => println!("Read {} bytes from the socket", read_bytes),
                // WouldBlock is returned by non-blocking streams when there is no data to read yet
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => {
                    println!("Unexpected stream error: {:?}", error);
                    self.set_disconnection_instant();
                    _ = self.status_update_sender.send(self.connection_status());
                    return Err(Box::new(error));
                }
            }
        }

        self.set_disconnection_instant();
        _ = self.status_update_sender.send(self.connection_status());
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
    }
}
