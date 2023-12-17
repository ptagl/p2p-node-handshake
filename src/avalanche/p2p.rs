use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    time::Duration,
};

use super::{network::NetworkHandler, ConnectionStatus, P2pError};

/// It handles the communication with Avalanche nodes.
pub struct AvalancheClient {
    /// Address of the remote peer.
    destination_address: String,

    /// Handler for the management of the network layer.
    /// It is an Option as it must be moved when running asynchronously.
    network_handler: Option<NetworkHandler>,

    status_update_receiver: Receiver<ConnectionStatus>,
}

impl AvalancheClient {
    /// Creates a new client instance to later connect to the destination address provided.
    pub fn new(destination_address: &str) -> Result<Self, P2pError> {
        // Let's use a channel to share information
        let (sender, receiver) = mpsc::channel::<ConnectionStatus>();

        // Create an object that will handle the network communication
        let network_handler = NetworkHandler::new(sender)?;

        Ok(Self {
            destination_address: destination_address.to_string(),
            network_handler: Some(network_handler),
            status_update_receiver: receiver,
        })
    }

    /// Tries to connect to the remote peer.
    pub fn connect(&mut self) -> Result<(), P2pError> {
        if let Some(handler) = self.network_handler.as_mut() {
            handler.connect(&self.destination_address)?;
        } else {
            panic!("Unexpected error: network_handler was None!");
        }

        Ok(())
    }

    /// Async task that handles the P2P connection and spawns
    /// another async task for handling the networking.
    pub async fn run(mut self) -> Result<Self, P2pError> {
        // Take ownership of the Option network_handler
        let handle = tokio::spawn(NetworkHandler::read_bytes(
            self.network_handler.take().unwrap(),
        ));

        // Monitor status updates from the network handler
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            match self.status_update_receiver.try_recv() {
                Ok(status) => {
                    println!("Connection status: {}", status);

                    // No further messages after the "Connection closed" event
                    if let ConnectionStatus::Closed(_) = status {
                        break;
                    }
                }
                // No message yet, retry
                Err(TryRecvError::Empty) => continue,
                // We won't receive any new status update
                Err(TryRecvError::Disconnected) => break,
            }
        }

        // If the execution reaches this point, the TLS connection was closed,
        // let's wait for the networking async task to stop running.
        match handle.await {
            // Return self just in case it is needed for later checks or operations
            Ok(Ok(_)) => Ok(self),
            Ok(Err(error)) => Err(error), // read error
            Err(error) => Err(P2pError::AsyncOperationError(error)), // Future error
        }
    }
}
