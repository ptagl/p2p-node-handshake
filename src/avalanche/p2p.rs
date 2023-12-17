use std::{
    net::Ipv6Addr,
    sync::mpsc::{self, TryRecvError},
    time::Duration,
};

use super::{
    network::{avalanche, NetworkHandler},
    ConnectionStatus, P2pError,
};

type ReceivedMessageQueue = mpsc::Receiver<avalanche::Message>;
type StatusUpdateQueue = mpsc::Receiver<ConnectionStatus>;

/// It handles the communication with Avalanche nodes.
pub struct AvalancheClient {
    /// Address of the remote peer.
    destination_address: String,

    /// Handler for the management of the network layer.
    /// It is an Option as it must be moved when running asynchronously.
    network_handler: Option<NetworkHandler>,

    /// The queue of messages received from the network layer and waiting to be processed.
    received_message_queue: ReceivedMessageQueue,

    /// The queue of status updates from the network layer.
    status_update_queue: StatusUpdateQueue,
}

impl AvalancheClient {
    /// Creates a new client instance to later connect to the destination address provided.
    pub fn new(destination_address: &str) -> Result<Self, P2pError> {
        // Received messages channel
        let (received_messages_sender, received_message_receiver) =
            mpsc::channel::<avalanche::Message>();

        // Status update channel
        let (status_sender, status_receiver) = mpsc::channel::<ConnectionStatus>();

        // Create an object that will handle the network communication
        let network_handler = NetworkHandler::new(received_messages_sender, status_sender)?;

        Ok(Self {
            destination_address: destination_address.to_string(),
            network_handler: Some(network_handler),
            received_message_queue: received_message_receiver,
            status_update_queue: status_receiver,
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

            // Check if there is any incoming message to be processed
            match self.received_message_queue.try_recv() {
                // Process the incoming message
                Ok(message) => self.process_message(message),
                // No message yet, nothing to do
                Err(TryRecvError::Empty) => {}
                // We won't receive any new message
                Err(TryRecvError::Disconnected) => break,
            }

            // Check if there is any status update
            match self.status_update_queue.try_recv() {
                Ok(status) => {
                    println!("Connection status: {}", status);

                    // No further messages after the "Connection closed" event
                    if let ConnectionStatus::Closed(_) = status {
                        break;
                    }
                }
                // No update yet, nothing to do
                Err(TryRecvError::Empty) => {}
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

    /// Handles an incoming P2P message read from the network
    fn process_message(&self, message_wrapper: avalanche::Message) {
        match message_wrapper.message {
            // Version is the first message sent by P2P nodes when performing the handshaking
            Some(avalanche::message::Message::Version(version_message)) => {
                println!(
                    "Connection established with Avalanche node {}:{}",
                    Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(version_message.ip_addr).unwrap()),
                    version_message.ip_port
                );
                println!("Received version message");

                // TODO: send a reply message
            }
            // The Ping message is periodically sent to show that the node is alive and connected
            Some(avalanche::message::Message::Ping(ping_message)) => {
                println!(
                    "Received ping message, node uptime: {}",
                    ping_message.uptime
                );

                let mut message_wrapper = avalanche::Message::new();
                message_wrapper.set_pong(avalanche::Pong::new());

                println!("Sending pong message");
                // TODO: send message
            }
            // Pong messages are sent as a reply to Ping ones
            Some(avalanche::message::Message::Pong(_)) => {
                println!("Received pong message");
            }
            // Messages that are not handled yet are printed here
            x => {
                println!("Received unknown message: {:?}", x);
            }
        }
    }
}
