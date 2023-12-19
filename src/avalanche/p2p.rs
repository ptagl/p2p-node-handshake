use std::{
    net::Ipv6Addr,
    str::FromStr,
    sync::mpsc::{self, TryRecvError},
    time::{Duration, SystemTime},
};

use protobuf::Message;
use rustls::PrivateKey;
use x509_certificate::Signer;
use zstd::bulk::decompress;

use super::{
    network::{avalanche, NetworkHandler},
    ConnectionStatus, MessageType, P2pError, MAX_MESSAGE_LENGTH,
};

type ReceivedMessageQueue = mpsc::Receiver<avalanche::Message>;
type SendMessageQueue = mpsc::Sender<avalanche::Message>;
type StatusUpdateReceiver = mpsc::Receiver<ConnectionStatus>;
type StatusUpdateSender = mpsc::Sender<ConnectionStatus>;

/// It handles the communication with Avalanche nodes.
pub struct AvalancheClient {
    /// Address of the remote peer.
    destination_address: String,

    /// Handler for the management of the network layer.
    /// It is an Option as it must be moved when running asynchronously.
    network_handler: Option<NetworkHandler>,

    /// Message type that is expected to be received next. This field is
    /// used to detect misbehaving nodes (e.g. sending messages in the wrong order).
    next_expected_message: MessageType,

    /// The private key is used to establish the TLS connection, but also for
    /// signing some fields of P2P messages.
    private_key: PrivateKey,

    /// The queue of messages received from the network layer and waiting to be processed.
    received_message_queue: ReceivedMessageQueue,

    /// The queue of messages that are ready to be serialized and sent through the network.
    send_message_queue: SendMessageQueue,

    /// The queue of status updates from the network layer (receiver).
    status_update_receiver: StatusUpdateReceiver,

    /// The queue of status updates from the network layer (sender).
    status_update_sender: StatusUpdateSender,
}

impl AvalancheClient {
    /// Creates a new client instance to later connect to the destination address provided.
    pub fn new(destination_address: &str) -> Result<Self, P2pError> {
        // Generate a private key and a certificate for establishing the TLS connection
        let (private_key, certificate) = cert_manager::x509::generate_der(None)
            .map_err(|error| P2pError::CertificateGenerationError(error.to_string()))?;

        // Received messages channel
        let (received_messages_sender, received_message_receiver) =
            mpsc::channel::<avalanche::Message>();

        // Send messages channel
        let (send_messages_sender, send_messages_receiver) = mpsc::channel::<avalanche::Message>();

        // Status update channel
        let (status_sender, status_receiver) = mpsc::channel::<ConnectionStatus>();

        // Create an object that will handle the network communication
        let network_handler = NetworkHandler::new(
            private_key.clone(),
            certificate,
            received_messages_sender,
            send_messages_receiver,
            status_sender.clone(),
        )?;

        Ok(Self {
            destination_address: destination_address.to_string(),
            network_handler: Some(network_handler),
            next_expected_message: MessageType::Version,
            private_key,
            received_message_queue: received_message_receiver,
            send_message_queue: send_messages_sender,
            status_update_receiver: status_receiver,
            status_update_sender: status_sender,
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
        let handle = tokio::spawn(self.network_handler.take().unwrap().read_and_write());

        // Monitor status updates from the network handler
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Check if there is any incoming message to be processed
            let process_result = match self.received_message_queue.try_recv() {
                // Process the incoming message
                Ok(message) => self.process_message(message),
                // No message yet, nothing to do
                Err(TryRecvError::Empty) => Ok(()),
                // We won't receive any new message
                Err(TryRecvError::Disconnected) => break,
            };

            match process_result {
                Ok(_) => {}
                Err(P2pError::WrongMessageOrder(expected_type, current_type)) => {
                    println!(
                        "Received a message in the wrong order, expected [{:?}], found [{:?}]",
                        expected_type, current_type
                    );

                    // This behavior is considered malicious, let's disconnect the peer.
                    // This mechanism could be improved with the implementation of a ban score system
                    // (e.g. ban after N wrong messages).
                }
                Err(error) => println!("Process message error: {}", error),
            }

            // Check if there is any status update
            match self.status_update_receiver.try_recv() {
                Ok(status) => {
                    println!("[Status Update]{}", status);

                    // No further messages after the "Connection closed" event
                    if let ConnectionStatus::Closed(_) = status {
                        break;
                    }
                }
                // No update yet, nothing to do
                Err(TryRecvError::Empty) => {}
                // We won't receive any new status update
                Err(TryRecvError::Disconnected) => break,
            };
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
    fn process_message(&mut self, message_wrapper: avalanche::Message) -> Result<(), P2pError> {
        // Check message ordering to detect potential misbheaving nodes
        self.check_message_order(&message_wrapper.message)?;

        match message_wrapper.message {
            // Version is the first message sent by P2P nodes when performing the handshaking
            Some(avalanche::message::Message::Version(version_message)) => {
                println!(
                    "Connection established with Avalanche node {}:{}",
                    Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(version_message.ip_addr).unwrap()),
                    version_message.ip_port
                );
                println!("Received version message");

                _ = self
                    .status_update_sender
                    .send(ConnectionStatus::HandshakeStarted(SystemTime::now().into()));

                let mut message_wrapper = avalanche::Message::new();
                message_wrapper.set_version(self.version_message());

                println!("Sending version message");
                _ = self.send_message_queue.send(message_wrapper);

                // Let's send an empty peer_list message as we don't know any other peer.
                // No ack is expected for such an empty message.
                println!("Sending peer_list message");
                let mut message_wrapper = avalanche::Message::new();
                message_wrapper.set_peer_list(avalanche::PeerList::new());
                _ = self.send_message_queue.send(message_wrapper);

                // Next message must be a PeerList to complete the handshaking
                self.next_expected_message = MessageType::PeerList;
            }
            // Message containing the peers known by the remote node
            Some(avalanche::message::Message::PeerList(peer_list)) => {
                println!(
                    "Received peer list from the node: {} entries",
                    peer_list.claimed_ip_ports.len()
                );

                // No ack is required in case the peer list is empty
                if !peer_list.claimed_ip_ports.is_empty() {
                    let mut ack_message = avalanche::PeerListAck::new();

                    peer_list.claimed_ip_ports.iter().for_each(|peer| {
                        let mut peer_ack = avalanche::PeerAck::new();
                        peer_ack.timestamp = peer.timestamp;
                        peer_ack.tx_id = peer.tx_id.clone();

                        ack_message.peer_acks.push(peer_ack);
                    });

                    let mut message_wrapper = avalanche::Message::new();
                    message_wrapper.set_peer_list_ack(ack_message);

                    println!("Sending Peer List Ack message");
                    _ = self.send_message_queue.send(message_wrapper);
                }

                // The handshake is completed afer receiving AND sending the PeerList message.
                // The message from our side has been already sent together with the Version one,
                // otherwise we wouldn't accept the incoming PeerList (see self.check_message_order()).
                _ = self
                    .status_update_sender
                    .send(ConnectionStatus::HandshakeCompleted(
                        SystemTime::now().into(),
                    ));

                // Next message could be anything
                self.next_expected_message = MessageType::Any;
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
                _ = self.send_message_queue.send(message_wrapper);
            }
            // Pong messages are sent as a reply to Ping ones
            Some(avalanche::message::Message::Pong(_)) => {
                println!("Received pong message");
            }
            Some(avalanche::message::Message::CompressedZstd(compressed_bytes)) => {
                // Decompress the incoming message
                let decompressed_bytes = decompress(&compressed_bytes, MAX_MESSAGE_LENGTH)
                    .map_err(|error| {
                        P2pError::DecompressionError(compressed_bytes, error.to_string())
                    })?;

                // Deserialize the message
                let decompressed_message =
                    avalanche::Message::parse_from_bytes(&decompressed_bytes).map_err(|error| {
                        P2pError::MessageDeserializationError(decompressed_bytes, error.to_string())
                    })?;

                // Process the message
                return self.process_message(decompressed_message);
            }
            // Messages that are not handled yet are printed here
            unknown_message => return Err(P2pError::UnknownMessage(Box::new(unknown_message))),
        }

        Ok(())
    }

    /// Checks whether a message arrives in the right order or not.
    /// For instance, a PeerList message must always arrive after a Version one.
    fn check_message_order(
        &self,
        message: &Option<avalanche::message::Message>,
    ) -> Result<(), P2pError> {
        let expected_message = self.next_expected_message;

        match message {
            // Version is always the first message to be sent to start the handshake
            Some(avalanche::message::Message::Version(_)) => {
                if expected_message != MessageType::Version {
                    return Err(P2pError::WrongMessageOrder(
                        expected_message,
                        MessageType::Version,
                    ));
                }
            }
            // The PeerList message is typically sent as second message of the communication,
            // immediately after Version, but it could arrive also later in case of updates
            Some(avalanche::message::Message::PeerList(_)) => {
                if expected_message != MessageType::PeerList && expected_message != MessageType::Any
                {
                    return Err(P2pError::WrongMessageOrder(
                        expected_message,
                        MessageType::PeerList,
                    ));
                }
            }
            // Ignore compressed messages as we don't know the type until we decompress
            Some(avalanche::message::Message::CompressedGzip(_)) => {}
            Some(avalanche::message::Message::CompressedZstd(_)) => {}
            // Any other message can be sent only after the handshake is completed
            _ => {
                if expected_message != MessageType::Any {
                    return Err(P2pError::WrongMessageOrder(
                        expected_message,
                        MessageType::Any,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Generates a version message to be sent for handshaking.
    fn version_message(&self) -> avalanche::Version {
        let mut version_message = avalanche::Version::new();
        version_message.network_id = 12345;
        version_message.my_version = "avalanche/1.10.17".to_string();
        version_message.my_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        version_message.my_version_time = version_message.my_time;
        version_message.ip_addr = std::net::Ipv4Addr::from_str("127.0.0.1")
            .unwrap()
            .to_ipv6_mapped()
            .octets()
            .to_vec();
        version_message.ip_port = 9651_u32;

        let to_sign = [
            version_message.ip_addr.clone(),
            (version_message.ip_port as u16).to_be_bytes().to_vec(),
            version_message.my_version_time.to_be_bytes().to_vec(),
        ]
        .concat();

        let sig =
            x509_certificate::InMemorySigningKeyPair::from_pkcs8_der(self.private_key.0.as_slice())
                .unwrap()
                .try_sign(to_sign.as_slice());
        version_message.sig = sig.unwrap().as_ref().to_vec();

        version_message
    }
}

#[cfg(test)]
mod tests {}
