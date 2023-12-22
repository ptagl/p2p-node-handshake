use std::{
    net::Ipv6Addr,
    str::FromStr,
    sync::{
        mpsc::{self, TryRecvError},
        Arc,
    },
    time::{Duration, SystemTime},
};

use protobuf::Message;
use rustls::PrivateKey;
use x509_certificate::Signer;
use zstd::bulk::decompress;

use crate::utils::time::TimeContext;

use super::{
    avalanche,
    config::{self, Configuration},
    network::NetworkHandler,
    ConnectionStatus, MessageType, P2pError, MAX_MESSAGE_LENGTH,
};

type ReceivedMessageQueue = mpsc::Receiver<avalanche::Message>;
type SendMessageQueue = mpsc::Sender<avalanche::Message>;
type StatusUpdateReceiver = mpsc::Receiver<ConnectionStatus>;
type StatusUpdateSender = mpsc::Sender<ConnectionStatus>;

/// It handles the communication with Avalanche nodes.
#[derive(Debug)]
pub struct AvalancheClient {
    /// Address of the remote peer.
    destination_address: String,

    /// Inactivity timeout for connected peers. Peers are required to send
    /// at least one message within the timeout period to not be disconnected.
    inactivity_timeout: Duration,

    /// Timestamp of the last message received. This is used to implement a
    /// protection mechanism and disconnect peers after an inactivity timeout.
    last_message_timestamp: SystemTime,

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
    /// It is optional so that we can discard it to notify the lower level (socket) to
    /// close the connection.
    send_message_queue: Option<SendMessageQueue>,

    /// The queue of status updates from the network layer (receiver).
    status_update_receiver: StatusUpdateReceiver,

    /// The queue of status updates from the network layer (sender).
    status_update_sender: StatusUpdateSender,

    /// A structure that provides utilities to get the current time.
    time_context: Arc<TimeContext>,

    /// Configuration to be used when generating P2P Version messages.
    version_message_configuration: config::VersionMessage,
}

impl AvalancheClient {
    /// Creates a new client instance to later connect to the destination address provided.
    pub fn new(
        configuration: Configuration,
        time_context: Arc<TimeContext>,
    ) -> Result<Self, P2pError> {
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
            time_context.clone(),
        );

        Ok(Self {
            destination_address: configuration.destination_address,
            inactivity_timeout: Duration::from_secs(configuration.inactivity_timeout),
            last_message_timestamp: time_context.now(),
            network_handler: Some(network_handler),
            next_expected_message: MessageType::Version,
            private_key,
            received_message_queue: received_message_receiver,
            send_message_queue: Some(send_messages_sender),
            status_update_receiver: status_receiver,
            status_update_sender: status_sender,
            time_context: time_context.clone(),
            version_message_configuration: configuration.version_message,
        })
    }

    /// Tries to connect to the remote peer.
    pub fn connect(&mut self) -> Result<(), P2pError> {
        if let Some(handler) = self.network_handler.as_mut() {
            handler.connect(&self.destination_address)?;
        } else {
            panic!("Unexpected error: network_handler was None!");
        }

        self.last_message_timestamp = self.time_context.now();

        Ok(())
    }

    /// Internal async function that runs just the logic of the client
    /// without the network_handler. This is useful for testing purpose.
    async fn run_client(&mut self) -> Result<(), P2pError> {
        // Monitor status updates from the network handler
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Check if the connection is stalling (remote peer
            // not sending any message for too long).
            self.check_inactivity()?;

            // Check if there is any incoming message to be processed
            match self.received_message_queue.try_recv() {
                // Process the incoming message
                Ok(message) => self.process_message(message)?,
                // No message yet, nothing to do
                Err(TryRecvError::Empty) => {}
                // We won't receive any new message
                Err(TryRecvError::Disconnected) => break,
            };

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

        Ok(())
    }

    /// Async task that handles the P2P connection and spawns
    /// another async task for handling the networking.
    pub async fn run_all(mut self) -> Result<Self, P2pError> {
        // Take ownership of the Option network_handler
        let handle = tokio::spawn(self.network_handler.take().unwrap().read_and_write());

        match self.run_client().await {
            Ok(_) => {}
            Err(P2pError::WrongMessageOrder(expected_type, current_type)) => {
                println!(
                    "Received a message in the wrong order, expected [{:?}], found [{:?}]",
                    expected_type, current_type
                );
            }
            Err(error) => println!("Process message error: {}", error),
        }

        // Close the channels with the NetworkHandler to make it shutdown the connection and stop.
        // This is useful when the run_client() function returns an error that does not depend
        // on the network layer (for instance in case of inactivity timeout), otherwise the
        // NetworkHandler would not stop on its own.
        drop(self.send_message_queue.take());

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
        // Check message ordering to detect potential misbehaving nodes.
        // Sending messages in the wrong order is considered malicious,
        // and the remote peer gets disconnected.
        // This mechanism could be improved with the implementation of a ban score system
        // (e.g. ban after N wrong messages).
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
                    .send(ConnectionStatus::HandshakeStarted(
                        self.time_context.now().into(),
                    ));

                println!("Sending version message");
                _ = self
                    .send_message_queue
                    .as_ref()
                    .unwrap()
                    .send(AvalancheClient::wrap_message(self.version_message()));

                // Let's send an empty peer_list message as we don't know any other peer.
                // No ack is expected for such an empty message.
                println!("Sending peer_list message");
                _ = self
                    .send_message_queue
                    .as_ref()
                    .unwrap()
                    .send(AvalancheClient::wrap_message(
                        avalanche::message::Message::PeerList(avalanche::PeerList::new()),
                    ));

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

                    println!("Sending Peer List Ack message");
                    _ = self.send_message_queue.as_ref().unwrap().send(
                        AvalancheClient::wrap_message(avalanche::message::Message::PeerListAck(
                            ack_message,
                        )),
                    );
                }

                // The handshake is completed after receiving AND sending the PeerList message.
                // The message from our side has been already sent together with the Version one,
                // otherwise we wouldn't accept the incoming PeerList (see self.check_message_order()).
                _ = self
                    .status_update_sender
                    .send(ConnectionStatus::HandshakeCompleted(
                        self.time_context.now().into(),
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

                println!("Sending pong message");
                _ = self
                    .send_message_queue
                    .as_ref()
                    .unwrap()
                    .send(AvalancheClient::wrap_message(
                        avalanche::message::Message::Pong(avalanche::Pong::new()),
                    ));
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

        // Update the last message timestamp with the current value
        self.last_message_timestamp = self.time_context.now();

        Ok(())
    }

    /// Checks whether the remote peer was inactive for more than [`super::INACTIVITY_TIMEOUT`].
    /// In case of inactivity, an error is returned so that the connection can be closed.
    fn check_inactivity(&self) -> Result<(), P2pError> {
        match self.time_context.elapsed(&self.last_message_timestamp) {
            Ok(time) if time < self.inactivity_timeout => Ok(()),
            Ok(_) => Err(P2pError::InactivePeer(self.inactivity_timeout)),
            Err(error) => panic!(
                "Fatal error, the last received message comes from the future! {}",
                error
            ),
        }
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
    fn version_message(&self) -> avalanche::message::Message {
        let mut version_message = avalanche::Version::new();
        version_message.network_id = self.version_message_configuration.network_id;
        version_message.my_version = self.version_message_configuration.version_string.clone();
        version_message.my_time = self
            .time_context
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        version_message.my_version_time = version_message.my_time;
        version_message.ip_addr =
            std::net::Ipv4Addr::from_str(&self.version_message_configuration.ip_address)
                .unwrap()
                .to_ipv6_mapped()
                .octets()
                .to_vec();
        version_message.ip_port = self.version_message_configuration.ip_port;

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

        avalanche::message::Message::Version(version_message)
    }

    /// Helper function that takes a specific P2P message and wraps it into
    /// the higher-level message data structure that can be used to be sent
    /// through the network.
    fn wrap_message(message: avalanche::message::Message) -> avalanche::Message {
        let mut wrapped_message = avalanche::Message::new();

        match message {
            avalanche::message::Message::PeerList(message) => {
                wrapped_message.set_peer_list(message)
            }
            avalanche::message::Message::PeerListAck(message) => {
                wrapped_message.set_peer_list_ack(message)
            }
            avalanche::message::Message::Ping(message) => wrapped_message.set_ping(message),
            avalanche::message::Message::Pong(message) => wrapped_message.set_pong(message),
            avalanche::message::Message::Version(message) => wrapped_message.set_version(message),
            message => panic!("Wrapping not supported yet for this message: {:?}", message),
        }

        wrapped_message
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ops::Add,
        sync::{
            mpsc::{self, Receiver, TryRecvError},
            Arc,
        },
        time::{Duration, SystemTime},
    };

    use crate::{
        avalanche::{
            avalanche::{self, Message},
            config::Configuration,
            ConnectionStatus, MessageType, P2pError, DEFAULT_INACTIVITY_TIMEOUT,
        },
        utils::time::TimeContext,
    };

    use super::AvalancheClient;

    type ReceivedMessageQueue = mpsc::Sender<Message>;
    type SendMessageQueue = mpsc::Receiver<Message>;
    type StatusUpdateSender = mpsc::Sender<ConnectionStatus>;

    /// A wrapper that stores all the MPSC queues that can be useful for unit testing
    /// the [`AvalancheClient`] implementation.
    struct ClientTestChannels {
        received_message_queue: ReceivedMessageQueue,
        send_message_queue: SendMessageQueue,
        status_update_sender: StatusUpdateSender,
    }

    /// Creates a default client for tests.
    fn default_client(time: Option<SystemTime>) -> (AvalancheClient, ClientTestChannels) {
        let mut client =
            AvalancheClient::new(Configuration::default(), Arc::new(TimeContext::new(time)))
                .unwrap();

        // Creates channels to be used by tests. We use the same side used
        // by the network handler to trigger client actions (e.g. simulate
        // a new message arrived from the socket).
        let (received_message_sender, received_message_receiver) = mpsc::channel::<Message>();
        client.received_message_queue = received_message_receiver;

        let (send_message_sender, send_message_receiver) = mpsc::channel::<Message>();
        client.send_message_queue = Some(send_message_sender);

        let (status_update_sender, status_update_receiver) = mpsc::channel::<ConnectionStatus>();
        client.status_update_receiver = status_update_receiver;
        client.status_update_sender = status_update_sender.clone();

        let channels = ClientTestChannels {
            received_message_queue: received_message_sender,
            send_message_queue: send_message_receiver,
            status_update_sender,
        };

        (client, channels)
    }

    /// The first expected message must always be Version.
    #[test]
    fn default_expected_message() {
        let (client, _) = default_client(None);
        assert_eq!(client.next_expected_message, MessageType::Version);
    }

    /// Helper function to run some similar unit tests.
    async fn check_rejected_messages(
        invalid_messages: &[avalanche::Message],
        expected_message_type: MessageType,
    ) {
        // Send all the invalid messages and check the client returns an error
        for wrapper in invalid_messages {
            let (mut client, channels) = default_client(None);
            client.next_expected_message = expected_message_type;
            channels
                .received_message_queue
                .send(wrapper.clone())
                .unwrap();

            let error = client.run_client().await.unwrap_err();

            match wrapper.clone().message.unwrap() {
                avalanche::message::Message::Version(_) => assert_eq!(
                    error,
                    P2pError::WrongMessageOrder(expected_message_type, MessageType::Version)
                ),
                avalanche::message::Message::PeerList(_) => assert_eq!(
                    error,
                    P2pError::WrongMessageOrder(expected_message_type, MessageType::PeerList)
                ),
                _ => assert_eq!(
                    error,
                    P2pError::WrongMessageOrder(expected_message_type, MessageType::Any)
                ),
            }
        }
    }

    /// Helper function to wait for a message to be received through a
    /// MPSC receiver. It is done in a non-blocking way.
    async fn wait_for_message<T>(receiver: &Receiver<T>) -> Result<T, ()> {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            match receiver.try_recv() {
                Ok(message) => return Ok(message),
                Err(TryRecvError::Empty) => continue,
                Err(TryRecvError::Disconnected) => return Err(()),
            }
        }
    }

    /// Check that all the messages (but Version) are discarded when waiting for the handshake to start.
    #[tokio::test]
    async fn messages_rejected_waiting_for_version() {
        // Create some messages that are not expected to be processed before the Version one
        let invalid_messages = [
            AvalancheClient::wrap_message(avalanche::message::Message::PeerList(
                avalanche::PeerList::new(),
            )),
            AvalancheClient::wrap_message(avalanche::message::Message::PeerListAck(
                avalanche::PeerListAck::new(),
            )),
            AvalancheClient::wrap_message(
                avalanche::message::Message::Ping(avalanche::Ping::new()),
            ),
            AvalancheClient::wrap_message(
                avalanche::message::Message::Pong(avalanche::Pong::new()),
            ),
        ];

        check_rejected_messages(&invalid_messages, MessageType::Version).await;
    }

    /// Check that all the messages (but PeerList) are discarded when waiting for the handshake to complete.
    #[tokio::test]
    async fn messages_rejected_waiting_for_peer_list() {
        // Create some messages that are not expected to be processed before the Version one
        let invalid_messages = [
            AvalancheClient::wrap_message(avalanche::message::Message::PeerListAck(
                avalanche::PeerListAck::new(),
            )),
            AvalancheClient::wrap_message(
                avalanche::message::Message::Ping(avalanche::Ping::new()),
            ),
            AvalancheClient::wrap_message(
                avalanche::message::Message::Pong(avalanche::Pong::new()),
            ),
            AvalancheClient::wrap_message(avalanche::message::Message::Version(
                avalanche::Version::new(),
            )),
        ];

        check_rejected_messages(&invalid_messages, MessageType::PeerList).await;
    }

    /// Check expected handshake sequence (1. Version, 2. PeerList).
    #[tokio::test]
    async fn right_handshake_sequence() {
        let (client, channels) = default_client(None);

        assert_eq!(client.next_expected_message, MessageType::Version);

        [
            AvalancheClient::wrap_message(client.version_message()),
            AvalancheClient::wrap_message(avalanche::message::Message::PeerList(
                avalanche::PeerList::new(),
            )),
        ]
        .into_iter()
        .for_each(|message| channels.received_message_queue.send(message).unwrap());

        let handle = tokio::spawn(client.run_all());

        // Check that we queued Version and PeerList messages to be sent to the peer
        assert!(matches!(
            wait_for_message(&channels.send_message_queue)
                .await
                .unwrap()
                .message
                .unwrap(),
            avalanche::message::Message::Version(_)
        ));
        assert!(matches!(
            wait_for_message(&channels.send_message_queue)
                .await
                .unwrap()
                .message
                .unwrap(),
            avalanche::message::Message::PeerList(_)
        ));

        // Force the client to stop the async processing by simulating
        // a connection closed.
        channels
            .status_update_sender
            // We should not use the system time here but rather the TimeContext struct
            .send(ConnectionStatus::Closed(SystemTime::now().into()))
            .unwrap();

        // Wait for the async task to complete and return the client
        let client = handle.await.unwrap().unwrap();

        // // Check that we are ready to receive any message
        assert_eq!(client.next_expected_message, MessageType::Any);
    }

    /// Check that after the inactivity timeout expires
    /// the connection with the remote peer is closed.
    #[test]
    fn check_inactivity_timeout() {
        let (mut client, _) = default_client(Some(SystemTime::UNIX_EPOCH));

        // Let's notify the client that the handshake is completed
        client.next_expected_message = MessageType::Any;

        // If the default timeout is 60 seconds, let's use 29 as duration
        let duration = Duration::from_secs(DEFAULT_INACTIVITY_TIMEOUT / 2 - 1);

        // Based on the duration chosen, we expect the following:
        // Iteration 1: the peer was inactive for 0 seconds  => OK
        // Iteration 2: the peer was inactive for 29 seconds => OK
        // Iteration 3: the peer was inactive for 58 seconds => OK
        for _ in 0..3 {
            // Check the peer is not considered inactive
            assert!(client.check_inactivity().is_ok());

            // Move the time ahead
            client
                .time_context
                .set_time(client.time_context.now().add(duration));
        }

        // Now the peer should be inactive for 87 seconds
        assert_eq!(
            client.check_inactivity().unwrap_err(),
            P2pError::InactivePeer(client.inactivity_timeout)
        );

        // Go back in time so that the inactivity is almost 60 seconds (minus just 1 nanosecond)
        client.time_context.set_time(
            client
                .last_message_timestamp
                .add(client.inactivity_timeout - Duration::from_nanos(1)),
        );

        // The peer must be considered active
        assert!(client.check_inactivity().is_ok());

        // Move 1 nanosecond ahead to trigger the inactivity timeout
        _ = client
            .time_context
            .set_time(client.time_context.now().add(Duration::from_nanos(1)));

        // The peer must be considered inactive now
        assert_eq!(
            client.check_inactivity().unwrap_err(),
            P2pError::InactivePeer(client.inactivity_timeout)
        );
    }

    /// Check that the inactivity timeout validation fails
    /// if the last timestamp is wrong (comes from the future).
    #[test]
    #[should_panic]
    fn check_inactivity_timeout_future_error() {
        let (mut client, _) = default_client(None);

        // Move the last message timestamp to the future (1 minute)
        client.last_message_timestamp = client.time_context.now().add(Duration::from_secs(60));

        // The check should detect the inconsistency and panic as this is symptom of a major flaw
        _ = client.check_inactivity();
    }

    /// Check that the TimeContext used by the [`AvalancheClient`] and the [`crate::avalanche::network::NetworkHandler`]
    /// are always aligned (through the Arc pointer).
    #[test]
    fn check_clocks_synchronization() {
        // Init the TimeContext with None, meaning that we want to use the real clock
        let (client, _) = default_client(None);
        let network_handler = client.network_handler.unwrap();

        // Check that client and network handler times are different but just for less than 1 millisecond
        let time_1 = client.time_context.now();
        let time_2 = network_handler.time_context.now();
        assert!(time_2.duration_since(time_1).unwrap() < Duration::from_millis(1));

        // Switch to mock time
        client.time_context.set_time(SystemTime::UNIX_EPOCH);
        assert_eq!(
            client.time_context.now(),
            network_handler.time_context.now()
        );

        // Move client time 10 seconds ahead
        client
            .time_context
            .set_time(SystemTime::UNIX_EPOCH.add(Duration::from_secs(10)));

        // Check that both client and network handler times match...
        assert_eq!(
            client.time_context.now(),
            network_handler.time_context.now()
        );

        // ... and that the value is as expected
        assert_eq!(
            client.time_context.now(),
            SystemTime::UNIX_EPOCH.add(Duration::from_secs(10))
        );

        // Move network handler time 10 seconds ahead
        network_handler.time_context.set_time(
            network_handler
                .time_context
                .now()
                .add(Duration::from_secs(10)),
        );

        // Check that both client and network handler times match...
        assert_eq!(
            client.time_context.now(),
            network_handler.time_context.now()
        );

        // ... and that the value is as expected
        assert_eq!(
            client.time_context.now(),
            SystemTime::UNIX_EPOCH.add(Duration::from_secs(20))
        );
    }
}
