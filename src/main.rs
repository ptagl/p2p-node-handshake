mod avalanche;

use std::sync::mpsc;

use avalanche::ConnectionStatus;

use crate::avalanche::network::NetworkHandler;

#[tokio::main]
async fn main() {
    // Let's use a channel to share information
    let (sender, receiver) = mpsc::channel::<ConnectionStatus>();

    // Create an object that will handle the network communication
    let mut network_handler = match NetworkHandler::new(sender) {
        Ok(handler) => handler,
        Err(error) => {
            println!(
                "An error occurred while creating the network handler: {:?}",
                error
            );
            return;
        }
    };

    // Try to connect to the Avalanche node
    match network_handler.connect("127.0.0.1:9651") {
        Ok(_) => {}
        Err(error) => {
            println!("An error occurred while connecting to peer: {}", error);
            return;
        }
    };

    // Run the async task for handling the network
    let network_handler_future = tokio::spawn(NetworkHandler::read_bytes(network_handler));

    // Monitor status updates from the network handler
    while let Ok(status) = receiver.recv() {
        println!("Connection status: {}", status);

        // If the connection is closed, we won't receive any further update
        if let ConnectionStatus::Closed(_) = status {
            break;
        }
    }

    // After receiving the "Closed" event, the network handler should be stopped,
    // but let's double check.
    match network_handler_future.await {
        Ok(Ok(handler)) => println!("Status: {}", handler.connection_status()),
        Ok(Err(error)) => println!("An error occurred while reading bytes: {:?}", error),
        Err(error) => println!(
            "An error occurred while handling the async task: {:?}",
            error
        ),
    }
}
