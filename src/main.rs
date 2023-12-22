use std::sync::Arc;

use utils::time::TimeContext;

mod avalanche;
mod utils;

#[tokio::main]
async fn main() {
    // Parse the configuration or get the default values.
    let config = avalanche::config::Configuration::new();

    // Create a client instance to connect to the peer
    let mut client = match avalanche::AvalancheClient::new(config, Arc::new(TimeContext::new(None)))
    {
        Ok(client) => client,
        Err(error) => {
            println!(
                "An error occurred while trying to initialize a new client connection: {}",
                error
            );
            return;
        }
    };

    // Try to connect to the Avalanche node
    match client.connect() {
        Ok(_) => {}
        Err(error) => {
            println!("An error occurred while connecting to the peer: {}", error);
            return;
        }
    };

    // Run the client async task and wait for its completion
    match tokio::spawn(client.run_all()).await {
        Ok(Ok(_)) => println!("Client run successfully!"),
        Ok(Err(error)) => println!(
            "An error occurred while running the P2P client: {:?}",
            error
        ),
        Err(error) => println!(
            "An error occurred while handling the async task: {:?}",
            error
        ),
    }
}
