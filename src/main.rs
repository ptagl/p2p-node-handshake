mod avalanche;

#[tokio::main]
async fn main() {
    // Create a client instance to connect to the peer
    let mut client = match avalanche::AvalancheClient::new("127.0.0.1:9651") {
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
            println!("An error occurred while connecting to peer: {}", error);
            return;
        }
    };

    // Run the client async task and wait for its completion
    match tokio::spawn(client.run()).await {
        Ok(Ok(_)) => println!("Client run succesfully!"),
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
