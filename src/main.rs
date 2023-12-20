use std::env;

mod avalanche;

#[tokio::main]
async fn main() {
    let ip_address = match get_command_line_arguments() {
        Ok(address) => address,
        Err(_) => return,
    };

    // Create a client instance to connect to the peer
    let mut client = match avalanche::AvalancheClient::new(&ip_address) {
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

/// Parses the command line arguments.
fn get_command_line_arguments() -> Result<String, ()> {
    let mut args: Vec<String> = env::args().collect();

    let destination_address = match args.len() {
        // If no argument is passed, use the default destination
        1 => String::from("127.0.0.1:9651"),
        2 => args.pop().unwrap(),
        _ => {
            println!(
                r#"Too many arguments, expected 1.
                   Usage: p2p-node-handshake [port]:[ip]
                   Example: p2p-node-handshake 127.0.0.1:9651"#
            );
            return Err(());
        }
    };

    Ok(destination_address)
}
