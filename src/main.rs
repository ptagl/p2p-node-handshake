use avalanche::{DEFAULT_INACTIVITY_TIMEOUT, DEFAULT_IP_ADDRESS};
use clap::Parser;

mod avalanche;

/// Struct containing the command line arguments supported.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address of the destination peer as [ADDRESS]:[PORT]
    #[arg(short, long, default_value_t = String::from(DEFAULT_IP_ADDRESS))]
    ip_address: String,

    /// Inactivity timeout for P2P communications (seconds)
    #[arg(short, long, default_value_t = DEFAULT_INACTIVITY_TIMEOUT)]
    timeout: u64,
}

#[tokio::main]
async fn main() {
    // Parse the command line arguments
    let args = Args::parse();

    // Create a client instance to connect to the peer
    let mut client = match avalanche::AvalancheClient::new(&args.ip_address, args.timeout) {
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
