mod avalanche;

use crate::avalanche::network::NetworkHandler;

#[tokio::main]
async fn main() {
    let handler = match NetworkHandler::connect("127.0.0.1:9651") {
        Ok(handler) => handler,
        Err(error) => {
            println!("An error occurred while connecting to peer: {:?}", error);
            return;
        }
    };

    match tokio::spawn(handler.read_bytes()).await {
        Ok(Ok(handler)) => println!("Status: {}", handler.connection_status()),
        Ok(Err(error)) => println!("An error occurred while reading bytes: {:?}", error),
        Err(error) => println!(
            "An error occurred while handling the async task: {:?}",
            error
        ),
    }
}
