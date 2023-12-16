mod avalanche;

use crate::avalanche::network::NetworkHandler;

fn main() {
    let mut handler = match NetworkHandler::connect("127.0.0.1:9651") {
        Ok(handler) => handler,
        Err(error) => {
            println!("An error occurred while connecting to peer: {:?}", error);
            return;
        }
    };

    if let Err(error) = handler.read_bytes() {
        println!("An error occurred while reading bytes: {:?}", error);
    }

    println!("Connection status: {}", handler.connection_status());
}
