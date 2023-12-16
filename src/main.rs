use std::net::TcpStream;

fn main() {
    println!("Hello, world!");

    connect_to_node("127.0.0.1:9651")
}

fn connect_to_node(destination_address: &str) {
    match TcpStream::connect(destination_address) {
        Ok(_) => println!("Connected succesfully"),
        Err(error) => println!("Connection error: {:?}", error),
    }
}
