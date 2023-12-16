use std::{
    io::{ErrorKind, Read},
    net::TcpStream,
    thread::sleep,
    time::{Duration, Instant},
};

fn main() {
    println!("Hello, world!");

    connect_to_node("127.0.0.1:9651")
}

fn connect_to_node(destination_address: &str) {
    let mut stream = match TcpStream::connect(destination_address) {
        Ok(stream) => stream,
        Err(error) => {
            println!("Connection error: {:?}", error);
            return;
        }
    };

    let start = Instant::now();

    println!("Connected succesfully");

    // Set the stream as non-blocking when performing read/write operations
    if let Err(error) = stream.set_nonblocking(true) {
        println!(
            "Error while setting the socket as non-blocking: {:?}",
            error
        );
    }

    let mut buffer = [0u8; 1024];

    loop {
        sleep(Duration::from_millis(100));

        match stream.read(&mut buffer) {
            // EOF, connection closed
            Ok(0) => break,
            Ok(read_bytes) => println!("Read {} bytes from the socket", read_bytes),
            // WouldBlock is returned by non-blocking streams when there is no data to read yet
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => {
                println!("Unexpected stream error: {:?}", error);
                break;
            }
        }
    }

    println!(
        "Connection closed after {} seconds",
        start.elapsed().as_secs()
    );
}
