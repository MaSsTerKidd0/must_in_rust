use std::net::{TcpListener, TcpStream, SocketAddr, IpAddr};
use std::io::{self, Read, Write, Result};
use std::sync::mpsc::{Receiver, Sender};
use crate::must::protocols::protocol::Protocol;

pub struct TcpProtocol {
    pub(crate) listener: TcpListener,
}

impl Protocol for TcpProtocol {
    fn new(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr)
            .expect("Failed to bind TCP listener to address");
        TcpProtocol { listener }
    }

    fn receive(&self, sender: Sender<Vec<u8>>) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buffer = vec![0; 1024];
                    let bytes_read = stream.read(&mut buffer);
                    buffer.truncate(bytes_read.unwrap());
                    sender.send(buffer).expect("Failed to send data");
                },
                Err(e) => println!("Error Occurred TCP"),
            }
        }
    }

    fn send(&self, target_addr: IpAddr, target_port: u16, receiver: Receiver<Vec<u8>>) {
        let target_socket_addr = SocketAddr::new(target_addr, target_port);
        match TcpStream::connect(target_socket_addr) {
            Ok(mut stream) => {
                while let Ok(message) = receiver.recv() {
                    match stream.write_all(&message) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!("Failed to send message: {}", e);
                            break; // Optional: decide if you want to stop on error or just log it
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Failed to connect to target address: {}", e);
            }
        }
    }
}
