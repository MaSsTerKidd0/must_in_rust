use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{self, Read, Write};
use std::sync::mpsc::{Receiver, Sender};
use crate::must::log_assistant::{LogAssistant, OperationId};
use crate::must::protocols::protocol::Protocol;

pub struct TcpProtocol {
    pub(crate) listener: TcpListener,
    target_socket_addr: SocketAddr,
}

impl Protocol for TcpProtocol {
    fn new(addr: SocketAddr, target_addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr)
            .expect("Failed to bind TCP listener to address");
        TcpProtocol {
            listener,
            target_socket_addr: target_addr,
        }
    }

    fn receive(&self, sender: Sender<Vec<u8>>) {
        for stream in self.listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buffer = vec![0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(bytes_read) => {
                            buffer.truncate(bytes_read);
                            sender.send(buffer).expect("Failed to send data");
                        },
                        Err(_) => println!("Error occurred during read from TCP stream"),
                    }
                },
                Err(_) => println!("Error occurred in TCP listener incoming stream"),
            }
        }
    }

    fn send(&self, receiver: Receiver<Vec<u8>>) {
        match TcpStream::connect(self.target_socket_addr) {
            Ok(mut stream) => {
                while let Ok(message) = receiver.recv() {
                    if let Err(e) = stream.write_all(&message) {
                        eprintln!("Failed to send message: {}", e);
                        LogAssistant::send_error(OperationId::SendPacket);
                    }
                }
            },
            Err(e) => eprintln!("Failed to connect to target address: {}", e),
        }
    }
}
