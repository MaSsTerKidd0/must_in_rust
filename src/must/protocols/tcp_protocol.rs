use std::net::{TcpListener, TcpStream, SocketAddr, IpAddr};
use std::io::{self, Read, Write};
use std::sync::mpsc::{Receiver, Sender};
use crate::must::log_assistant::{LogAssistant, OperationId};
use crate::must::protocols::protocol::Protocol;


pub struct TcpProtocol {
    pub(crate) listener: TcpListener,
}

impl Protocol for TcpProtocol {
    fn new(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr)
            .expect("Failed to bind TCP listener to address");
        TcpProtocol {
            listener,
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

    fn send(&self, receiver: Receiver<Vec<u8>>,network_type:bool, target_ip: IpAddr, target_port: u16) {
        let target_socket_addr = SocketAddr::new(target_ip, target_port);
        match TcpStream::connect(target_socket_addr) {
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
