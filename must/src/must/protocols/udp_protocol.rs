use std::net::{IpAddr, SocketAddr, UdpSocket};
use crate::must::protocols::protocol::Protocol;
use std::sync::mpsc::{Receiver, Sender};
use std::{io, thread};
use std::time::Duration;
use crate::must::network_icd::network_icd::NetworkICD;


pub struct UdpProtocol {
    pub(crate) socket: UdpSocket,
}

impl Protocol for UdpProtocol {
    fn new(local_addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind(local_addr)
            .expect("Failed to bind to local address");
        UdpProtocol {
            socket,
        }
    }

    fn receive(&self, sender: Sender<Vec<u8>>){
        let mut buffer = [0; 1024];

        match self.socket.recv_from(&mut buffer) {
            Ok((number_of_bytes, _src_addr)) => {
                let data = buffer[..number_of_bytes].to_vec();
                if let Err(e) = sender.send(data) {
                    eprintln!("Failed to send data: {}", e);
                }
            },
            Err(e) => eprintln!("Failed to receive data: {}", e),
        }
    }

    fn send(&self, receiver: Receiver<Vec<u8>>,network_type:bool, target_ip: IpAddr, target_port: u16) {
        let target_socket_addr = SocketAddr::new(target_ip, target_port);
        loop {
            match receiver.recv() {
                Ok(data) => {
                    if let Err(e) = self.socket.send_to(&data, target_socket_addr) {
                        eprintln!("Failed to send data: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Failed to receive data from channel: {}", e);
                    break;
                }
            }
        }
    }
}
