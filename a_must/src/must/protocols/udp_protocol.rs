use std::net::{IpAddr, SocketAddr, UdpSocket};
use crate::must::protocols::protocol::Protocol;
use std::sync::mpsc::{Receiver, Sender};
use std::{io, thread};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use chrono::Local;
use crate::must::network::network_icd::NetworkICD;


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


    fn receive(&self, sender: Sender<Vec<u8>>) {
        let mut buffer = [0; 1024];
        let socket =  self.socket.try_clone().unwrap();
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((number_of_bytes, _src_addr)) => {
                    let data = buffer[..number_of_bytes].to_vec();
                    if let Err(e) = sender.send(data) {
                        eprintln!("Failed to send data over channel: {}", e);
                    }
                },
                Err(e) => eprintln!("Failed to receive data: {}", e),
            }
        }
    }

    fn send(&self, receiver: Receiver<Vec<u8>>, target_ip: IpAddr, target_port: u16) {
        let target_socket_addr = SocketAddr::new(target_ip, target_port);

        println!("In Send");
        let socket = self.socket.try_clone().unwrap();
        loop {
            match receiver.recv() {

                Ok(data) => {
                    println!("Data: {:?}", &data);
                    match socket.send_to(&data, target_socket_addr) {
                        Ok(_) => println!("Successfully sent data to {}:{}", target_ip, target_port),
                        Err(e) => eprintln!("Failed to send data to {}: {}", target_socket_addr, e),
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
impl Clone for UdpProtocol {
    fn clone(&self) -> Self {
        UdpProtocol {
            socket: self.socket.try_clone().expect("Failed to clone UdpSocket"),
        }
    }
}