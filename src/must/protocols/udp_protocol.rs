use std::net::{IpAddr, SocketAddr, UdpSocket};
use crate::must::protocols::protocol::Protocol;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use env_logger::Target;

pub struct UdpProtocol {
    pub(crate) socket: UdpSocket,
}

impl Protocol for UdpProtocol {
    fn new(addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind(addr)
            .expect("Failed to bind to address");
        UdpProtocol { socket }
    }

    fn receive(&self, sender: Sender<Vec<u8>> ){
        let mut buffer = [0; 1024];
        match self.socket.recv_from(&mut buffer) {
            Ok((number_of_bytes, _src_addr)) => {
                // Create a Vec from the received bytes
                let data = buffer[..number_of_bytes].to_vec();

                // Send the message through the sender
                if let Err(e) = sender.send(data) {
                    eprintln!("Failed to send data: {}", e);
                }
            },
            Err(e) => eprintln!("Failed to receive data: {}", e),
        }
    }
    fn send(&self, target_addr: IpAddr, target_port: u16, receiver: Receiver<Vec<u8>>) {
        let data = receiver.recv().map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Channel receive error"));

        // Construct the target socket address from the IP address and the port number
        let target_socket_addr = SocketAddr::new(target_addr, target_port);

        // Send the data to the target socket address
        self.socket.send_to(&data.unwrap(), target_socket_addr).expect("TODO: panic message");
    }

}
