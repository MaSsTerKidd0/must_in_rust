use std::net::{IpAddr, UdpSocket, TcpListener};
use std::sync::mpsc::Receiver;
use crate::must::protocols::protocol::Protocol;
use crate::must::protocols::tcp_protocol::TcpProtocol;
use crate::must::protocols::udp_protocol::UdpProtocol;

pub struct SendUnit;
pub enum ProtocolType {
    Udp(UdpProtocol),
    Tcp(TcpProtocol),
}

impl SendUnit {
    // Constructor for UDP
    pub(crate) fn new_udp(ip_addr: IpAddr, port: u16) -> UdpProtocol {
        // Create a UdpSocket
        let udp_socket = UdpSocket::bind((ip_addr, port))
            .expect("Failed to create UDP socket");

        // Initialize the SendUnit for UDP with the created UdpSocket
        UdpProtocol {
            socket : udp_socket
        }
    }

    // Constructor for TCP
    pub(crate) fn new_tcp(ip_addr: IpAddr, port: u16) -> TcpProtocol {
        // Create a TcpListener
        let tcp_listener = TcpListener::bind((ip_addr, port))
            .expect("Failed to create TCP listener");

        TcpProtocol {
            listener : tcp_listener,
        }
    }
}

// Define an enum to choose the constructor method
pub enum SendUnitConstructor {
    Udp(IpAddr, u16),
    Tcp(IpAddr, u16),
}

impl SendUnit {
    // Function to construct a SendUnit based on the provided enum
    fn new(ctor: SendUnitConstructor) -> ProtocolType {
        match ctor {
            SendUnitConstructor::Udp(ip_addr, port) => {
                ProtocolType::Udp(SendUnit::new_udp(ip_addr, port))
            }
            SendUnitConstructor::Tcp(ip_addr, port) => {
                ProtocolType::Tcp(SendUnit::new_tcp(ip_addr, port))
            }
        }
    }
}
