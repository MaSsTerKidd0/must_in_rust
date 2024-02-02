use std::net::{IpAddr, UdpSocket, TcpListener, SocketAddr};
use crate::must::protocols::protocol::Protocol;
use crate::must::protocols::tcp_protocol::TcpProtocol;
use crate::must::protocols::udp_protocol::UdpProtocol;

pub struct SendUnit;

/// Enumeration of protocol types supported by SendUnit.
pub enum ProtocolType {
    Udp(UdpProtocol),
    Tcp(TcpProtocol),
}

impl SendUnit {
    /// Creates a new UdpProtocol instance.
    ///
    /// # Arguments
    /// * `local_ip_addr` - An IP address to bind the UDP socket to.
    /// * `local_port` - The port number to bind the UDP socket to.
    /// * `target_ip_addr` - The target IP address for the UDP protocol.
    /// * `target_port` - The target port for the UDP protocol.
    ///
    /// # Returns
    /// A UdpProtocol instance with the initialized UDP socket and target address.
    ///
    /// # Panics
    /// if the UDP socket cannot be created.
    pub(crate) fn new_udp(local_ip_addr: IpAddr, local_port: u16, target_ip_addr: IpAddr, target_port: u16) -> UdpProtocol {
        let local_addr = SocketAddr::new(local_ip_addr, local_port);
        let target_addr = SocketAddr::new(target_ip_addr, target_port);

        UdpProtocol::new(local_addr, target_addr)
    }

    /// Creates a new TcpProtocol instance.
    ///
    /// # Arguments
    /// * `local_ip_addr` - An IP address to bind the TCP listener to.
    /// * `local_port` - The port number to bind the TCP listener to.
    /// * `target_ip_addr` - The target IP address for the TCP protocol.
    /// * `target_port` - The target port for the TCP protocol.
    ///
    /// # Returns
    /// A TcpProtocol instance with the initialized TCP listener and target address.
    ///
    /// # Panics
    /// if the TCP listener cannot be created.
    pub(crate) fn new_tcp(local_ip_addr: IpAddr, local_port: u16, target_ip_addr: IpAddr, target_port: u16) -> TcpProtocol {
        let local_addr = SocketAddr::new(local_ip_addr, local_port);
        let target_addr = SocketAddr::new(target_ip_addr, target_port);

        TcpProtocol::new(local_addr, target_addr)
    }
}

/// Enumeration for selecting the constructor method of SendUnit.
pub enum SendUnitConstructor {
    Udp(IpAddr, u16, IpAddr, u16),
    Tcp(IpAddr, u16, IpAddr, u16),
}

impl SendUnit {
    /// Factory method for creating a SendUnit with either TCP or UDP protocol.
    ///
    /// # Arguments
    /// * `ctor` - A SendUnitConstructor that specifies the protocol type (TCP or UDP) along with the IP addresses and ports.
    ///
    /// # Returns
    /// A ProtocolType variant (Udp or Tcp) initialized with the specified protocol.
    fn new(ctor: SendUnitConstructor) -> ProtocolType {
        match ctor {
            SendUnitConstructor::Udp(local_ip, local_port, target_ip, target_port) => {
                ProtocolType::Udp(SendUnit::new_udp(local_ip, local_port, target_ip, target_port))
            },
            SendUnitConstructor::Tcp(local_ip, local_port, target_ip, target_port) => {
                ProtocolType::Tcp(SendUnit::new_tcp(local_ip, local_port, target_ip, target_port))
            }
        }
    }
}