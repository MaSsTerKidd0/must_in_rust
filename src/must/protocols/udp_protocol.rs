use std::net::{SocketAddr, UdpSocket};
use crate::must::protocols::protocol::Protocol;
use std::io;
pub struct UdpProtocol{
    socket: UdpSocket,
}

impl Protocol for UdpProtocol{
    fn new(addr: SocketAddr) -> Self {
        let socket = UdpSocket::bind(addr)
            .expect("Failed to bind to address");
        UdpProtocol { socket }
    }

    fn receive(&self) -> io::Result<Option<String>> {
        let mut buffer = [0; 1024];
        match self.socket.recv_from(&mut buffer) {
            Ok((number_of_bytes, _src_addr)) => {
                let message = std::str::from_utf8(&buffer[..number_of_bytes])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Some(message.to_string()))
            },
            Err(e) => Err(e),
        }
    }

    fn send(&self, target_addr: String, message: &[u8]) -> io::Result<()> {
        let target_socket_addr: SocketAddr = target_addr.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address format"))?;
        self.socket.send_to(message, target_socket_addr).map(|_number_of_bytes| ())
    }
}
