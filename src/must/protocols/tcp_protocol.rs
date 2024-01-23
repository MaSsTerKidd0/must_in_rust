
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{self, Read, Write};
use crate::must::protocols::protocol::Protocol;

pub struct TcpProtocol {
    addr: SocketAddr,
}

impl Protocol for TcpProtocol {
    fn new(addr: SocketAddr) -> Self {
        TcpProtocol { addr }
    }

    fn receive(&self) -> io::Result<Option<String>> {
        let listener = TcpListener::bind(self.addr)?;
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buffer = vec![0; 1024];
                let bytes_read = stream.read(&mut buffer)?;
                buffer.truncate(bytes_read);
                Ok(Some(String::from_utf8_lossy(&buffer).to_string()))
            },
            Err(e) => Err(e),
        }
    }

    fn send(&self, target_addr: String, message: &[u8]) -> io::Result<()> {
        let target_socket_addr: SocketAddr = target_addr.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid address format"))?;
        let mut stream = TcpStream::connect(target_socket_addr)?;
        stream.write_all(message)?;
        Ok(())
    }
}