
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use crate::must::protocols::protocol::Protocol;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
pub struct TcpProtocol {
    addr: SocketAddr,
}

impl Protocol for TcpProtocol {
    fn new(addr: SocketAddr) -> Self {
        TcpProtocol { addr }
    }

    async fn receive(&self) -> io::Result<Option<String>> {
        let listener = TcpListener::bind(self.addr).await?;
        match listener.accept().await {
            Ok((mut socket, _)) => {
                let mut data = vec![0; 1024];
                let size = socket.read(&mut data).await?;
                data.truncate(size);
                Ok(Some(String::from_utf8_lossy(&data).to_string()))
            },
            Err(e) => Err(e),
        }
    }

    async fn send(&self, message: String) -> io::Result<Option<String>> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.write_all(message.as_bytes()).await?;
        Ok(Some(message))
    }
}
