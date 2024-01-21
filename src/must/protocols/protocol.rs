use std::net::SocketAddr;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
pub trait Protocol {
    fn new(addr: SocketAddr) -> Self;
    async fn receive(&self) -> io::Result<Option<String>>;
    async fn send(&self, message: String) -> io::Result<Option<String>>;
}