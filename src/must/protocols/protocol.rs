use std::net::SocketAddr;
use std::io::Result;
pub trait Protocol {
    fn new(addr: SocketAddr) -> Self;
    fn receive(&self) -> Result<Option<String>>;
    fn send(&self,target_addr: String, message: &[u8]) -> Result<()>;
}