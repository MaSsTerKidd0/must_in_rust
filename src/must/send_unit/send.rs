use std::net::IpAddr;
use std::sync::mpsc::Receiver;
use crate::must::protocols::protocol::Protocol;

pub struct SendUnit<T: Protocol> {
    protocol: T,
    ip_address: IpAddr,
    port: u16,
    receiver: Receiver<Vec<u8>>,
}
impl<T: Protocol> SendUnit<T> {
    pub fn new(protocol: T, ip_address: IpAddr, port: u16, receiver: Receiver<Vec<u8>>) -> SendUnit<T> {
        SendUnit { protocol, ip_address, port, receiver}
    }
    pub(crate) fn send(&self) -> std::io::Result<()> {
        for message in &self.receiver {
            let target_addr = format!("{}:{}", self.ip_address, self.port);
            self.protocol.send(target_addr, &message)?;
        }
        Ok(())
    }

}