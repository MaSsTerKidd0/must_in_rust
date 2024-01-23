use std::net::IpAddr;
use crate::must::protocols::protocol::Protocol;

pub struct SendUnit<T: Protocol> {
    protocol: T,
    ip_address: IpAddr,
    port: u16,
}
impl<T: Protocol> SendUnit<T> {
    pub fn new(protocol: T, ip_address: IpAddr, port: u16) -> SendUnit<T> {
        SendUnit { protocol, ip_address, port}
    }
    pub(crate) fn send(&self, message: &[u8]) -> std::io::Result<()> {
        let target_addr = format!("{}:{}", self.ip_address, self.port);
        self.protocol.send(target_addr, message)
    }

}