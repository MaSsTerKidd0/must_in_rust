use crate::must::protocols::protocol::Protocol;

pub struct Send<T: Protocol> {
    protocol: T,
}
impl<T: Protocol> Send<T> {
    pub fn new(protocol: T) -> Send<T> {
        Send { protocol }
    }
    fn send(&self) {
        self.protocol.send();
    }
}