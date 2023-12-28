use crate::must::protocols::protocol::Protocol;

pub struct TcpProtocol;

impl Protocol for TcpProtocol {
    fn receive(&self) -> Option<String> {
        todo!()
    }

    fn send(&self) -> Option<String> {
        todo!()
    }
}