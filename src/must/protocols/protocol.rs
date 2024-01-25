use std::io;
use std::net::{IpAddr, SocketAddr};
use std::io::Result;
use std::sync::mpsc::{Receiver, Sender};

pub trait Protocol {
    fn new(addr: SocketAddr) -> Self;
    fn receive(&self, sender: Sender<Vec<u8>> );
    fn send(&self, target_addr: IpAddr, target_port: u16, receiver: Receiver<Vec<u8>>);
}