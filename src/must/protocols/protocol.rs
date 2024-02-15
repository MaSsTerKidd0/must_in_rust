use std::io;
use std::net::{IpAddr, SocketAddr};
use std::io::Result;
use std::sync::mpsc::{Receiver, Sender};
use crate::must::network_icd::network_icd::NetworkICD;

pub trait Protocol {
    fn new(addr: SocketAddr, target_addr: SocketAddr) -> Self;
    fn receive(&self, sender: Sender<Vec<u8>>);
    fn send(&self, receiver: Receiver<Vec<u8>>);
}