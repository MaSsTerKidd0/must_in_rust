use std::io;
use std::net::{IpAddr, SocketAddr};
use std::io::Result;
use std::sync::mpsc::{Receiver, Sender};
use crate::must::network_icd::network_icd::NetworkICD;


pub trait Protocol {
    fn new(addr: SocketAddr) -> Self;
    fn receive(&self, sender: Sender<Vec<u8>>);
    // Updated to include target IP and port as parameters
    fn send(&self, receiver: Receiver<Vec<u8>>, network_type:bool, target_ip: IpAddr, target_port: u16);
}