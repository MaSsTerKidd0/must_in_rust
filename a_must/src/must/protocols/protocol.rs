use std::{io, thread};
use std::net::{IpAddr, SocketAddr};
use std::io::Result;
use std::sync::mpsc::{Receiver, Sender};
use crate::must::network::network_icd::NetworkICD;
use crate::must::protocols::udp_protocol::UdpProtocol;

pub trait Protocol {
    fn new(addr: SocketAddr) -> Self;
    fn receive(&self, sender: Sender<Vec<u8>>);
    fn send(&self, receiver: Receiver<Vec<u8>>, target_ip: IpAddr, target_port: u16);
}