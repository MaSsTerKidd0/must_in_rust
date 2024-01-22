use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device};

pub struct ReceiveUnit {
    pub(crate) device: Device,
    pub(crate) packet_data_tx: Sender<Vec<u8>>,
}
impl ReceiveUnit {
    pub fn new(device: Device, packet_data_tx: Sender<Vec<u8>>) -> ReceiveUnit {
        ReceiveUnit{
            device,
            packet_data_tx,
        }
    }
}