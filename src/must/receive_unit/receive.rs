use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device};

pub struct ReceiveUnit {
    device: Device,
    packet_data_tx: Sender<Vec<u8>>,
}
impl ReceiveUnit {
    pub fn new(device: Device, packet_data_tx: Sender<Vec<u8>>) -> ReceiveUnit {
        ReceiveUnit{
            device,
            packet_data_tx,
        }
    }
    pub fn receive(&self) {
        let mut cap: Capture<Active> = self.device.clone().open().unwrap();
        println!("listening on {:?}", self.device.desc.clone().unwrap());
        while let Ok(packet) = cap.next_packet() {
            thread::sleep(Duration::from_millis(1));
            self.packet_data_tx.send(packet.data.clone().to_vec()).unwrap();
        }
    }
}