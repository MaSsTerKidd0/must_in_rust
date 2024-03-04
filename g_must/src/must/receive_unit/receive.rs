use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device};

pub struct ReceiveUnit;
impl ReceiveUnit {
    pub(crate) fn receive(device: Device, packet_data_tx:Sender<Vec<u8>> ) {
        let mut cap: Capture<Active> = device.clone().open().unwrap();
        println!("listening on {:?}", device.desc.clone().unwrap());
        while let Ok(packet) = cap.next_packet() {
            thread::sleep(Duration::from_millis(1));
            packet_data_tx.send(packet.data.to_vec()).unwrap();
        }
    }
}