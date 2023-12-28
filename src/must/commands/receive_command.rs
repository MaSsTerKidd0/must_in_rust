use std::thread;
use std::time::Duration;
use pcap::{Active, Capture};
use crate::must::receive_unit::receive::ReceiveUnit;
use super::command::Command;


impl Command for ReceiveUnit {
    fn execute(&self) {
        let mut cap: Capture<Active> = self.device.clone().open().unwrap();
        println!("listening on {:?}", self.device.desc.clone().unwrap());
        while let Ok(packet) = cap.next_packet() {
            thread::sleep(Duration::from_millis(1));
            self.packet_data_tx.send(packet.data.clone().to_vec()).unwrap();
        }
    }
}