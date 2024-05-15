
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use pcap::{Capture, Device};
use crate::must::web_api::handlers::dashboard_handler::GLOBAL_STATUS;

pub struct ReceiveUnit;
impl ReceiveUnit {
    pub(crate) fn receive(device: Device, packet_data_tx: Sender<Vec<u8>>, running: Arc<AtomicBool>) {
        let mut cap = Capture::from_device(device.clone())
            .unwrap()
            .promisc(true)
            .snaplen(5000)
            .timeout(14)
            .open()
            .unwrap();

        while running.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    packet_data_tx.send(packet.data.to_vec()).unwrap();
                    // Update the global state
                    let mut status = GLOBAL_STATUS.lock().unwrap();
                    status.connection_established = true;
                    status.data_transmitted = false;
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Do Nothing
                }
                Err(e) => {
                    println!("Error receiving packet: {:?}", e);
                    break;
                }
            }
        }
    }
}