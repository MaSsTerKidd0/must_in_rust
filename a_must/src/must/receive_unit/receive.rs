use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device, Error, Packet};

pub struct ReceiveUnit;
impl ReceiveUnit {
    pub(crate) fn receive(device: Device, packet_data_tx:Sender<Vec<u8>>, running: Arc<AtomicBool>) {
        let mut cap  = Capture::from_device(device.clone()).unwrap()
            .promisc(true)
            .snaplen(5000)
            .timeout(14)
            .open().unwrap();


        while running.load(Ordering::SeqCst){
            match cap.next_packet() {
                Ok(packet) =>{
                    packet_data_tx.send(packet.data.to_vec()).unwrap();
                }
                Err(pcap::Error::TimeoutExpired)=>{
                    //Do Nothing
                }
                Err(e) => {
                    println!("Error receiving packet: {:?}", e);
                    break;
                }
            }
        }

    }
}