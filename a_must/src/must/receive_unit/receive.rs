use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device, Error, Packet};

pub struct ReceiveUnit;
impl ReceiveUnit {
    pub(crate) fn receive(device: Device, packet_data_tx: Sender<Vec<u8>>, running: Arc<AtomicBool>) {
        let mut cap = Capture::from_device(device.clone()).unwrap()
            .promisc(true)
            .snaplen(5000)
            .timeout(14)
            .open().unwrap();

        while running.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    // Assuming Ethernet (14 bytes) + IP (20 bytes for header without options) + TCP/UDP header
                    // This is a very basic example and might not be accurate for all cases.
                    if packet.data.len() > 34 { // Check if packet is long enough for IP+TCP/UDP header
                        let source_ip = format!("{}.{}.{}.{}",
                                                packet.data[26], packet.data[27], packet.data[28], packet.data[29]);
                        let protocol = packet.data[23];

                        // TCP or UDP
                        if protocol == 6 || protocol == 17 {
                            let source_port = ((packet.data[34] as u16) << 8) | (packet.data[35] as u16);
                            println!("Packet from IP: {}, Port: {}", source_ip, source_port);
                        }

                        packet_data_tx.send(packet.data.to_vec()).unwrap();
                    }
                },
                Err(pcap::Error::TimeoutExpired) => {
                    // Do Nothing
                },
                Err(e) => {
                    println!("Error receiving packet: {:?}", e);
                    break;
                }
            }
        }
    }
}