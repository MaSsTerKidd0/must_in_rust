use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender};
use std::thread;
use std::time::Duration;
use pcap::{Active, Capture, Device, Error, Packet};

pub struct ReceiveUnit;
impl ReceiveUnit {
    /// Receives packets from a network device and sends them through a Sender channel.
    ///
    /// This function continuously captures packets from the specified network device using the pcap library.
    /// It is designed to run in a separate thread and will continue to run until the `running` flag is set to false.
    /// Each packet's data is sent to a specified Sender<Vec<u8>> channel for further processing.
    ///
    /// # Parameters:
    /// - `device`: The network device (`Device`) from which packets are to be captured.
    /// - `packet_data_tx`: The Sender channel (`Sender<Vec<u8>>`) used to transmit the packet data.
    /// - `running`: A shared atomic boolean (`Arc<AtomicBool>`) used to control the execution of the capture loop.
    ///
    /// # Panics:
    /// - The function will panic if it fails to open the device or if sending through the channel fails.
    ///
    /// # Errors:
    /// - Errors from the pcap library (except for `TimeoutExpired`) will cause the loop to break and print an error message.
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