use std::sync::mpsc::{Receiver, Sender};
use crate::must::processing_unit::actions_chain::filter::Filter;
use crate::must::processing_unit::actions_chain::filter::Protocol::UDP;

pub struct ProcessorUnit;

impl ProcessorUnit {

    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>) {
        let running = true;
        let ip = "38.0.101.76";
        println!("In Process");

        while running {
            let packet_vec = match packet_data_rx.recv() {
                Ok(data) => data,
                Err(e) => {
                    println!("Failed to receive data: {:?}", e);
                    break;
                }
            };

            println!("received packet\n data: {:?}\n", packet_vec);

            if Filter::is_protocol_packet_for_ip(&packet_vec, ip, UDP) {
                println!("Packet is UDP packet received from IP address: {}", ip);

                // Process packet data as needed

                // Send processed data to the next stage
                match processed_data_tx.send(packet_vec) {
                    Ok(_) => println!("Processed data sent to next stage"),
                    Err(e) => println!("Failed to send processed data: {:?}", e),
                }
            }
        }
    }
}
