use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;
use crate::must::processing_unit::actions_chain::filter::{Filter, Protocol};
use crate::must::processing_unit::actions_chain::filter::Protocol::{UDP,TCP};

pub struct ProcessorUnit;

impl ProcessorUnit {

    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>) {
        println!("\n\nIn Process");

        while let Ok(packet_vec) = packet_data_rx.recv() {
            println!("*received packet");
            if Filter::is_protocol_packet_for_ip(&packet_vec,"127.0.0.1", UDP) {
                if let Some(payload) = extract_payload(&packet_vec, UDP) {
                    println!("*Passed Filter\n");

                    if let Err(e) = processed_data_tx.send(payload) {
                        println!("Failed to send processed data: {:?}", e);
                        break;
                    }
                }
            }
        }
    }
}

fn extract_payload(packet_data: &[u8], protocol: Protocol) -> Option<Vec<u8>> {
    // Ethernet frame is 14 bytes, minimum IP header is 20 bytes
    let ethernet_and_ip_header_length = 14 + 20;

    if packet_data.len() < ethernet_and_ip_header_length {
        return None;
    }

    // Calculate the total header size based on the protocol
    // Add the length of the Ethernet frame to the header size
    let header_size = match protocol {
        TCP => ethernet_and_ip_header_length + 20, // Ethernet + IP header + TCP header
        UDP => ethernet_and_ip_header_length + 8,  // Ethernet + IP header + UDP header
    };

    // Extract the payload
    if packet_data.len() > header_size {
        Some(packet_data[header_size..].to_vec())
    } else {
        None
    }
}