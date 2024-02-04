use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;

use crate::must::ciphers_lib::AesType;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::log_assistant::LogAssistant;
use crate::must::log_handler::LOG_HANDLER;
use crate::must::processing_unit::actions_chain::encrypt;
use crate::must::processing_unit::actions_chain::encrypt::Encryptor;
use crate::must::processing_unit::actions_chain::filter::{Filter, Protocol};
use crate::must::processing_unit::actions_chain::filter::Protocol::{UDP, TCP};
use crate::must::processing_unit::actions_chain::fragment::Fragment;
use crate::must::web_api::models::config_record::ConfigRecord;

pub struct ProcessorUnit;

impl ProcessorUnit {
    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>, config_record: ConfigRecord) {
        let key = KeyGenerator::generate_key(KeySize::Bits256);
        let aes_type_str: &str = config_record.aes_type.as_str();
        let fragment_unit = Fragment {
            first_net_max_bandwidth: 32u16,
            second_net_max_bandwidth: 32u16,
        };
        while let Ok(packet_vec) = packet_data_rx.recv() {
            if Filter::is_protocol_packet_for_ip(&packet_vec, &config_record.unsecure_net, UDP) {
                if let Some(payload) = extract_payload(&packet_vec, UDP) {
                    match Encryptor::encrypt_data(&payload, AesType::from_str(aes_type_str), key.clone()) {
                        Ok(encrypted_payload) => {
                            let fragmented_packets = fragment_unit.fragment(encrypted_payload.as_slice());
                            for packet in fragmented_packets {
                                match packet.to_bytes() {
                                    Ok(serialized_packet) => {
                                        if let Err(e) = processed_data_tx.send(serialized_packet) {
                                            LogAssistant::fragment_failure();
                                            break;
                                        }
                                        LogAssistant::send_success();
                                    }
                                    Err(e) => {
                                        LogAssistant::serialize_failure();
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            LogAssistant::cipher_failure();
                        }
                    }
                }
            }
        }
        fn extract_payload(packet_data: &[u8], protocol: Protocol) -> Option<Vec<u8>> {
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
    }
}

