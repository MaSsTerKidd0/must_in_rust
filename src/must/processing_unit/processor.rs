use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::must::ciphers_lib::AesType;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::log_assistant::{LogAssistant, OperationId};
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
        let aes_type = AesType::from_str(&config_record.aes_type).unwrap();
        let fragment_unit = Fragment {
            first_net_max_bandwidth: config_record.unsecure_net_bandwidth as u16,
            second_net_max_bandwidth: config_record.secure_net_bandwidth as u16,
        };

        let mut packet_counter: u32 = 0;
        let mut start_time = Instant::now();

        while let Ok(packet_vec) = packet_data_rx.recv() {
            if ProcessorUnit::should_process_packet(&packet_vec, &config_record) {
                if let Some(encrypted_payload) = ProcessorUnit::encrypt_packet_payload(&packet_vec, aes_type.clone(), key.clone()) {
                    ProcessorUnit::fragment_and_send_packets(encrypted_payload, &fragment_unit, &processed_data_tx, &mut packet_counter, &mut start_time);
                }
            }
        }
    }
    fn should_process_packet(packet_vec: &Vec<u8>, config_record: &ConfigRecord) -> bool {
        Filter::is_protocol_packet_for_ip(packet_vec, &config_record.unsecure_net, UDP)
    }
    fn encrypt_packet_payload(packet_vec: &Vec<u8>, aes_type: AesType, key: Vec<u8>) -> Option<Vec<u8>> {
        ProcessorUnit::extract_payload(packet_vec, UDP)
            .and_then(|payload| Encryptor::encrypt_data(&payload, Some(aes_type), key).ok())
    }
    fn fragment_and_send_packets(encrypted_payload: Vec<u8>, fragment_unit: &Fragment, processed_data_tx: &Sender<Vec<u8>>, packet_counter: &mut u32, start_time: &mut Instant) {
        let fragmented_packets = fragment_unit.fragment(encrypted_payload.as_slice());
        for packet in fragmented_packets {
            if let Ok(serialized_packet) = packet.to_bytes() {
                if let Err(_) = processed_data_tx.send(serialized_packet) {
                    LogAssistant::fragment_failure(OperationId::Fragmentation);
                    break;
                }
                *packet_counter += 1;
                if start_time.elapsed() >= Duration::new(1, 0) {
                    LogAssistant::send_success(OperationId::SendPacket, *packet_counter);
                    *packet_counter = 0;
                    *start_time = Instant::now();
                }
            } else {
                LogAssistant::serialize_failure(OperationId::Serialization);
            }
        }
    }
    fn extract_payload(packet_data: &[u8], protocol: Protocol) -> Option<Vec<u8>> {
            let ethernet_and_ip_header_length = 14 + 20;

            if packet_data.len() < ethernet_and_ip_header_length {
                return None;
            }

            let header_size = match protocol {
                TCP => ethernet_and_ip_header_length + 20,
                UDP => ethernet_and_ip_header_length + 8,
            };

            if packet_data.len() > header_size {
                Some(packet_data[header_size..].to_vec())
            } else {
                None
            }
        }
}

