use std::ops::Deref;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::RsaPublicKey;
use crate::must::ciphers_lib::AesType;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::ciphers_lib::rsa_crypto::RsaCryptoKeys;
use crate::must::log_assistant::{LogAssistant, OperationId};
use crate::must::log_handler::LOG_HANDLER;
use crate::must::network::remote_networks::NetworkConfig;
use crate::must::processing_unit::actions_chain::encrypt;
use crate::must::processing_unit::actions_chain::encrypt::Encryptor;
use crate::must::processing_unit::actions_chain::filter::{Filter, Protocol};
use crate::must::processing_unit::actions_chain::filter::Protocol::{UDP, TCP};
use crate::must::processing_unit::actions_chain::fragment::Fragment;
use crate::must::web_api::models::config_record::ConfigRecord;

pub struct ProcessorUnit;

impl ProcessorUnit {
    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>, config_record: ConfigRecord, remote_networks: &NetworkConfig) {

        let aes_type = AesType::from_str(&config_record.aes_type).unwrap();
        let rsa = RsaCryptoKeys::load().unwrap();
        processed_data_tx.send(rsa.get_public_key().to_pkcs1_der().unwrap().as_ref().to_vec());

        let fragment_unit = Fragment {
            first_net_max_bandwidth: config_record.unsecure_net_bandwidth as u16,
            second_net_max_bandwidth: config_record.secure_net_bandwidth as u16,
        };

        let mut packet_counter: u32 = 0;
        let mut start_time = Instant::now();

        while let Ok(packet_vec) = packet_data_rx.recv() {
            if Filter::is_protocol_packet_for_ip(packet_vec.clone().as_slice(), config_record.clone(), remote_networks.clone(), UDP) {
                let aes_key = KeyGenerator::generate_key(KeySize::Bits256);
                if let Some(encrypted_payload) = ProcessorUnit::encrypt_packet_payload(&packet_vec, aes_type.clone(), aes_key.clone()) {
                    let packets_to_send = ProcessorUnit::fragment_and_prepare_packets(encrypted_payload, &fragment_unit, aes_key, &rsa);
                    ProcessorUnit::send_packets(packets_to_send, &processed_data_tx, &mut packet_counter, &mut start_time);
                }
            }
        }
    }
    fn encrypt_packet_payload(packet_vec: &Vec<u8>, aes_type: AesType, aes_key: Vec<u8>) -> Option<Vec<u8>> {
        ProcessorUnit::extract_payload(packet_vec, UDP)
            .and_then(|payload| Encryptor::encrypt_data(&payload, Some(aes_type), aes_key).ok())
    }

    fn fragment_and_prepare_packets(encrypted_payload: Vec<u8>,
                                    fragment_unit: &Fragment,
                                    aes_key: Vec<u8>,
                                    rsa: &RsaCryptoKeys) -> Vec<Vec<u8>> {

        let rsa_encrypted_aes_key = rsa.encrypt(&aes_key).unwrap_or_default();
        let fragmented_packets = fragment_unit.fragment(encrypted_payload.as_slice(), rsa_encrypted_aes_key);

        fragmented_packets.iter().filter_map(|packet| packet.to_bytes().ok()).collect()
    }

    fn send_packets(packets: Vec<Vec<u8>>,
                    processed_data_tx: &Sender<Vec<u8>>,
                    packet_counter: &mut u32,
                    start_time: &mut Instant) {
        for packet in packets {
            if processed_data_tx.send(packet).is_err() {
                LogAssistant::fragment_failure(OperationId::Fragmentation);
                break;
            }
            *packet_counter += 1;
            if start_time.elapsed() >= Duration::new(1, 0) {
                LogAssistant::send_success(OperationId::SendPacket, *packet_counter);
                *packet_counter = 0;
                *start_time = Instant::now();
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

