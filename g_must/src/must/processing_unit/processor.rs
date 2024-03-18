use std::error::Error;
use std::ops::Deref;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{Oaep, RsaPublicKey};
use rsa::sha2::Sha256;
use crate::must::ciphers_lib::AesType;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::ciphers_lib::rsa_crypto::RsaCryptoKeys;
use crate::must::log_assistant::{LogAssistant, OperationId};
use crate::must::log_handler::LOG_HANDLER;
use crate::must::network::remote_networks::NetworkConfig;
use crate::must::processing_unit::actions_chain::encrypt;
use crate::must::processing_unit::actions_chain::encrypt::Encryptor;
use crate::must::processing_unit::actions_chain::filter::{Filter, NetworkState, Protocol};
use crate::must::processing_unit::actions_chain::filter::Protocol::{UDP, TCP};
use crate::must::processing_unit::actions_chain::fragment::Fragment;
use crate::must::web_api::models::config_record::ConfigRecord;

const REQUEST_PUBLIC_KEY: &str = "REQUEST_PUBLIC_KEY";
const KEY_RECEIVED_ACKNOWLEDGMENT: &str = "KEY_RECEIVED_ACKNOWLEDGMENT";
const SENDING_KEY_PREFIX: &str = "SENDING_KEY:";
const SOCKET_READ_TIMEOUT_SECS: u64 = 5;
const SOCKET_WRITE_TIMEOUT_SECS: u64 = 5;
const BUFFER_SIZE: usize = 1024;

pub struct ProcessorUnit;

impl ProcessorUnit {
    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>, config_record: ConfigRecord, remote_networks: &NetworkConfig) {
        let mut received_public_key = None;
        while received_public_key.is_none() {
            if let Ok(received_message) = packet_data_rx.recv() {
                // Assuming REQUEST_PUBLIC_KEY and KEY_RECEIVED_ACKNOWLEDGMENT are defined elsewhere
                received_public_key = handle_key_exchange(received_message, REQUEST_PUBLIC_KEY, KEY_RECEIVED_ACKNOWLEDGMENT);
                if let Some(public_key_pem) = &received_public_key {
                    processed_data_tx.send(RsaCryptoKeys::get_public_key_pem().unwrap().as_bytes().to_vec()).expect("Failed to send public key PEM");
                }
            }
        }


        let aes_type = AesType::from_str(&config_record.aes_type).unwrap();
        let fragment_unit = Fragment {
            first_net_max_bandwidth: config_record.unsecure_net_bandwidth as u16,
            second_net_max_bandwidth: config_record.secure_net_bandwidth as u16,
        };

        let mut packet_counter: u32 = 0;
        let mut start_time = Instant::now();

        while let Ok(packet_vec) = packet_data_rx.recv() {
            let network_state = Filter::identify_network_state_for_packet(&packet_vec, &config_record, remote_networks, UDP);
                match network_state {
                    Some(NetworkState::SecureNetwork) => {
                        // Handle packet for secure local network
                    },
                    Some(NetworkState::UnsecureNetwork) => {
                        // Handle packet for unsecure local network
                    },
                    Some(NetworkState::SecureNetworkRemote) => {
                        // Handle packet for secure remote network
                    },
                    Some(NetworkState::UnsecureNetworkRemote) => {
                        // Handle packet for unsecure remote network
                    },
                    None => {
                        //Unrecognized Network
                    }
                }
                let aes_key = KeyGenerator::generate_key(KeySize::Bits256);
                if let Some(encrypted_payload) = ProcessorUnit::encrypt_packet_payload(&packet_vec, aes_type.clone(), aes_key.clone()) {
                    let packets_to_send = ProcessorUnit::fragment_and_prepare_packets(encrypted_payload, &fragment_unit, aes_key, &received_public_key);
                    ProcessorUnit::send_packets(packets_to_send, &processed_data_tx, &mut packet_counter, &mut start_time);
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
                                    received_public_key: &Option<RsaPublicKey>) -> Vec<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        let encrypted_aes_key = match received_public_key {
            Some(public_key) => {
                let mut rng = rand::thread_rng();
                public_key.encrypt(&mut rng, padding, &mut aes_key.clone().into_boxed_slice())
                    .unwrap_or_default()
            }
            None => Vec::new(),
        };

        let fragmented_packets = fragment_unit.fragment(encrypted_payload.as_slice(), encrypted_aes_key);
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

pub fn handle_key_exchange(received_message: Vec<u8>, request_public_key: &str, key_received_acknowledgment: &str) -> Option<RsaPublicKey> {
    let message_str = String::from_utf8(received_message).unwrap_or_default();

    if message_str == request_public_key {
        match RsaCryptoKeys::get_public_key_pem() {
            Ok(pem_str) => {
                let public_key_pem = pem_str.as_bytes().to_vec();
                let recv_public_key = RsaPublicKey::from_pkcs1_der(&*public_key_pem).unwrap();
                return Some(recv_public_key);
            },
            Err(_) => {
                // Handle error or continue
            }
        }
    }

    None
}