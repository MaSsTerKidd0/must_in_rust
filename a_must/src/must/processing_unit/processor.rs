use std::collections::VecDeque;
use std::error::Error;
use std::ops::Deref;
use std::path::PrefixComponent;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::{Oaep, RsaPublicKey};
use rsa::sha2::Sha256;
use serde::__private::from_utf8_lossy;
use crate::must::ciphers_lib::AesType;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::ciphers_lib::rsa_crypto::RsaCryptoKeys;
use crate::must::log_assistant::{LogAssistant, OperationId};
use crate::must::log_handler::LOG_HANDLER;
use crate::must::network::network_icd::NetworkICD;
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
const MIN_PACKETS_TO_ASSEMBLE: usize = 25;


pub struct ProcessorUnit;

impl ProcessorUnit {
    pub(crate) fn process(packet_data_rx: Receiver<Vec<u8>>, processed_data_tx: Sender<Vec<u8>>, config_record: ConfigRecord, remote_networks: &NetworkConfig) {
        let mut received_public_key = None;

        // while received_public_key.is_none() {
        //     if let Ok(received_message) = packet_data_rx.recv() {
        //         let received_message_payload = ProcessorUnit::extract_payload(&received_message, UDP);
        //         if String::from_utf8_lossy(&received_message_payload.unwrap()) == REQUEST_PUBLIC_KEY {
        //             // Send your public key
        //             let my_public_key = RsaCryptoKeys::get_public_key_pem().expect("Failed to get public key PEM");
        //             processed_data_tx.send(my_public_key.as_bytes().to_vec()).expect("Failed to send public key PEM");
        //
        //             // Additionally, send a request for the other party's public key
        //             processed_data_tx.send(REQUEST_PUBLIC_KEY.as_bytes().to_vec()).expect("Failed to request public key");
        //
        //             break;
        //         }
        //         // } else {
        //         //     // Handle receiving the other party's public key
        //         //     received_public_key = handle_key_exchange(received_message, REQUEST_PUBLIC_KEY, KEY_RECEIVED_ACKNOWLEDGMENT);
        //         // }
        //     }
        // }
        let mut net_icd_queue = VecDeque::new();

        let aes_type = AesType::from_str(&config_record.aes_type).unwrap();
        let fragment_unit = Fragment {
            first_net_max_bandwidth: 8 as u16,
            second_net_max_bandwidth: 16 as u16,
        };

        let mut packet_counter: u32 = 0;
        let mut start_time = Instant::now();

        let encryptor = Encryptor::new(aes_type).unwrap();

        while let Ok(packet_vec) = packet_data_rx.recv() {
            let network_state = Filter::identify_network_state_for_packet(&packet_vec, &config_record, remote_networks, UDP);
            match network_state {
                Some(NetworkState::SecureNetwork) => {
                    ProcessorUnit::handle_secure_network_packet(packet_vec, encryptor.clone());
                }
                Some(NetworkState::UnsecureNetwork) => {
                   //TODO:: assemble packets
                    ProcessorUnit::process_unsecure_packet(packet_vec, UDP, &mut net_icd_queue);
                    let assembled_data = ProcessorUnit::handle_unsecure_network_packet(&mut net_icd_queue, &fragment_unit);
                    if !assembled_data.is_empty() {
                        // Handle the assembled data
                        let pac = from_utf8_lossy(&assembled_data);
                        println!("Processed packet as text: {}", pac);
                    }

                }
                Some(NetworkState::SecureNetworkRemote) => {
                    let aes_key = KeyGenerator::generate_key(KeySize::Bits256);
                    let nonce = Encryptor::generate_iv_or_nonce(Some(aes_type)).unwrap_or_default();
                    if let Some(encrypted_payload) = ProcessorUnit::encrypt_packet_payload(&packet_vec, aes_key.clone(), nonce.clone(), encryptor.clone()) {
                        let packets_to_send = ProcessorUnit::fragment_and_prepare_packets(encrypted_payload, &fragment_unit, aes_key, nonce, &received_public_key);
                        ProcessorUnit::send_packets(packets_to_send, &processed_data_tx, &mut packet_counter, &mut start_time);
                    }
                }
                Some(NetworkState::UnsecureNetworkRemote) => {
                    let packet_payload = ProcessorUnit::extract_payload(packet_vec.as_slice(), UDP);
                    let packets_to_send = fragment_unit.fragment(&*packet_payload.unwrap(), Vec::new(), Vec::new() ,false);
                    ProcessorUnit::send_packets(packets_to_send.iter().filter_map(|packet| packet.to_bytes().ok()).collect(), &processed_data_tx, &mut packet_counter, &mut start_time);
                }
                None => {
                    //TODO:change to log
                    println!("Unrecognized Network")
                }
            }
        }
    }
    fn encrypt_packet_payload(packet_vec: &Vec<u8>, aes_key: Vec<u8>, nonce: Vec<u8>, encryptor: Encryptor) -> Option<Vec<u8>> {
        ProcessorUnit::extract_payload(packet_vec, UDP)
            .and_then(|payload| encryptor.encrypt_data(&payload, aes_key, &nonce).ok())
    }

    fn fragment_and_prepare_packets(encrypted_payload: Vec<u8>,
                                    fragment_unit: &Fragment,
                                    aes_key: Vec<u8>,
                                    nonce: Vec<u8>,
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

        let fragmented_packets = fragment_unit.fragment(encrypted_payload.as_slice(), encrypted_aes_key, nonce,true);
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
        //The Byte the payload starts from.
        let ethernet_and_ip_header_length = 34;

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


    fn handle_secure_network_packet(packet: Vec<u8>, encryptor: Encryptor) -> Option<Vec<u8>> {
        match ProcessorUnit::extract_payload(&packet, Protocol::UDP) {
            Some(payload) => {
                let net_icd_packet_result = NetworkICD::from_bytes(&payload);
                println!("Packet Data: {:?}", &payload);
                // Here, we use pattern matching to handle the Result more gracefully
                match net_icd_packet_result {
                    Ok(net_icd_packet) => {
                        println!("Packet ICD: {:?}", net_icd_packet);
                        let aes_current_key = &net_icd_packet.aes_key;
                        let encrypted_aes_data = &net_icd_packet.data;
                        let aes_nonce_or_iv = &net_icd_packet.iv_or_nonce;
                        let decrypted_aes_data = ProcessorUnit::decrypt_aes_payload(encrypted_aes_data, aes_current_key, aes_nonce_or_iv, encryptor);
                        println!("Decrypted Data: {:?}", decrypted_aes_data);

                        if let Some(decrypted_data) = decrypted_aes_data {
                            match String::from_utf8(decrypted_data) {
                                Ok(text) => println!("Decrypted Text: {}", text),
                                Err(e) => eprintln!("Failed to convert decrypted data to UTF-8: {:?}", e),
                            }
                        }
                    },
                    Err(e) => eprintln!("Failed to parse Network ICD: {:?}", e),
                }
            }
            None => {
                // Handle the case where extracting the payload fails.
                eprintln!("Failed to extract payload from packet.");
            }
        }
        Some(Vec::new()) // Assuming you'll replace this with actual logic to return meaningful data
    }

    // fn handle_unsecure_network_packet(packet: Vec<u8>, protocol: Protocol, fragment: Fragment) -> Vec<u8> {
    //     let packet_payload = ProcessorUnit::extract_payload(&packet, protocol);
    //     let mut net_icd_queue:VecDeque<NetworkICD> = Default::default();
    //     match NetworkICD::from_bytes(&packet_payload.unwrap()) {
    //         Ok(net_icd_packet) => {
    //             net_icd_queue.push_back(net_icd_packet);
    //         }
    //         Err(_) => {
    //
    //         }
    //     }
    //
    //
    //     fragment.assemble(net_icd_queue)
    //
    // }
    fn handle_unsecure_network_packet(net_icd_queue: &mut VecDeque<NetworkICD>, fragment: &Fragment) -> Vec<u8> {
        if net_icd_queue.len() >= MIN_PACKETS_TO_ASSEMBLE {
            fragment.assemble(net_icd_queue.clone())
        } else {
            Vec::new()
        }
    }

    fn process_unsecure_packet(packet: Vec<u8>, protocol: Protocol, net_icd_queue: &mut VecDeque<NetworkICD>) {
        if let Some(packet_payload) = ProcessorUnit::extract_payload(&packet, protocol) {
            if let Ok(net_icd_packet) = NetworkICD::from_bytes(&packet_payload) {
                net_icd_queue.push_back(net_icd_packet);
            }
        }
    }

    fn decrypt_rsa_packet(cipher_data: &[u8]) -> Option<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();
        let decrypted_data = RsaCryptoKeys::load()
            .ok()?
            .get_private_key()
            .decrypt(padding, cipher_data)
            .ok()?;
        Some(decrypted_data)
    }

    fn decrypt_aes_payload(encrypted_data: &[u8], aes_key: &[u8], nonce: &[u8], encryptor: Encryptor) -> Option<Vec<u8>> {
        Some(encryptor.decrypt_data(encrypted_data, aes_key.to_vec(), nonce)
            .unwrap_or_default())
    }

    // fn extract_aes_key_and_payload_from_rsa_decrypted_data(decrypted_data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    //     if decrypted_data.len() > 32 {
    //         // Assuming the AES key is the first 32 bytes of the decrypted data
    //         let aes_key = decrypted_data[..32].to_vec();
    //         // The rest of the data is the payload
    //         let payload = decrypted_data[32..].to_vec();
    //
    //         Some((aes_key, payload))
    //     } else {
    //         // If the decrypted data is not long enough to contain both an AES key and payload,
    //         // return None to indicate a failure to extract
    //         // error
    //         None
    //     }
    // }

    fn assemble_packet(payload: &[u8], protocol: Protocol) -> Vec<u8> {
        let mut assembled_packet = Vec::new();

        // Implement the logic to add the required headers (e.g., Ethernet, IP, UDP/TCP)
        // based on the protocol and network specifications
        // ...

        assembled_packet.extend_from_slice(payload);
        assembled_packet
    }
}

// pub fn handle_key_exchange(received_message: Vec<u8>, request_public_key: &str, key_received_acknowledgment: &str) -> Option<RsaPublicKey> {
//     // This function now assumes received_message could be a public key in PEM format directly
//     // Try to parse the received message as a PEM-encoded public key
//     if let Ok(pem_str) = String::from_utf8(received_message) {
//         // Attempt to parse the PEM string into an RsaPublicKey
//         match RsaPublicKey::from_pkcs1_pem(&pem_str) {
//             Ok(public_key) => {
//                 // Optionally, send an acknowledgment here if needed
//                 return Some(public_key);
//             },
//             Err(_) => {
//                 // The message wasn't a valid PEM-encoded public key
//                 // Handle error or continue
//             }
//         }
//     }
//     None
// }