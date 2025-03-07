#![allow(warnings)]
mod must;

use std::string::String;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::{fs, io, thread};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Barrier, Mutex};
use pcap::Device;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::json_handler::JsonHandler;
use crate::must::network::network_icd::{NetworkICD, SECURE_NET, UNSECURE_NET};
use aes_gcm_siv::{Nonce, aead::{Aead}};
use rand::{rngs::OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use crate::must::ciphers_lib::aes_modes::aes_cbc_cipher::AesCbc;
use crate::must::ciphers_lib::aes_modes::aes_ctr_cipher::AesCtr;
use crate::must::ciphers_lib::rsa_crypto::{RsaCryptoKeys, RsaKeySize};
use tokio;
use actix_web::{web, App, HttpServer, middleware::Logger, HttpResponse};
use actix_cors::Cors;
use actix_web::http::header;
use chrono::{Local, Utc};
use pem::parse;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::RsaPublicKey;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use mongodb::{Client, bson::{doc, DateTime}};
use crate::must::log_assistant::LogAssistant;
use crate::must::log_handler::LOG_HANDLER;
use crate::must::mongo_db_handler::get_mongo_handler;
use crate::must::network;
use crate::must::network::remote_networks::NetworkConfig;
use crate::must::processing_unit::actions_chain::filter::Protocol::UDP;
use crate::must::processing_unit::processor::ProcessorUnit;
use crate::must::protocols::protocol::Protocol;
use crate::must::protocols::tcp_protocol::TcpProtocol;
use crate::must::protocols::udp_protocol::UdpProtocol;
use crate::must::receive_unit::receive::ReceiveUnit;
use crate::must::send_unit::send::{SendUnit};
use crate::must::web_api::handlers;
use crate::must::web_api::handlers::config_handler::find_config_by_name;
use crate::must::web_api::models::config_record::ConfigRecord;
use crate::must::web_api::models::rsa_record::PublicKeyData;
use crate::must::web_api::models::user_record::UserRecord;



const LOCAL_MUST_IP: &str = "0.0.0.0";
const LOCAL_MUST_PORT: u16 = 0;

fn main(){
    let configuration_name = "Save18";
    let config = find_config_by_name("configurations.json", configuration_name).unwrap().unwrap();

    //RsaCryptoKeys::generate(RsaKeySize::Bits2048);
    let networks = load_remote_network().unwrap();

    let running = Arc::new(AtomicBool::new(true));


    let mut secure_net = String::from(config.secure_net.clone());
    let mut  unsecure_net = String::from(config.unsecure_net.clone());

    let secure_net_port:u16 = config.secure_net_port;
    let unsecure_net_port:u16 = config.unsecure_net_port;
    println!("Secure-{}:{}, Unsecure-{}:{}",secure_net, secure_net_port, unsecure_net, unsecure_net_port);

    let (pre_process_sender, pre_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (post_process_sender, post_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (secure_sender, secure_receiver) = std::sync::mpsc::channel::<Vec<u8>>();


    let unsecure_device = device_picker();
    println!("Selected unsecure device: {}", unsecure_device.desc.clone().unwrap());
    let pre_process_sender_clone = pre_process_sender.clone(); // Clone the sender for the first thread
    let run_clone = running.clone();
    let receive_unsecure = thread::spawn(move  || ReceiveUnit::receive(unsecure_device, pre_process_sender_clone, run_clone));

    let secure_device = device_picker();
    println!("Selected secure device: {}", secure_device.desc.clone().unwrap());
    let run_clone = running.clone();
    let receive_secure = thread::spawn(move|| ReceiveUnit::receive(secure_device, pre_process_sender, run_clone));


    let process_thread = thread::spawn(move|| ProcessorUnit::process(pre_process_receiver, post_process_sender, config.clone(), &networks));
    let send_unit = SendUnit::new_udp(LOCAL_MUST_IP.parse().unwrap(), LOCAL_MUST_PORT);

    let send_unit_clone = send_unit.clone();
    let secure_send = thread::spawn(move || send_unit_clone.send(secure_receiver,secure_net.parse().unwrap(), secure_net_port));
    let send_unit_clone = send_unit.clone();
    let unsecure_send = thread::spawn(move || send_unit.send(post_process_receiver,unsecure_net.parse().unwrap(), unsecure_net_port));

    // Clone the Arc to share send_unit between threads
    let run_clone = running.clone();
    ctrlc::set_handler(move||{
        run_clone.store(false, Ordering::SeqCst)
    }).expect("Error setting SIGINT handler");

    let run_clone = running.clone();
    signal_hook::flag::register(signal_hook::consts::SIGTERM, run_clone)
        .expect("Error setting SIGTERM handler");

    while running.load(Ordering::SeqCst){
        thread::sleep(Duration::from_secs(1));
    }

    // This triggers ReceiveUnit::receive to stop.
    // The Sender that ReceiveUnit::receive thread owns, goes out of scope.
    // When a Sender goes out of scope, its accompanying receiver immediately
    // returns error.
    // When that happens, it causes a chain reaction that cause all the threads
    // to error out and return gracefully.
    running.store(false, Ordering::SeqCst);

    receive_unsecure.join().unwrap();
    receive_secure.join().unwrap();
    secure_send.join().unwrap();
    unsecure_send.join().unwrap();
    process_thread.join().unwrap();
}

fn load_remote_network() -> Result<NetworkConfig, Box<dyn std::error::Error>> {
    let remote_networks_json_file_path = "remote_networks.json";
    let network_config: NetworkConfig = JsonHandler::load(remote_networks_json_file_path)?;

    Ok(network_config)
}



fn show_devices() {
    let mut device_no = 1;
    match Device::list() {
        Ok(devices) => {
            for device in devices {
                print!("Device No.{} - ", device_no);
                println!("Description: {:?}", device.desc);
                device_no = device_no + 1;
            }
        }
        Err(e) => {
            eprintln!("Error listing devices: {}", e);
        }
    }
}

fn device_picker() -> Device {
    let devices = Device::list().unwrap();
    let mut choice: usize = 0;
    while choice < 1 || choice > devices.len() {
        println!("Select a device");
        show_devices();
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        choice = input.trim().parse::<usize>().unwrap();
    }
    return devices.get(choice - 1).unwrap().clone();
}
