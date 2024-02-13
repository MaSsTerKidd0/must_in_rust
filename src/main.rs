#![allow(unused)]
mod must;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::{fs, io, thread};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use pcap::Device;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::json_handler::JsonHandler;
use crate::must::network_icd::network_icd::NetworkICD;
use aes_gcm_siv::{Nonce, aead::{Aead}};
use rand::{rngs::OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use crate::must::ciphers_lib::aes_modes::aes_cbc_cipher::AesCbc;
use crate::must::ciphers_lib::aes_modes::aes_ctr_cipher::AesCtr;
use crate::must::ciphers_lib::rsa_crypto::{RsaCryptoKeys, RsaKeySize};

use actix_web::{web, App, HttpServer, middleware::Logger, HttpResponse};
use actix_cors::Cors;
use actix_web::http::header;
use chrono::Local;
use pem::parse;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use crate::must::log_assistant::LogAssistant;
use crate::must::log_handler::LOG_HANDLER;
use crate::must::processing_unit::actions_chain::filter::Protocol::UDP;
use crate::must::processing_unit::processor::ProcessorUnit;
use crate::must::protocols::protocol::Protocol;
use crate::must::protocols::tcp_protocol::TcpProtocol;
use crate::must::protocols::udp_protocol::UdpProtocol;
use crate::must::receive_unit::receive::ReceiveUnit;
use crate::must::send_unit::send::{SendUnit};
use crate::must::web_api::handlers;
use crate::must::web_api::handlers::config_handler::find_config_by_name;
use crate::must::web_api::models::rsa_record::PublicKeyData;

//Dear programmer :)
//When I wrote this code, only god and
//I knew how it worked
//Now, only god knows it!
//
//Therefore, if you are trying to optimize
//this routine, and it fails (most surely),
//please increase this counter as a
//warning for the next person:
//
//total hours wasted here: 212
//

// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     std::env::set_var("RUST_LOG", "actix_web=debug");
//     env_logger::init();
//
//     HttpServer::new(move || {
//         let cors = Cors::default()
//             .allowed_origin_fn(|origin, _req_head| {
//                 true
//             })
//             .allowed_methods(vec!["GET", "POST", "OPTIONS"])
//             .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE])
//             .max_age(3600);
//         App::new()
//             .wrap(Logger::default())
//             .wrap(cors)
//             .configure(handlers::config)
//             .configure(handlers::dashboard)
//             .service(handlers::login)
//             .service(handlers::rsa)
//
//     })
//         .bind("127.0.0.1:8080")?
//         .run()
//         .await
// }

fn main(){
    RsaCryptoKeys::generate(RsaKeySize::Bits2048);
    let configuration_name = "Save18";
    let config = find_config_by_name("configurations.json", configuration_name).unwrap().unwrap();

    let mut secure_net = String::from(config.secure_net.clone());
    let mut  unsecure_net = String::from(config.unsecure_net.clone());

    let secure_net_port = config.secure_net_port;
    let unsecure_net_port = config.unsecure_net_port;
    println!("Secure-{}:{}, Unsecure-{}:{}",secure_net, secure_net_port, unsecure_net, unsecure_net_port);

    let (sender, receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (pre_process_sender, pre_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (post_process_sender, post_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();

    let device = device_picker();
    println!("Selected device: {}", device.desc.clone().unwrap());
    post_process_sender.send(Vec::from(RsaCryptoKeys::get_public_key_pem().unwrap()));

    let connection_handler = Arc::new(Mutex::new(SendUnit::new_udp(
        secure_net.parse().unwrap(),
        secure_net_port,
        unsecure_net.parse().unwrap(),
        unsecure_net_port,
    )));

    let handler_clone = connection_handler.clone();
    let temp_thread = thread::spawn(move || {
        let mut handler = handler_clone.lock().unwrap();
        handler.receive(sender)
    });

    // Clone `connection_handler` for each subsequent thread that needs it
    let handler_clone = connection_handler.clone();
    let send_thread = thread::spawn(move || {
        let mut handler = handler_clone.lock().unwrap();
        handler.send(post_process_receiver)
    });

    let receive_thread = thread::spawn(move|| ReceiveUnit::receive(device, pre_process_sender));
    let process_thread = thread::spawn(move|| ProcessorUnit::process(pre_process_receiver, post_process_sender, config.clone()));

    receive_thread.join().unwrap();
    process_thread.join().unwrap();
    send_thread.join().unwrap();
}


fn show_devices() {
    let mut device_no = 1;
    match Device::list() {
        Ok(devices) => {
            for device in devices {
                print!("Device No.{} - ", device_no);
                println!("Description: {:?}", device.desc);
                device_no = device_no+1;
            }
        }
        Err(e) => {
            eprintln!("Error listing devices: {}", e);
        }
    }
}
fn device_picker() -> Device {
    let  devices = Device::list().unwrap();
    let mut choice: usize = 0;
    while choice < 1 || choice > devices.len(){
        println!("Select a device");
        show_devices();
        print!("Please choose device:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        choice = input.trim().parse::<usize>().unwrap();
    }
    return devices.get(choice - 1).unwrap().clone();
}

fn check_assemble_packets(packets: VecDeque<NetworkICD>){
    let assemble = Fragment{
        first_net_max_bandwidth: 0,
        second_net_max_bandwidth: 0,
    };

    let assembled_packet = assemble.assemble(packets);
    match String::from_utf8(assembled_packet) {
        Ok(s) => println!("Converted ASCII: {}", s),
        Err(e) => println!("Failed to convert: {}", e),
    }
}

//TODO: use this to generate random nonce put in the aes
fn generate_key_and_nonce() -> (Vec<u8>, [u8; 16]) {
    let key = KeyGenerator::generate_key(KeySize::Bits256);
    println!("key: {:?}", hex::encode(&key));

    let mut nonce_bytes: [u8; 16] = [0; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    println!("Nonce: {:?}", hex::encode(&nonce_bytes));

    (key, nonce_bytes)
}