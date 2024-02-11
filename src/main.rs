#![allow(warnings)]
mod must;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::{io, thread};
use std::net::SocketAddr;
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
use crate::must::ciphers_lib::rsa_crypto::RsaCryptoKeys;

use actix_web::{web, App, HttpServer, middleware::Logger, HttpResponse};
use actix_cors::Cors;
use actix_web::http::header;
use chrono::Local;
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
//this routine and it fails (most surely),
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
    generate_and_display_rsa_keys();

    let configuration_name = "Save18";
    let config = find_config_by_name("configurations.json", configuration_name).unwrap().unwrap();

    let mut secure_net = String::from(config.secure_net.clone());
    let mut  unsecure_net = String::from(config.unsecure_net.clone());

    let secure_net_port = config.secure_net_port;
    let unsecure_net_port = config.unsecure_net_port;
    println!("Secure-{}:{}, Unsecure-{}:{}",secure_net, secure_net_port, unsecure_net, unsecure_net_port);
    let (pre_process_sender, pre_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (post_process_sender, post_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();

    let device = device_picker();
    println!("Selected device: {}", device.desc.clone().unwrap());

    let thread1 = thread::spawn(move|| ReceiveUnit::receive(device, pre_process_sender));
    let thread2 = thread::spawn(move|| ProcessorUnit::process(pre_process_receiver, post_process_sender, config.clone()));
    let thread3 = thread::spawn(move|| SendUnit::new_udp(secure_net.parse().unwrap(), secure_net_port, unsecure_net.parse().unwrap(),unsecure_net_port ).send(post_process_receiver));

    thread1.join().unwrap();
    thread2.join().unwrap();
    thread3.join().unwrap();
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
    return devices.get(choice-1).unwrap().clone();
}
fn check_fragmentation() -> VecDeque<NetworkICD>{
    let text = "Hello, ipsum dolor sit amet consectetur adipisicing elit. Maxime mollitia,
molestiae quas vel sint commodi repudiandae consequuntur voluptatum laborum
numquam blanditiis harum quisquam eius sed odit fugiat iusto fuga praesentium
optio, eaque rerum! Provident similique accusantium nemo autem. Veritatis
obcaecati tenetur iure eius earum ut molestias architecto voluptate aliquam
nihil, eveniet aliquid culpa officia aut! Impedit sit sunt quaerat, odit,
tenetur error, harum nesciunt ipsum debitis quas aliquid. Reprehenderit,
quia. Quo neque error repudiandae fuga? Ipsa laudantium molestias eos
sapiente officiis modi at sunt excepturi expedita sint? Sed quibusdam
recusandae alias error harum maxime adipisci amet laborum. Perspiciatis
minima nesciunt dolorem! Officiis iure rerum voluptates a cumque velit
quibusdam sed amet tempora. Sit laborum ab, eius fugit doloribus tenetur
fugiat, temporibus enim commodi iusto libero magni deleniti quod quam
consequuntur! Commodi minima excepturi repudiandae velit hic maxime
doloremque...
";
    let encoded_text = text.as_bytes();

    let max_bandwidth_net1 = 1024;
    let max_bandwidth_net2 = 512;

    let fragmenter= JsonHandler::load::<Fragment>("fragmentation_config.json");
    let fragmented_packets = fragmenter.unwrap().fragment(encoded_text);
    return fragmented_packets;
}
fn check_assemble_packets(packets: VecDeque<NetworkICD>){
    let assemble = Fragment{
        first_net_max_bandwidth: 0,
        second_net_max_bandwidth: 0,
    };

    let assembled_packet = assemble.assemble(packets);
    match convert_dec_to_ascii(assembled_packet) {
        Ok(s) => println!("Converted ASCII: {}", s),
        Err(e) => println!("Failed to convert: {}", e),
    }
}
fn convert_dec_to_ascii(vec: Vec<u8>) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(vec)
}
fn generate_key_and_nonce() -> (Vec<u8>, [u8; 16]) {
    let key = KeyGenerator::generate_key(KeySize::Bits256);
    println!("key: {:?}", hex::encode(&key));

    let mut nonce_bytes: [u8; 16] = [0; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    println!("Nonce: {:?}", hex::encode(&nonce_bytes));

    (key, nonce_bytes)
}
fn perform_aes_encryption_and_decryption(key: &[u8], nonce_bytes: &[u8; 16]) {
    let data = b"Hello, world!";
    match AesCtr::encrypt(data, key.to_vec(), nonce_bytes) {
        Ok(encrypted_data) => {
            println!("Encrypted Data: {:?}", hex::encode(&encrypted_data));
            match AesCtr::decrypt(&encrypted_data, key.to_vec(), nonce_bytes) {
                Ok(decrypted_data) => println!("Decrypted Data: {:?}", String::from_utf8_lossy(&decrypted_data)),
                Err(e) => println!("Decryption error: {}", e),
            }
        }
        Err(e) => println!("Encryption error: {}", e),
    }
}
fn generate_and_display_rsa_keys() {
    let rsa = RsaCryptoKeys::new(2048).unwrap();
    let public_key = rsa.get_public_key();

    let n_hex = hex::encode(public_key.n().to_bytes_be());
    let e_hex = hex::encode(public_key.e().to_bytes_be());

    let public_key_data = PublicKeyData {
        modulus: n_hex.clone(),
        exponent: e_hex.clone(),
        date: Local::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };

    println!("Public Key:");
    println!("Modulus (n): {}", n_hex.clone());
    println!("Exponent (e): {}", e_hex.clone());

    let file_path = "public_key.json";
    JsonHandler::save(file_path, &public_key_data).expect("Failed to save public key");

}

