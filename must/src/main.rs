#![allow(unused)]

mod must;

use std::string::String;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::{fs, io, thread};
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use pcap::Device;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::json_handler::JsonHandler;
use crate::must::network_icd::network_icd::{NetworkICD, SECURE_NET, UNSECURE_NET};
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
use mongodb::{Client, bson::{doc, DateTime}};
use crate::must::log_assistant::LogAssistant;
use crate::must::log_handler::LOG_HANDLER;
use crate::must::mongo_db_handler::get_mongo_handler;
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


const MUST_IP: &str = "127.0.0.1";
const MUST_PORT: u16 = 42069;

fn main(){
    let configuration_name = "Save18";
    let config = find_config_by_name("configurations.json", configuration_name).unwrap().unwrap();
    //RsaCryptoKeys::generate(RsaKeySize::Bits2048);

    let mut secure_net = String::from(config.secure_net.clone());
    let mut  unsecure_net = String::from(config.unsecure_net.clone());

    let secure_net_port:u16 = config.secure_net_port;
    let unsecure_net_port:u16 = config.unsecure_net_port;
    println!("Secure-{}:{}, Unsecure-{}:{}",secure_net, secure_net_port, unsecure_net, unsecure_net_port);

    let (pre_process_sender, pre_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (post_process_sender, post_process_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
    let (incoming_data_rx, incoming_data_tx) = std::sync::mpsc::channel::<Vec<u8>>();
    let unsecure_device = device_picker();
    println!("Selected device: {}", unsecure_device.desc.clone().unwrap());
    let sender_clone = pre_process_sender.clone(); // Clone the sender for the first thread
    let receive_unsecure = thread::spawn(move  || ReceiveUnit::receive(unsecure_device, sender_clone));

    let secure_device = device_picker();
    println!("Selected device: {}", secure_device.desc.clone().unwrap());
    let receive_secure = thread::spawn(move|| ReceiveUnit::receive(secure_device, pre_process_sender));
    //let rsa = RsaCryptoKeys::load().unwrap();
    //post_process_sender.send(rsa.get_public_key().to_pkcs1_der().unwrap().as_ref().to_vec());

    let send_unit = SendUnit::new_udp(MUST_IP.parse().unwrap(), MUST_PORT);
    let send_unit = Arc::new(Mutex::new(send_unit)); // Wrap send_unit with Arc<Mutex<>> for shared ownership and thread safety

    //rsa_exchange_public_keys(&a.socket);
    // Clone the Arc to share send_unit between threads
    let send_unit_for_send_thread = send_unit.clone();
    let secure_send_thread = thread::spawn(move || {
        let send_unit = send_unit_for_send_thread.lock().unwrap(); // Lock to access the inner value
        send_unit.send(post_process_receiver, SECURE_NET, secure_net.parse().unwrap(), secure_net_port);
    });

    // Another clone for the must_receive_thread
    let send_unit_for_receive_thread = send_unit.clone();
    let must_receive_thread = thread::spawn(move || {
        let send_unit = send_unit_for_receive_thread.lock().unwrap(); // Lock to access the inner value
        send_unit.receive(incoming_data_rx);
    });

    let process_thread = thread::spawn(move|| ProcessorUnit::process(pre_process_receiver, post_process_sender, config.clone()));

    must_receive_thread.join().unwrap();
    receive_unsecure.join().unwrap();
    receive_secure.join().unwrap();
    process_thread.join().unwrap();
    secure_send_thread.join().unwrap();
}

fn check_network_icd() -> Result<(), Box<dyn Error>>{
    // Create a sample NetworkICD instance
    let sample_icd = NetworkICD {
        aes_key: vec![1, 2, 3, 4, 5],
        network: true,
        packet_number: 123,
        seq_number: 456,
        data: vec![9, 8, 7, 6, 5],
    };

    // Serialize the sample_icd to bytes
    let serialized_bytes = sample_icd.to_bytes()?;

    // Deserialize the bytes back into a NetworkICD instance
    let deserialized_icd = NetworkICD::from_bytes(&serialized_bytes)?;

    // Print the original and deserialized NetworkICD instances to verify they are the same
    println!("Original ICD: {:?}", sample_icd);
    println!("Deserialized ICD: {:?}", deserialized_icd);

    // Verify that the original and deserialized instances are the same
    assert_eq!(sample_icd, deserialized_icd);

    Ok(())
}

fn rsa_exchange_public_keys(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let binding = RsaCryptoKeys::get_public_key_pem()?;
    let rsa_pub_key = binding.as_bytes();
    // let ip_address = config_record.secure_net + ":" + &config_record.secure_net_port.to_string();
    //let socket = UdpSocket::bind(ip_address.clone())?;
    println!("Listening on {:?}", socket.local_addr().unwrap());

    let mut buf = [0u8; 1024];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        println!("Received data from {}", src);

        match std::str::from_utf8(&buf[..amt]) {
            Ok(v) => {
                println!("Received: {}", v);

                if v == "REQUEST_PUBLIC_KEY" {
                    match socket.send_to(rsa_pub_key, &src) {
                        Ok(_) => println!("RSA public key sent successfully."),
                        Err(e) => eprintln!("Failed to send RSA public key: {}", e),
                    }
                } else if v == "KEY_RECEIVED_ACKNOWLEDGMENT" {
                    println!("Acknowledgment received. Key exchange successful.");
                    break;
                } else if v.starts_with("SENDING_KEY:") {
                    println!("Received key from {}: {}", src, &v["SENDING_KEY:".len()..]);
                    let ack_msg = "KEY_RECEIVED_ACKNOWLEDGMENT".as_bytes();
                    match socket.send_to(ack_msg, &src) {
                        Ok(_) => println!("Acknowledgment sent successfully."),
                        Err(e) => eprintln!("Failed to send acknowledgment: {}", e),
                    }
                }
            }
            Err(e) => println!("Invalid UTF-8 sequence: {}", e),
        }
    }

    Ok(())
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
        print!("Please choose device:");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        choice = input.trim().parse::<usize>().unwrap();
    }
    return devices.get(choice - 1).unwrap().clone();
}

fn check_assemble_packets(packets: VecDeque<NetworkICD>) {
    let assemble = Fragment {
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

// #[tokio::main]
// async fn main() {
//     // URI and database name should be specified here
//     let uri = "mongodb://localhost:27017/";
//     let db_name = "your_db_name";
//
//     // Attempt to get the MongoDBHandler
//     let mongo_handler = get_mongo_handler().await.expect("Failed to initialize MongoDB handler.");
//
//     // Create a new user
//     let new_user = UserRecord {
//         id: None, // MongoDB will auto-generate an ObjectId
//         username: "johndoe".to_string(),
//         password: "hashed_password".to_string(), // This should be a hashed password
//         roles: vec!["user".to_string()],
//         created_at: Utc::now().format("%Y-%m-%d").to_string(),
//     };
//
//
//     mongo_handler.insert_user(new_user).await.expect("Failed to insert new user");
//
//     println!("New user inserted successfully.");
// }