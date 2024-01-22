#![allow(warnings)]
mod must;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::io;
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
use crate::must::protocols::protocol::Protocol;
use crate::must::protocols::tcp_protocol::TcpProtocol;
use crate::must::web_api::handlers;
use crate::must::web_api::handlers::config_handler::find_config_by_name;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    env_logger::init();

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                true
            })
            .allowed_methods(vec!["GET", "POST", "OPTIONS"]) // Specify the allowed HTTP methods
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT, header::CONTENT_TYPE]) // Specify the allowed HTTP headers
            .max_age(3600);
        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .configure(handlers::config)
            .service(handlers::login)
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}


async fn handle_transmission(configuration_name: &str) {
    let config = find_config_by_name("configurations.json", configuration_name).unwrap().unwrap();

    // Parse the secure_net and unsecure_net into SocketAddr
    let secure_addr: SocketAddr = config.secure_net.parse().expect("Invalid secure net address");
    let unsecure_addr: SocketAddr = config.unsecure_net.parse().expect("Invalid unsecure net address");

    // Create TcpProtocol instance
    let secure_tcp_socket = TcpProtocol::new(secure_addr);
    let unsecure_tcp_socket = TcpProtocol::new(unsecure_addr);

    let (_pre_process_data, _processing_packets_data) = std::sync::mpsc::channel::<Vec<u8>>();
    let (_after_process_data, _processing_packets_data) = std::sync::mpsc::channel::<Vec<u8>>();


}

















fn show_devices(devices: Vec<Device>) {
    let mut device_no = 1;
    for device in devices {

        println!("{}.{}", device_no, device.desc.unwrap());
        device_no += 1;
    }
}
fn device_picker() -> Device {
    let  devices = Device::list().unwrap();
    let mut choice: usize = 0;
    while choice < 1 || choice > devices.len(){
        println!("Select a device");
        show_devices(devices.clone());
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
    let n = public_key.n();
    let e = public_key.e();

    let n_hex = hex::encode(n.to_bytes_be());
    let e_hex = hex::encode(e.to_bytes_be());

    println!("Public Key:");
    println!("Modulus (n): {}", n_hex);
    println!("Exponent (e): {}", e_hex);

    let data = b"Hello, world!";

    let res_enc = rsa.encrypt(data).expect("TODO: panic message");
    println!("Encrypted RSA: {:?}", res_enc);
    let res_dec = rsa.decrypt(res_enc.as_slice()).expect("TOD");
    println!("Decrypted RSA: {:?}", String::from_utf8_lossy(res_dec.as_slice()));
}
// let (key, nonce_bytes) = generate_key_and_nonce();
// perform_aes_encryption_and_decryption(&key, &nonce_bytes);
// generate_and_display_rsa_keys();

//let device = device_picker();

//let fragmented_packets = check_fragmentation();
//check_assemble_packets(fragmented_packets);
//}