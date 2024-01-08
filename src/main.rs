#![allow(warnings)]
mod must;
use crate::must::processing_unit::actions_chain::fragment::{Fragment};

use std::collections::VecDeque;
use std::io;
use pcap::Device;
use crate::must::ciphers_lib::key_generator::{KeyGenerator, KeySize};
use crate::must::json_handler::JsonHandler;
use crate::must::network_icd::network_icd::NetworkICD;
use aes_gcm_siv::{Nonce, aead::{Aead}};
use rand::{rngs::OsRng, RngCore};
use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use crate::must::ciphers_lib::aes_modes::aes_ctr_cipher::AesCtr;

fn main() {
    let data = b"Hello, world!";
    let key = KeyGenerator::generate_key(KeySize::Bits256);
    println!("key: {:?}", key);

    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);

    // let encrypted_data = AesCtr::encrypt(data, key.clone(), &nonce_bytes);
    // println!("encrypted data: {:?}", encrypted_data.unwrap());
    //
    // let decrypted_data = AesCtr::decrypt(data, key.clone(), &nonce_bytes);
    // println!("decrypted data: {:?}", String::from_utf8_lossy(&decrypted_data.unwrap()))
    //let nonce = Nonce::from_slice(&nonce_bytes);

    match AesCtr::encrypt(data, key.clone(), &nonce_bytes) {
        Ok((encrypted_data)) => {
            println!("Encrypted Data: {:?}", encrypted_data);
            match AesCtr::decrypt(&encrypted_data, key, &nonce_bytes) {
                Ok(decrypted_data) => println!("Decrypted Data: {:?}", String::from _utf8_lossy(&decrypted_data)),
                Err(e) => println!("Decryption error: {}", e),
            }
        }
        Err(e) => println!("Encryption error: {}", e),
    }


    //let fragmented_packets = check_fragmentation();
    //check_assemble_packets(fragmented_packets);
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