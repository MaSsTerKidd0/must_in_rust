use std::slice::Chunks;
use crate::AesCipher;
use aes::Aes256;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
type Aes256Ctr = Ctr128BE<Aes256>;
pub struct AesCtr;

impl AesCipher<[u8; 16]> for AesCtr {
    fn encrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 16]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 256 bits (32 bytes) long".to_string());
        }

        let key_array: [u8; 32] = match key.try_into() {
            Ok(arr) => arr,
            Err(_) => return Err("Failed to convert key into a valid format".to_string()),
        };

        let mut buffer = data.to_vec();
        let mut cipher = Aes256Ctr::new(&key_array.into(), nonce.into());
        cipher.apply_keystream(&mut buffer);
        return Ok(buffer);
    }

    fn decrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 16]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 256 bits (32 bytes) long".to_string());
        }
        Self::encrypt(data, key, nonce)
    }

}
