
use crate::must::ciphers_lib::AesCipher;
use aes::Aes256;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
type Aes256Ctr = Ctr128BE<Aes256>;

/// Represents AES-256 in Counter (CTR) mode.
/// AES-256-CTR encrypts each block with a counter and a key, offering confidentiality without authentication.
/// The counter is combined with a nonce and incremented for each block.
pub struct AesCtr;

impl AesCipher<[u8; 16]> for AesCtr {

    /// Encrypts data using AES-256 in CTR mode.
    /// # Arguments
    /// * `data` - A slice of data to be encrypted.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `nonce` - A 128-bit (16 bytes) nonce.
    /// # Returns
    /// `Result<Vec<u8>, String>` - Encrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Returns an error if the key is not 32 bytes, or if encryption fails.
    fn encrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 16]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key g_must be 256 bits (32 bytes) long".to_string());
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

    /// Decrypts data encrypted with AES-256 in CTR mode.
    /// # Arguments
    /// * `data` - A slice of encrypted data.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `nonce` - A 128-bit (16 bytes) nonce.
    /// # Returns
    /// `Result<Vec<u8>, String>` - Decrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Returns an error if the key is not 32 bytes, or if decryption fails.
    fn decrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 16]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key g_must be 256 bits (32 bytes) long".to_string());
        }
        Self::encrypt(data, key, nonce)
    }

}
