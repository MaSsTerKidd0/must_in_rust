use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use aes_gcm_siv::{Aes256GcmSiv, Nonce, aead::{Aead, KeyInit}};
use std::convert::TryInto;

/// Represents AES-256-GCM-SIV encryption mode.
/// AES-256-GCM-SIV provides authenticated encryption using a 256-bit key.
/// It combines Galois/Counter Mode (GCM) with Synthetic Initialization Vector (SIV),
/// ensuring both confidentiality and integrity of data. This mode is resistant to nonce reuse.
pub struct AesGcmSiv;

impl AesCipher<[u8; 12]> for AesGcmSiv {

    /// Encrypts data using AES-256-GCM-SIV mode.
    /// # Arguments
    /// * `data` - A slice of data to be encrypted.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `nonce` - A reference to a 12-byte array used as a nonce.
    /// # Returns
    /// `Result<Vec<u8>, String>` - Encrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Returns an error if the key is not 32 bytes, or if encryption fails.
    fn encrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key g_must be 32 bytes for Aes256GcmSiv".to_string());
        }

        let nonce = Nonce::from_slice(nonce); // Converts the 12-byte array into a Nonce
        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| e.to_string())?;
        cipher.encrypt(nonce, data).map_err(|e| e.to_string())
    }

    /// Decrypts data encrypted with AES-256-GCM-SIV mode.
    /// # Arguments
    /// * `data` - A slice of encrypted data.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `nonce` - A reference to a 12-byte array used as a nonce.
    /// # Returns
    /// `Result<Vec<u8>, String>` - Decrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Returns an error if the key is not 32 bytes, or if decryption fails.
    fn decrypt(data: &[u8], key: Vec<u8>, nonce: &[u8; 12]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key g_must be 32 bytes for Aes256GcmSiv".to_string());
        }

        let nonce = Nonce::from_slice(nonce); // Converts the 12-byte array into a Nonce
        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| e.to_string())?;
        cipher.decrypt(nonce, data).map_err(|e| e.to_string())
    }
}
