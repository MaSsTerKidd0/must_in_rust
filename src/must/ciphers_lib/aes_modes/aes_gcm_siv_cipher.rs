use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use aes_gcm_siv::{Aes256GcmSiv, Nonce, aead::{Aead, KeyInit}};

pub struct AesGcmSivCipher;

impl AesCipher<Nonce> for AesGcmSivCipher {
    fn encrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &Nonce) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes for Aes256GcmSiv".to_string());
        }

        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| e.to_string())?;
        return cipher.encrypt(iv_or_nonce, data).map_err(|e| e.to_string());
    }

    fn decrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &Nonce) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes for Aes256GcmSiv".to_string());
        }

        let cipher = Aes256GcmSiv::new_from_slice(&key).map_err(|e| e.to_string())?;
        return cipher.decrypt(iv_or_nonce, data).map_err(|e| e.to_string());
    }
}
