
use crate::AesCipher;
use crate::must::ciphers_lib::aes_modes::aes_gcm_siv_cipher::AesGcmSiv;
use crate::must::ciphers_lib::aes_modes::aes_cbc_cipher::AesCbc;
use crate::must::ciphers_lib::aes_modes::aes_ctr_cipher::AesCtr;
use crate::must::ciphers_lib::AesType;
use rand::{Rng, rngs::OsRng};



pub struct Encryptor;

impl Encryptor {
    pub fn encrypt_data(data: &[u8], aes_type: Option<AesType>, key: Vec<u8>) -> Result<Vec<u8>, String> {
        let iv_or_nonce = Self::generate_iv_or_nonce(&aes_type)?;
        match aes_type {
            Some(AesType::AesGcmSiv) => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesGcmSiv::encrypt(data, key, &nonce)
            },
            Some(AesType::AesCtr) => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesCtr::encrypt(data, key, &nonce)
            },
            Some(AesType::AesCbc) => {
                let iv = iv_or_nonce.try_into().map_err(|_| "IV conversion failed")?;
                AesCbc::encrypt(data, key, &iv)
            },
            None => Err("AES type not specified".to_string()),
        }
    }

    pub fn decrypt_data(encrypted_data: &[u8], aes_type: AesType, key: Vec<u8>, iv_or_nonce: Vec<u8>) -> Result<Vec<u8>, String> {
        match aes_type {
            AesType::AesGcmSiv => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesGcmSiv::decrypt(encrypted_data, key, &nonce)
            },
            AesType::AesCtr => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesCtr::decrypt(encrypted_data, key, &nonce)
            },
            AesType::AesCbc => {
                let iv = iv_or_nonce.try_into().map_err(|_| "IV conversion failed")?;
                AesCbc::decrypt(encrypted_data, key, &iv)
            },
        }
    }

    // Function to generate IV or Nonce
    fn generate_iv_or_nonce(aes_type: &Option<AesType>) -> Result<Vec<u8>, String> {
        let size = match aes_type {
            Some(AesType::AesGcmSiv) => 12, // Size for GCM-SIV nonce
            Some(AesType::AesCtr) => 16,    // Size for CTR nonce
            Some(AesType::AesCbc) => 16,    // Size for CBC IV
            None => 0,

        };

        let mut rng = rand::thread_rng();
        Ok((0..size).map(|_| rng.gen()).collect())
    }
}