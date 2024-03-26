
use crate::must::ciphers_lib::AesCipher;
use crate::must::ciphers_lib::aes_modes::aes_gcm_siv_cipher::AesGcmSiv;
use crate::must::ciphers_lib::aes_modes::aes_cbc_cipher::AesCbc;
use crate::must::ciphers_lib::aes_modes::aes_ctr_cipher::AesCtr;
use crate::must::ciphers_lib::AesType;
use rand::{Rng, rngs::OsRng};

#[derive(Clone)]
pub struct Encryptor {
    aes_type: AesType,
}

impl Encryptor {
    pub fn new(aes_type: AesType) -> Result<Self, String> {
        Ok(Encryptor { aes_type })
    }
    pub fn encrypt_data(&self, data: &[u8], key: Vec<u8>, iv_or_nonce:&[u8]) -> Result<Vec<u8>, String> {
        match self.aes_type {
            AesType::AesGcmSiv => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesGcmSiv::encrypt(data, key, &nonce)
            },
            AesType::AesCtr => {
                let nonce = iv_or_nonce.try_into().map_err(|_| "Nonce conversion failed")?;
                AesCtr::encrypt(data, key, &nonce)
            },
            AesType::AesCbc => {
                let iv = iv_or_nonce.try_into().map_err(|_| "IV conversion failed")?;
                AesCbc::encrypt(data, key, &iv)
            },
        }
    }

    pub fn decrypt_data(&self, encrypted_data: &[u8], key: Vec<u8>, nonce_or_iv: &[u8]) -> Result<Vec<u8>, String> {
        match self.aes_type {
            AesType::AesGcmSiv => {
                let nonce = nonce_or_iv.try_into().map_err(|_| "Nonce conversion failed")?;
                AesGcmSiv::decrypt(encrypted_data, key, &nonce)
            },
            AesType::AesCtr => {
                let nonce = nonce_or_iv.try_into().map_err(|_| "Nonce conversion failed")?;
                AesCtr::decrypt(encrypted_data, key, &nonce)
            },
            AesType::AesCbc => {
                let iv = nonce_or_iv.try_into().map_err(|_| "IV conversion failed")?;
                AesCbc::decrypt(encrypted_data, key, &iv)
            },
        }
    }


    // Function to generate IV or Nonce
    pub(crate) fn generate_iv_or_nonce(aes_type: Option<AesType>) -> Result<Vec<u8>, String> {
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