use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use aes::cipher::{generic_array::GenericArray};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
pub struct AesCbc;

impl AesCipher<[u8; 16]> for AesCbc {
    fn encrypt(data: &[u8], key: Vec<u8>, iv: &[u8; 16]) -> Result<Vec<u8>, String> {
        let key = GenericArray::from_slice(&key);
        let iv = GenericArray::from_slice(iv);
        return Ok(Aes256CbcEnc::new(&(*key).into(), &(*iv).into()).encrypt_padded_vec_mut::<Pkcs7>(data));
    }

    fn decrypt(data: &[u8], key: Vec<u8>, iv: &[u8; 16]) -> Result<Vec<u8>, String> {
        let key = GenericArray::from_slice(&key);
        let iv = GenericArray::from_slice(iv);
        return Ok(Aes256CbcDec::new(&(*key).into(), &(*iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data)
            .unwrap());
    }
}
