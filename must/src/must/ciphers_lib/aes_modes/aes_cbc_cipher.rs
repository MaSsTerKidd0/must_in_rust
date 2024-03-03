use crate::must::ciphers_lib::aes_cipher_trait::AesCipher;
use aes::cipher::{generic_array::GenericArray};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Represents AES-256 in Cipher Block Chaining (CBC) mode with PKCS7 padding.
/// AES-256-CBC provides confidentiality by linking each block's encryption to the previous block,
/// and PKCS7 padding ensures each block has the correct size. It does not provide integrity or authenticity.
pub struct AesCbc;

impl AesCipher<[u8; 16]> for AesCbc {

    /// Encrypts data using AES-256 in CBC mode with PKCS7 padding.
    /// # Arguments
    /// * `data` - A slice of data to be encrypted.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `iv` - A 128-bit (16 bytes) Initialization Vector (IV).
    /// # Returns
    /// `Result<Vec<u8>, String>` - Encrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Returns an error if encryption fails.
    fn encrypt(data: &[u8], key: Vec<u8>, iv: &[u8; 16]) -> Result<Vec<u8>, String> {
        let key = GenericArray::from_slice(&key);
        let iv = GenericArray::from_slice(iv);
        return Ok(Aes256CbcEnc::new(&(*key).into(), &(*iv).into()).encrypt_padded_vec_mut::<Pkcs7>(data));
    }

    /// Decrypts data encrypted with AES-256 in CBC mode with PKCS7 padding.
    /// # Arguments
    /// * `data` - A slice of encrypted data.
    /// * `key` - A vector containing the 256-bit (32 bytes) key.
    /// * `iv` - A 128-bit (16 bytes) Initialization Vector (IV).
    /// # Returns
    /// `Result<Vec<u8>, String>` - Decrypted data as a vector on success, or an error string on failure.
    /// # Errors
    /// Decrypting may panic if the padding is incorrect.
    fn decrypt(data: &[u8], key: Vec<u8>, iv: &[u8; 16]) -> Result<Vec<u8>, String> {
        let key = GenericArray::from_slice(&key);
        let iv = GenericArray::from_slice(iv);
        return Ok(Aes256CbcDec::new(&(*key).into(), &(*iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data)
            .unwrap());
    }
}
