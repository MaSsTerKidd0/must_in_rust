use aes_gcm_siv::Nonce;

pub trait AesCipher<IvOrNonce> {
    fn encrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &IvOrNonce) -> Result<Vec<u8>, String>;
    fn decrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &IvOrNonce) -> Result<Vec<u8>, String>;
}
