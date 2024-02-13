
#[derive(Clone)]
pub enum AesType {
    AesGcmSiv,
    AesCtr,
    AesCbc,
}

impl AesType {
    pub fn from_str(s: &str) -> Option<AesType> {
        match s {
            "AesGcmSiv" => Some(AesType::AesGcmSiv),
            "AesCtr" => Some(AesType::AesCtr),
            "AesCbc" => Some(AesType::AesCbc),
            _ => None,
        }
    }
}

pub trait AesCipher<Nonce> {
    fn encrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &Nonce) -> Result<Vec<u8>, String>;
    fn decrypt(data: &[u8], key: Vec<u8>, iv_or_nonce: &Nonce) -> Result<Vec<u8>, String>;
}


