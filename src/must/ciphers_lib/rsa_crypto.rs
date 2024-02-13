use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, sha2::Sha256};
use rand::rngs::OsRng;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use pem::parse;
use std::fs;
use num_enum::{IntoPrimitive};
use rsa::traits::PublicKeyParts;


const PRIVATE_KEY_PATH: &str = "private_key.pem";
const PUBLIC_KEY_PATH: &str = "public_key.pem";


#[derive(IntoPrimitive)]
#[repr(usize)]
pub enum RsaKeySize {
    Bits1024 = 1024,
    Bits2048 = 2048,
    Bits3072 = 3072,
    Bits4096 = 4096,
}



pub struct RsaCryptoKeys {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaCryptoKeys {
    pub(crate) fn generate(bits: RsaKeySize) -> Result<(), Box<dyn Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits.into())?;
        let public_key = RsaPublicKey::from(&private_key);
        let keys = RsaCryptoKeys { private_key, public_key };
        keys.save_keys()?;

        return Ok(());
    }
    pub(crate) fn load() -> Result<Self, Box<dyn Error>> {
        let private_key = read_rsa_private_key_from_pem()?;
        let public_key = read_rsa_public_key_from_pem()?;

        Ok(RsaCryptoKeys { private_key, public_key })
    }
    pub fn get_public_key(&self) -> &RsaPublicKey {
        return &self.public_key;
    }
    pub fn get_private_key(&self) -> &RsaPrivateKey {
        return &self.private_key;
    }
    pub fn save_keys(&self) -> Result<(), Box<dyn Error>> {
        // Save the private key in PEM format
        let private_key_pem = self.private_key.to_pkcs8_pem(Default::default())?;
        let mut private_file = File::create(PRIVATE_KEY_PATH)?;
        private_file.write_all(private_key_pem.as_bytes())?;

        // Save the public key in PEM format
        let public_key_pem = self.public_key.to_pkcs1_pem(Default::default())?;
        let mut public_file = File::create(PUBLIC_KEY_PATH)?;
        public_file.write_all(public_key_pem.as_bytes())?;

        return Ok(());
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();
        self.public_key.encrypt(&mut rng, padding, data)
            .map_err(|e| e.into())
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let padding = Oaep::new::<Sha256>();

        return self.private_key.decrypt(padding, ciphertext)
            .map_err(|e| e.into());
    }

    pub(crate) fn get_public_key_pem() -> std::io::Result<String> {
        return fs::read_to_string(PUBLIC_KEY_PATH);
    }
}

fn read_rsa_public_key_from_pem() -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let pem_contents = fs::read_to_string(PUBLIC_KEY_PATH)?;
    let public_key = RsaPublicKey::from_pkcs1_pem(&*pem_contents.clone())?;

    return Ok(public_key);
}
fn read_rsa_private_key_from_pem() -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
    let pem_contents = fs::read_to_string(PRIVATE_KEY_PATH)?;
    let public_key = RsaPrivateKey::from_pkcs8_pem(&*pem_contents.clone())?;

    return Ok(public_key);
}