use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, sha2::Sha256};
use rand::rngs::OsRng;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;


pub struct RsaCryptoKeys {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaCryptoKeys {
    pub fn new(bits: usize) -> Result<Self, Box<dyn Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);
        return Ok(RsaCryptoKeys { private_key, public_key });
    }

    pub fn get_public_key(&self) -> &RsaPublicKey {
        return &self.public_key;
    }
    pub fn save_keys(&self) -> Result<(), Box<dyn Error>> {
        // Save the private key in PEM format
        let private_key_pem = self.private_key.to_pkcs8_pem(Default::default())?;
        let mut private_file = File::create("private_key.pem")?;
        private_file.write_all(private_key_pem.as_bytes())?;

        // Save the public key in PEM format
        // Note: This assumes the `rsa` crate and your key types support converting to PKCS#1 PEM format.
        // If your specific version or crate does not support this directly, you may need to adapt this code.
        let public_key_pem = self.public_key.to_pkcs1_pem(Default::default())?;
        let mut public_file = File::create("public_key.pem")?;
        public_file.write_all(public_key_pem.as_bytes())?;

        Ok(())
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut rng = OsRng;
        let padding = Oaep::new::<Sha256>();
        self.public_key.encrypt(&mut rng, padding, data)
            .map_err(|e| e.into())
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let padding = Oaep::new::<Sha256>();
        self.private_key.decrypt(padding, ciphertext)
            .map_err(|e| e.into())
    }
}