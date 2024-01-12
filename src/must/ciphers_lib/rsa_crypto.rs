use rsa::{ RsaPublicKey, RsaPrivateKey,Oaep};
use rand::rngs::OsRng;
use std::error::Error;
use sha2::Sha256;

pub struct RsaCryptoKeys {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaCryptoKeys {
    // Function to create new instance with generated keys
    pub fn new(bits: usize) -> Result<Self, Box<dyn Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(RsaCryptoKeys { private_key, public_key })
    }

    pub fn get_public_key(&self) -> &RsaPublicKey {
        &self.public_key
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