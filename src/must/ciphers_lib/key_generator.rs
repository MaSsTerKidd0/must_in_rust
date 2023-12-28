use rand::{Rng, rngs::OsRng};

pub enum KeySize {
    Bits128,
    Bits192,
    Bits256,
    Bits512,
}

impl KeySize {
    fn byte_size(&self) -> usize {
        match self {
            KeySize::Bits128 => 16,
            KeySize::Bits192 => 24,
            KeySize::Bits256 => 32,
            KeySize::Bits512 => 64,
        }
    }
}

pub struct  KeyGenerator;

impl KeyGenerator {
    pub fn generate_key(size: KeySize) -> Vec<u8> {
        let byte_size = size.byte_size();
        let mut key = [0u8; 64];
        OsRng.fill(&mut key[..byte_size]);
        return key[..byte_size].to_vec()
    }
}