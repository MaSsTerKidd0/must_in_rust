use serde::{Serialize, Deserialize};
use bincode;

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkICD {
    pub(crate) aes_key: Vec<u8>,
    pub(crate) packet_number: u16,
    pub(crate) seq_number: u16,
    pub(crate) data: Vec<u8>,
}

impl NetworkICD {
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::serialize(self).map_err(Into::into)
    }
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}