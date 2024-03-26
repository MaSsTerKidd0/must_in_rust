use serde::{Serialize, Deserialize};
use bincode;

/// NetworkICD struct represents a network communication data structure with various fields:
/// aes_key: A vector of bytes representing the AES encryption key used for securing the data.
/// network: A boolean indicating the type of network. `true` represents a secure network, while `false` represents an unsecure network.
/// packet_number: A 16-bit unsigned integer indicating the packet number. This is used to order packets in a sequence.
/// seq_number: A 16-bit unsigned integer representing the sequence number, which can be used for identifying the position of this packet in a series of packets.
/// data: A vector of bytes containing the actual data being transmitted. This field holds the payload of the packet.
pub const SECURE_NET:bool = true;
pub const UNSECURE_NET:bool = true;

#[derive(Serialize, Deserialize, Debug, PartialEq,Clone)]
pub struct NetworkICD {
    pub(crate) aes_key: Vec<u8>,
    pub(crate) iv_or_nonce: Vec<u8>,
    pub(crate) network: bool,
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