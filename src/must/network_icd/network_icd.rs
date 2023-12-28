use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkICD {
    pub(crate) packet_number: u16,
    pub(crate) seq_number: u16,
    pub(crate) data: Vec<u8>,
}
