use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct ConfigReq {
    pub config_name: String,
    pub ip_addr: String,
    pub aes_type: String,
}
