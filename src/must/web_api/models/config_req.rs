use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ConfigReq {
    pub config_name: String,
    pub ip_addr: String,
    pub aes_type: String,
}
