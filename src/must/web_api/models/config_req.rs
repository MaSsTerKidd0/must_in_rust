use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct ConfigRecord {
    pub config_name: String,
    pub secure_net: String,
    pub unsecure_net: String,
    pub aes_type: String,
}
impl ConfigRecord {
    pub fn is_valid(&self) -> bool {
        !self.config_name.trim().is_empty() &&
            !self.secure_net.trim().is_empty() &&
            !self.unsecure_net.trim().is_empty() &&
            !self.aes_type.trim().is_empty() &&
            self.secure_net.parse::<std::net::Ipv4Addr>().is_ok() &&
            self.unsecure_net.parse::<std::net::Ipv4Addr>().is_ok()
    }
}
