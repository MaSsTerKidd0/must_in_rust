use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ConfigRecord {
    pub config_name: String,
    pub secure_net: String,
    pub secure_net_port: u16,
    pub secure_net_subnet_mask: Ipv4Addr,
    pub secure_net_bandwidth: u32,
    pub unsecure_net: String,
    pub unsecure_net_port: u16,
    pub unsecure_net_subnet_mask: Ipv4Addr,
    pub unsecure_net_bandwidth: u32,
    pub aes_type: String,
}

impl ConfigRecord {
    pub fn is_valid(&self) -> bool {
        !self.config_name.trim().is_empty() &&
            !self.secure_net.trim().is_empty() &&
            self.secure_net_port > 0 &&
            !self.unsecure_net.trim().is_empty() &&
            self.unsecure_net_port > 0 &&
            self.secure_net_bandwidth > 0 &&
            self.unsecure_net_bandwidth > 0 &&
            !self.aes_type.trim().is_empty() &&
            self.secure_net.parse::<Ipv4Addr>().is_ok() &&
            self.unsecure_net.parse::<Ipv4Addr>().is_ok()
    }
}
