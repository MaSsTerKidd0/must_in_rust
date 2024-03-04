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
            self.unsecure_net.parse::<Ipv4Addr>().is_ok()&&
            self.is_subnet_mask_valid(&self.secure_net_subnet_mask) &&
            self.is_subnet_mask_valid(&self.unsecure_net_subnet_mask)
    }

    fn is_subnet_mask_valid(&self, subnet_mask: &Ipv4Addr) -> bool {
        let mask = u32::from(*subnet_mask); // Convert Ipv4Addr to a u32.
        let mask = mask.to_be(); // Ensure it's in big-endian to match network byte order.

        // A valid subnet mask has all 1s on the left, then all 0s.
        // To check this, find the first 0 and then ensure all bits following it are 0.
        let first_zero = !mask; // Flip bits; 0s become 1s and 1s become 0s.
        let subsequent_one = first_zero + 1; // Add 1; if mask was valid, we should get a power of 2.
        let is_valid = mask & subsequent_one == 0; // Perform AND; result should be 0 for a valid mask.

        return is_valid && mask != 0; // Ensure mask is not 0 and passes the validity check.
    }
}
