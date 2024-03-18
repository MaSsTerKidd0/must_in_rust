use crate::must::network::remote_networks::NetworkConfig;
use crate::must::web_api::models::config_record::ConfigRecord;

#[repr(u8)]
pub enum Protocol {
    UDP = 17,
    TCP = 6,
}

#[derive(Debug, PartialEq)]
pub enum NetworkState {
    UnsecureNetwork,
    SecureNetwork,
    UnsecureNetworkRemote,
    SecureNetworkRemote,
}

pub struct Filter;

impl Filter {
    pub fn identify_network_state_for_packet(packet_data: &[u8], config_record: &ConfigRecord, remote_networks: &NetworkConfig, protocol: Protocol) -> Option<NetworkState> {
        if packet_data.len() < 34 {
            return None;
        }

        if packet_data[23] != protocol as u8 && packet_data[23] != 50 {
            return None;
        }

        let dst_ip = format!("{}.{}.{}.{}", packet_data[30], packet_data[31], packet_data[32], packet_data[33]);

        Filter::identify_network_state(&dst_ip, config_record, remote_networks)
    }

    fn identify_network_state(dst_ip: &str, config_record: &ConfigRecord, remote_networks: &NetworkConfig) -> Option<NetworkState> {
        if dst_ip == config_record.secure_net {
            Some(NetworkState::SecureNetwork)
        } else if dst_ip == config_record.unsecure_net {
            Some(NetworkState::UnsecureNetwork)
        } else if dst_ip == remote_networks.secure_network.ip {
            Some(NetworkState::SecureNetworkRemote)
        } else if dst_ip == remote_networks.unsecure_network.ip {
            Some(NetworkState::UnsecureNetworkRemote)
        } else {
            None
        }
    }
}