
#[repr(u8)]
pub enum Protocol {
    UDP = 17,
    TCP = 6,
}

pub struct Filter;

impl Filter {
    pub fn is_protocol_packet_for_ip(packet_data: &[u8], target_ip: &str, protocol: Protocol) -> bool {
        // Ethernet frame is 14 bytes. Total length for Ethernet + IP header without options is 34 bytes.
        if packet_data.len() < 34 {
            return false;
        }

        // Check the protocol field in the IP header
        // Ethernet frame is 14 bytes, IP header starts at 15th byte, protocol is at 10th byte of IP header
        if packet_data[23] != protocol as u8 {
            return false;
        }

        // Extract destination IP address
        // Destination IP starts at 16th byte of IP header, after 14 bytes of Ethernet frame
        let dst_ip = format!("{}.{}.{}.{}",
                             packet_data[30],
                             packet_data[31],
                             packet_data[32],
                             packet_data[33]);

        dst_ip == target_ip
    }
}