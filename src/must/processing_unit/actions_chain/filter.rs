
#[repr(u8)]
pub enum Protocol {
    UDP = 17,
    TCP = 6,
}

pub struct Filter;

impl Filter {
    pub fn is_protocol_packet_for_ip(packet_data: &[u8], target_ip: &str, protocol: Protocol) -> bool {
        if packet_data.len() < 20 {
            return false;
        }
        if packet_data[9] !=  protocol as u8 {
            return false;
        }
        let dst_ip = format!("{}.{}.{}.{}",
                             packet_data[16],
                             packet_data[17],
                             packet_data[18],
                             packet_data[19]);
        dst_ip == target_ip
    }
}