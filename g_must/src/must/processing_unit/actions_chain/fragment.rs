use std::sync::atomic::{AtomicU16, Ordering};
use crate::must::network_icd::network_icd::NetworkICD;
use std::collections::VecDeque;
use serde::{Deserialize, Serialize};

const HEADER_SIZE: u16 = 4;
static PACKET_COUNTER: AtomicU16 = AtomicU16::new(1);

#[derive(Serialize, Deserialize)]
pub struct Fragment{
    pub(crate) first_net_max_bandwidth: u16,
    pub(crate) second_net_max_bandwidth: u16,
}


impl Fragment{

    pub fn fragment(&self, data: &[u8], new_aes_key: Vec<u8>) -> VecDeque<NetworkICD> {
        let mut new_packets = VecDeque::new();
        let data_len= self.second_net_max_bandwidth - HEADER_SIZE;
        let mut sequence_number = 1;

        for chunk in data.chunks(data_len as usize) {
            let packet = NetworkICD {
                aes_key: new_aes_key.clone(),
                network: false,
                packet_number: PACKET_COUNTER.load(Ordering::SeqCst),
                seq_number: sequence_number,
                data: Vec::from(chunk),
            };
            sequence_number += 1;
            new_packets.push_back(packet);
        }

        PACKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        return new_packets;
    }

    pub fn assemble(&self,packets: VecDeque<NetworkICD>) -> Vec<u8>{
        let mut sorted_packets: Vec<_> = packets.into_iter().collect();
        sorted_packets.sort_by(|a, b| {
            a.packet_number.cmp(&b.packet_number)
                .then_with(|| a.seq_number.cmp(&b.seq_number))
        });
        let mut assembled_data = Vec::new();
        for packet in sorted_packets {
            assembled_data.extend(packet.data);
        }
        return assembled_data;
    }
}
