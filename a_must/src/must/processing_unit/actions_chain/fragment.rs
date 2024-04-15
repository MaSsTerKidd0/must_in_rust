use std::sync::atomic::{AtomicU16, Ordering};
use crate::must::network::network_icd::NetworkICD;
use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};

const SECURE_HEADER_SIZE: u16 = 32+12+5;
const UNSECURE_HEADER_SIZE: u16 = 5;
static PACKET_COUNTER: AtomicU16 = AtomicU16::new(1);

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Fragment{
    pub(crate) secure_net_max_bandwidth: u16,
    pub(crate) unsecure_net_max_bandwidth: u16,
}


impl Fragment{

    pub fn fragment(&self, data: &[u8], new_aes_key: Vec<u8>, aes_nonce_or_iv: Vec<u8>, net_type: bool) -> VecDeque<NetworkICD> {
        let mut new_packets = VecDeque::new();

        let data_len = if (net_type) {  self.secure_net_max_bandwidth - SECURE_HEADER_SIZE }
        else {
            self.unsecure_net_max_bandwidth - UNSECURE_HEADER_SIZE
        };
        let mut sequence_number = 1;

        for chunk in data.chunks(data_len as usize) {
            let packet = NetworkICD {
                aes_key: new_aes_key.clone(),
                iv_or_nonce: aes_nonce_or_iv.clone(),
                network: net_type,
                packet_number: PACKET_COUNTER.load(Ordering::SeqCst),
                seq_number: sequence_number,
                frames_amount: data.chunks(data_len as usize).len() as u16,
                data: Vec::from(chunk),
            };
            sequence_number += 1;
            new_packets.push_back(packet);
        }

        PACKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        return new_packets;
    }
    pub fn assemble(&self, packets: &mut VecDeque<NetworkICD>) -> VecDeque<Vec<u8>> {
        let mut packet_groups: HashMap<u16, Vec<&NetworkICD>> = HashMap::new();
        let mut indices_to_remove: Vec<usize> = Vec::new();

        // Group packets by packet_number, cloning necessary data
        for (i, packet) in packets.iter().enumerate() {
            packet_groups.entry(packet.packet_number).or_insert_with(Vec::new).push(packet);
            if packet_groups[&packet.packet_number].len() == packet.frames_amount as usize {
                indices_to_remove.push(i);
            }
        }
        let mut assembled_packets = VecDeque::new();

        // For each group, sort by seq_number and concatenate data
        for (_, mut group) in packet_groups {
            if group.len() == group[0].frames_amount as usize {
                group.sort_by_key(|packet| packet.seq_number);
                let mut assembled_data = Vec::new();
                for packet in group {
                    assembled_data.extend(&packet.data);
                }
                assembled_packets.push_back(assembled_data);
            }
        }

        // Remove the assembled packets from the original packets
        indices_to_remove.sort_by(|a, b| b.cmp(a));
        for index in indices_to_remove {
            packets.remove(index);
        }

        assembled_packets
    }
}
