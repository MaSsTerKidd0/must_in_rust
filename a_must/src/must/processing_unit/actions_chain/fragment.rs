use std::sync::atomic::{AtomicU16, Ordering};
use crate::must::network::network_icd::NetworkICD;
use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};

const SECURE_HEADER_SIZE: u16 = 51;
const UNSECURE_HEADER_SIZE: u16 = 7;
static PACKET_COUNTER: AtomicU16 = AtomicU16::new(1);

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Fragment{
    pub(crate) secure_net_max_bandwidth: u16,
    pub(crate) unsecure_net_max_bandwidth: u16,
}


impl Fragment{

    /// Fragments a data array into smaller packets based on network bandwidth constraints.
    ///
    /// This function takes a byte slice and divides it into multiple network packets, each complying with the maximum payload size constraints dictated by whether the network is secure or not. It also assigns each packet a new AES key and an initialization vector or nonce for encryption.
    ///
    /// # Parameters:
    /// - `data`: A byte slice of the original data to be fragmented.
    /// - `new_aes_key`: A vector containing the new AES encryption key.
    /// - `aes_nonce_or_iv`: A vector containing the AES initialization vector or nonce.
    /// - `net_type`: A boolean indicating whether the network is secure (true) or not (false).
    ///
    /// # Returns:
    /// - A vector of `NetworkICD` packets, each containing a portion of the original data along with the encryption parameters and packet metadata.
    ///
    /// # Runtime Complexity:
    /// - O(n), where `n` is the length of the `data` array.
        pub fn fragment(&self, data: &[u8], new_aes_key: Vec<u8>, aes_nonce_or_iv: Vec<u8>, net_type: bool) -> Vec<NetworkICD> {
        let max_payload_size = if net_type {
            self.secure_net_max_bandwidth - SECURE_HEADER_SIZE
        } else {
            self.unsecure_net_max_bandwidth - UNSECURE_HEADER_SIZE
        };

        let mut packets = Vec::new();
        let mut sequence_number = 1;
        let mut packet_counter = PACKET_COUNTER.fetch_add(1, Ordering::SeqCst);

        for chunk in data.chunks(max_payload_size as usize) {
            let packet = NetworkICD {
                aes_key: new_aes_key.clone(),//32bytes
                iv_or_nonce: aes_nonce_or_iv.clone(),// 12 or 16 bytes
                network: net_type, // 1 byte
                packet_number: packet_counter,//2bytes
                seq_number: sequence_number,//2bytes
                frames_amount: ((data.len() + max_payload_size as usize - 1) / max_payload_size as usize) as u16,//2 bytes
                data: Vec::from(chunk),//rest
            };
            sequence_number += 1;
            packets.push(packet);
        }

        packets
    }

    /// Assembles fragmented packets back into complete data sets.
    ///
    /// This function takes a mutable queue of network packets and assembles them back into their original data form. It groups packets by their packet number, ensures all fragments of a group are present, sorts them by sequence number, and then concatenates their data to form the complete byte arrays.
    ///
    /// # Parameters:
    /// - `packets`: A mutable reference to a deque of `NetworkICD` network packets to be assembled.
    ///
    /// # Returns:
    /// - A `VecDeque<Vec<u8>>` where each `Vec<u8>` represents a complete set of data reconstructed from the fragmented packets.
    ///
    /// # Runtime Complexity:
    /// - O(m log m), where `m` is the number of packets.
    pub fn assemble(&self, packets: &mut VecDeque<NetworkICD>) -> VecDeque<Vec<u8>> {
        let mut packet_groups: HashMap<u16, Vec<&NetworkICD>> = HashMap::new();
        let mut indices_to_remove: Vec<usize> = Vec::new();

        // Group packets by packet_number, cloning necessary datanpm
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
