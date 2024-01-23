use std::sync::mpsc::Receiver;

pub struct ProcessorUnit {
    pub(crate) packet_data_rx: Receiver<Vec<u8>>

}

impl ProcessorUnit {
    pub fn new(packet_data_rx: Receiver<Vec<u8>>) -> ProcessorUnit {
        ProcessorUnit {
            packet_data_rx,
        }
    }
}