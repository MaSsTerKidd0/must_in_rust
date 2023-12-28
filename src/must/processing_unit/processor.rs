use std::sync::mpsc::Receiver;

pub struct Processor{
    packet_data_rx: Receiver<Vec<u8>>
}

impl Processor {
    pub fn new(packet_data_rx: Receiver<Vec<u8>>) -> Processor {
        Processor {
            packet_data_rx,
        }
    }
}