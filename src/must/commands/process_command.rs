use crate::must::commands::command::Command;
use crate::must::processing_unit::actions_chain::filter::Filter;
use crate::must::processing_unit::actions_chain::filter::Protocol::UDP;
use crate::must::processing_unit::processor::ProcessorUnit;

impl Command for ProcessorUnit {
    fn execute(&self) {
        let running = true;
        let ip = "38.0.101.76";
        println!("In Process");

        while running {
            let packet_vec = self.packet_data_rx.recv().unwrap();
            let packet_data = packet_vec.as_slice();

            println!("received packet\n data: {:?}\n", packet_vec);

            if Filter::is_protocol_packet_for_ip(packet_data, ip, UDP)
            {
                println!("Packet Is UDP packet received from IP address {:}", ip);
            }
        }
    }
}