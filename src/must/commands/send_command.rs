use crate::must::commands::command::Command;
use crate::must::protocols::protocol::Protocol;
use crate::must::send_unit::send::SendUnit;

impl<T: Protocol> Command for SendUnit<T>{
    fn execute(&self) {
        self.send(&[]).expect("TODO: panic message");
    }
}



