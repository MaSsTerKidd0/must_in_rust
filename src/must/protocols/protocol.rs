
pub trait Protocol {
    fn receive(&self) -> Option<String>;
    fn send(&self) -> Option<String>;
}