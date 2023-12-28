pub trait EncodeTrait{
    fn encode(data: Vec<u8>) -> Option<Vec<u8>>;
}