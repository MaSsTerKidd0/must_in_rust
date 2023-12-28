#[allow(unused_variables)]
use crate::must::compressions::encode_trait::EncodeTrait;

pub struct LZWEncode;


impl EncodeTrait for LZWEncode{
    fn encode(data: Vec<u8>) -> Option<Vec<u8>> {
        todo!()
    }
}
