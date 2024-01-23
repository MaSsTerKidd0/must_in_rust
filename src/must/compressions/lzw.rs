#[allow(unused_variables)]
use crate::must::compressions::encode_trait::EncodeTrait;

pub struct LZWEncode;


impl EncodeTrait for LZWEncode{
    fn compress(data: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }

    fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }
}
