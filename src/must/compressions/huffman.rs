use crate::must::compressions::encode_trait::EncodeTrait;
pub struct HuffmanEncode;

impl EncodeTrait for HuffmanEncode{
    fn encode(_data: Vec<u8>) -> Option<Vec<u8>> {
        todo!()
    }
}