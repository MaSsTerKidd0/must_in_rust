use crate::must::compressions::encode_trait::EncodeTrait;
pub struct RLEEncode;

impl EncodeTrait for RLEEncode {
    fn encode(data: Vec<u8>) -> Option<Vec<u8>> {
        todo!()
    }
}