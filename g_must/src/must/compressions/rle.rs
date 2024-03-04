use crate::must::compressions::encode_trait::EncodeTrait;
pub struct RLEEncode;

impl EncodeTrait for RLEEncode {
    fn compress(data: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }

    fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }
}