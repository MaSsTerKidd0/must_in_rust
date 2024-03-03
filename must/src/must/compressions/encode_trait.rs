pub trait EncodeTrait{
    fn compress(data: &[u8]) -> Option<Vec<u8>>;
    fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>>;
}