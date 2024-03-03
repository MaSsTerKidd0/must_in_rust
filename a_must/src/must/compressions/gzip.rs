use crate::must::compressions::encode_trait::EncodeTrait;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::prelude::*;
use flate2::read::GzDecoder;

pub struct GzipEncode;

impl EncodeTrait for GzipEncode
{
    fn compress(data: &[u8]) -> Option<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("Failed to write data");
        return Some(encoder.finish().expect("Failed to finish compression"));
    }

    fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
        let mut decoder = GzDecoder::new(compressed_data);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data).expect("Failed to read data");
        return Some(decompressed_data);
    }
}