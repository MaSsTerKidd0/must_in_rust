use crate::EncodeTrait;
use std::io::{Cursor, Read};
use tokio::io::AsyncReadExt;

pub struct RleEncoder;

impl EncodeTrait for RleEncoder {
    fn compress(data: &[u8]) -> Option<Vec<u8>> {
        let mut compressed = Vec::new();
        let mut cursor = Cursor::new(data);
        let mut prev_byte = None;
        let mut run_length = 0;

        let mut byte_buffer = [0u8; 1];

        loop {
            match std::io::Read::read_exact(&mut cursor, &mut byte_buffer) {
                Ok(_) => {
                    let byte = byte_buffer[0];
                    if Some(byte) != prev_byte || run_length == 255 {
                        if let Some(prev) = prev_byte {
                            compressed.push(run_length as u8);
                            compressed.push(prev);
                        }
                        prev_byte = Some(byte);
                        run_length = 1;
                    } else {
                        run_length += 1;
                    }
                }
                Err(_) => {
                    if run_length > 0 {
                        if let Some(prev) = prev_byte {
                            compressed.push(run_length as u8);
                            compressed.push(prev);
                        }
                    }
                    break;
                }
            }
        }

        Some(compressed)
    }

    fn decompress(compressed_data: &[u8]) -> Option<Vec<u8>> {
        let mut decompressed = Vec::new();
        let mut cursor = Cursor::new(compressed_data);

        let mut run_length_buffer = [0u8; 1];

        loop {
            match std::io::Read::read_exact(&mut cursor, &mut run_length_buffer) {
                Ok(_) => {
                    let run_length = run_length_buffer[0];
                    let mut byte_buffer = [0u8; 1];
                    if std::io::Read::read_exact(&mut cursor, &mut byte_buffer).is_ok() {
                        let byte = byte_buffer[0];
                        decompressed.extend(std::iter::repeat(byte).take(run_length as usize));
                    } else {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        Some(decompressed)
    }
}