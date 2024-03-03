pub struct CompressorHandler;

enum EncodingMethod {
    Huffman,
    LZW,
    RLE,
}


// impl CompressorHandler {
//     fn encode(data: Vec<u8>, method: EncodingMethod) -> Result<Vec<u8>, Err()> {
//         return match method {
//             EncodingMethod::Huffman => {
//                 //huffman_encode(data)
//             },
//             EncodingMethod::LZW => {
//                 //lzw_encode(data)
//             },
//             EncodingMethod::RLE => {
//                 //rle_encode(data)
//             },
//         }
//     }
// }

