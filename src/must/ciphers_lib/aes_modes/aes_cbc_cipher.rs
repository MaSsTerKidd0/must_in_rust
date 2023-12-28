// use openssl::symm::{Cipher, Crypter, Mode};
// use openssl::error::ErrorStack;
//
// pub trait AesCipher<IvOrNonce> {
//     fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack>;
//     fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack>;
// }
//
// pub struct AesCbc;
//
// impl AesCipher<[u8; 16]> for AesCbc {
//     fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
//         let cipher = Cipher::aes_256_cbc();
//         let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
//         let mut ciphertext = vec![0; data.len() + cipher.block_size()];
//         let count = crypter.update(data, &mut ciphertext)?;
//         let rest = crypter.finalize(&mut ciphertext[count..])?;
//         ciphertext.truncate(count + rest);
//         Ok(ciphertext)
//     }
//
//     fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorStack> {
//         let cipher = Cipher::aes_256_cbc();
//         let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
//         let mut plaintext = vec![0; data.len() + cipher.block_size()];
//         let count = crypter.update(data, &mut plaintext)?;
//         let rest = crypter.finalize(&mut plaintext[count..])?;
//         plaintext.truncate(count + rest);
//         Ok(plaintext)
//     }
// }
