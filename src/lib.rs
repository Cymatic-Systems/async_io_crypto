//! Provides a wrapper around a [`AsyncRead`](tokio::io::AsyncRead)
//!
//! ```rust
//! # use async_io_crypto::{CipherRead, DecipherRead};
//! # use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
//! # use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
//! # use rand::SeedableRng;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! let key = b"my very super super secret key!!";
//! let plaintext = b"hello world!";
//!
//! let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
//! let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(Key::from_slice(key));
//! let (mut ci_reader, nonce) = CipherRead::new(&plaintext[..], cipher.clone(), &mut csprng);
//!
//! let mut ciphered = Vec::new();
//! ci_reader.read_to_end(&mut ciphered).await.unwrap();
//!
//! let mut deci_reader = DecipherRead::new(&ciphered[..], cipher, nonce.as_slice());

//! let mut deciphered = Vec::new();
//! deci_reader.read_to_end(&mut deciphered).await.unwrap();

//! assert_eq!(deciphered, plaintext);
//! # Ok(())
//! # }
//! ```

const CHUNK_INFO_SIZE: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();
const CHUNK_SIZE: usize = 64 * 1024;

mod cipher;
mod decipher;

pub use cipher::CipherRead;
pub use decipher::DecipherRead;
