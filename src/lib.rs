#![feature(trait_alias)]

use aead::AeadInPlace;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait DEST = AsyncWrite + Unpin + Send;
pub trait SOURCE = AsyncRead + Unpin + Send;
pub trait CIPHER = AeadInPlace + Send + Clone;
pub trait RNG = rand::RngCore + rand::CryptoRng + Send;

const CHUNK_INFO_SIZE: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();
const CHUNK_SIZE: usize = 64 * 1024;

pub mod cipher;
pub mod decipher;
