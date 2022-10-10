const CHUNK_INFO_SIZE: usize = std::mem::size_of::<u32>() + std::mem::size_of::<u8>();
const CHUNK_SIZE: usize = 64 * 1024;

pub mod cipher;
pub mod decipher;
