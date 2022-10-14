use std::{
    ops::Sub,
    pin::Pin,
    task::{Context, Poll},
};

use aead::{
    consts::*,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    stream::{EncryptorBE32, NewStream, Nonce, StreamBE32, StreamPrimitive},
    AeadInPlace,
};
use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{CHUNK_INFO_SIZE, CHUNK_SIZE};
//pub trait SOURCE = AsyncRead + Unpin + Send;
//pub trait CIPHER = AeadInPlace + Send + Clone;
//pub trait RNG = rand::RngCore + rand::CryptoRng + Send;

#[derive(Debug, PartialEq)]
enum State {
    Init,
    ReadingChunk,
    Ciphering,
    WritingChunkSize,
    WritingChunk,
    Eof,
}

pin_project! {
    pub struct CipherRead<S, C>
    where
        S: AsyncRead,
        C: AeadInPlace,
        <C as aead::AeadCore>::NonceSize: Sub<U5>,
        <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    {
        #[pin]
        reader: S,
        read: usize,
        last: bool,
        chunk_info_buffer: BytesMut,
        buffer: BytesMut,
        encryptor: Option<EncryptorBE32<C>>,
        state: State,
    }
}

impl<S: AsyncRead + Unpin + Send, C: AeadInPlace + Send + Clone> CipherRead<S, C>
where
    <C as aead::AeadCore>::NonceSize: Sub<U5>,
    <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    const TAG_OVERHEAD: usize = <C as aead::AeadCore>::TagSize::USIZE;
    const CIPHER_OVERHEAD: usize = <C as aead::AeadCore>::CiphertextOverhead::USIZE;
    const FETCH_SIZE: usize = CHUNK_SIZE - Self::TAG_OVERHEAD - Self::CIPHER_OVERHEAD;

    pub fn new<R: rand::RngCore + rand::CryptoRng + Send>(
        reader: S,
        cipher: C,
        csprng: &mut R,
    ) -> (Self, Nonce<C, StreamBE32<C>>) {
        let chunk_info_buffer = BytesMut::with_capacity(CHUNK_INFO_SIZE);
        let buffer = BytesMut::with_capacity(CHUNK_SIZE);
        let mut nonce: Nonce<C, StreamBE32<C>> = GenericArray::default();
        csprng.fill_bytes(&mut nonce);
        let encryptor = StreamBE32::from_aead(cipher, &nonce).encryptor();

        (
            Self {
                reader,
                read: 0,
                last: false,
                encryptor: Some(encryptor),
                chunk_info_buffer,
                buffer,
                state: State::Init,
            },
            nonce,
        )
    }

    fn poll_read_n(
        &mut self,
        cx: &mut Context<'_>,
        size_to_read: usize,
    ) -> Poll<std::io::Result<(usize, bool)>> {
        let mut read_count = 0;
        while self.read <= size_to_read {
            let dst = self.buffer.chunk_mut();
            let dst = unsafe { dst.as_uninit_slice_mut() };
            let mut buf = ReadBuf::uninit(dst);
            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            read_count += n;
            if n == 0 {
                return Poll::Ready(Ok((read_count, true)));
            }
            // Safety: This is guaranteed to be the number of initialized (and read)
            // bytes due to the invariants provided by `ReadBuf::filled`.
            unsafe {
                self.buffer.advance_mut(n);
            }
            self.read += n;
        }
        Poll::Ready(Ok((read_count, false)))
    }

    fn poll_read_chunk(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let (rc, eof) = ready!(self.poll_read_n(cx, Self::FETCH_SIZE))?;
        if self.read == 0 && rc == 0 {
            self.state = State::Eof;
            return Poll::Ready(Ok(0));
        }
        self.last = eof;
        self.state = State::Ciphering;
        Poll::Ready(Ok(rc))
    }

    fn cipher_chunk(&mut self) -> std::io::Result<()> {
        if self.last {
            if let Some(encryptor) = self.encryptor.take() {
                encryptor
                    .encrypt_last_in_place(b"", &mut self.buffer)
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Encryption last error: {:?}", e),
                        )
                    })?;
                self.state = State::WritingChunkSize;
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid state, encryptor consumed".to_string(),
                ))
            }
        } else if let Some(encryptor) = self.encryptor.as_mut() {
            encryptor
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Encryption error: {:?}", e),
                    )
                })?;
            self.state = State::WritingChunkSize;
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid state, encryptor consumed".to_string(),
            ))
        }
    }

    fn write_size(&mut self) {
        let value = self.buffer.len() as u32;
        self.chunk_info_buffer.put_u32_le(value);
        let last = u8::from(self.last);
        self.chunk_info_buffer.put_u8(last);
    }
}

impl<S: AsyncRead + Unpin + Send, C: AeadInPlace + Send + Clone> AsyncRead for CipherRead<S, C>
where
    <C as aead::AeadCore>::NonceSize: Sub<U5>,
    <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;

        loop {
            //dbg!(&me.state);
            match me.state {
                State::Init => {
                    me.buffer.clear();
                    me.buffer.reserve(CHUNK_SIZE);
                    me.state = State::ReadingChunk;
                    me.read = 0;
                }
                State::ReadingChunk => {
                    ready!(me.poll_read_chunk(cx))?;
                }
                State::Ciphering => {
                    me.cipher_chunk()?;
                    me.write_size();
                }
                State::WritingChunkSize => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    write_to_buffer(&mut me.chunk_info_buffer, buf);
                    if me.chunk_info_buffer.remaining() == 0 {
                        me.state = State::WritingChunk;
                    }
                }
                State::WritingChunk => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if me.buffer.remaining() == 0 {
                        if me.last {
                            me.state = State::Eof;
                        } else {
                            me.state = State::Init;
                        }
                    } else {
                        let w = write_to_buffer(&mut me.buffer, buf);
                        if w != 0 {
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                State::Eof => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

fn write_to_buffer(src: &mut BytesMut, dst: &mut ReadBuf) -> usize {
    let chunk = src.chunk();
    let amt = std::cmp::min(chunk.len(), dst.remaining());
    dst.put_slice(&chunk[..amt]);
    src.advance(amt);
    amt
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use aead::generic_array::typenum::Unsigned;
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
    use rand::SeedableRng;
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio_test::{io, task};

    use crate::{CipherRead, CHUNK_INFO_SIZE};

    fn create_read<R: AsyncRead + Unpin + Send>(input: R) -> impl AsyncRead + Unpin + Send {
        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
        let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
        let key = Key::from_slice(secret);
        let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);
        let (ci_reader, _) = CipherRead::new(input, cipher, &mut csprng);
        ci_reader
    }

    const TAG_OVERHEAD: usize = <ChaCha20Poly1305 as aead::AeadCore>::TagSize::USIZE;
    const CIPHER_OVERHEAD: usize = <ChaCha20Poly1305 as aead::AeadCore>::CiphertextOverhead::USIZE;

    #[test]
    fn it_can_cipher_empty() {
        let empty = io::Builder::new().build();
        let mut t = task::spawn(());
        let mut r = create_read(empty);

        t.enter(|cx, _| {
            let mut buf = [0; 8];
            let mut read_buf = ReadBuf::new(&mut buf);
            tokio_test::assert_ready_ok!(Pin::new(&mut r).poll_read(cx, &mut read_buf));
            assert_eq!(read_buf.filled().len(), 0);
        })
    }

    #[test]
    fn it_can_cipher_small_data() {
        let data = b"abcd";
        let small_read = io::Builder::new().read(data).build();
        let mut t = task::spawn(());
        let mut r = create_read(small_read);

        t.enter(|cx, _| {
            let mut buf = [0; 64];
            let written = {
                let mut read_buf = ReadBuf::new(&mut buf);
                tokio_test::assert_ready_ok!(Pin::new(&mut r).poll_read(cx, &mut read_buf));
                read_buf.filled().len()
            };

            assert_eq!(
                written,
                CHUNK_INFO_SIZE + data.len() + CIPHER_OVERHEAD + TAG_OVERHEAD
            );
        })
    }

    #[test]
    fn it_can_cipher_small_buffer() {
        let data = b"abcd";
        let small_read = io::Builder::new().read(data).build();
        let mut t = task::spawn(());
        let mut r = create_read(small_read);

        let expected_size = CHUNK_INFO_SIZE + data.len() + CIPHER_OVERHEAD + TAG_OVERHEAD;
        t.enter(|cx, _| {
            const BUF_SIZE: usize = 4;
            let mut buf = [0; BUF_SIZE];

            let mut total_written = 0;
            while total_written < expected_size {
                let mut read_buf = ReadBuf::new(&mut buf);
                tokio_test::assert_ready_ok!(Pin::new(&mut r).poll_read(cx, &mut read_buf));
                let count_w = read_buf.filled().len();
                let remaining = usize::min(expected_size - total_written, BUF_SIZE);
                total_written += count_w;
                assert_eq!(remaining, count_w);
                read_buf.clear();
            }
            assert_eq!(total_written, expected_size)
        })
    }
}
