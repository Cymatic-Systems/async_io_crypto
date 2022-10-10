use pin_project_lite::pin_project;

use aead::{
    consts::*,
    generic_array::{ArrayLength, GenericArray},
    stream::{DecryptorBE32, NewStream, StreamBE32, StreamPrimitive},
};
use bytes::{Buf, BufMut, BytesMut};
use std::{ops::Sub, pin::Pin, task::*};
use tokio::io::{AsyncRead, ReadBuf};

use crate::{CHUNK_INFO_SIZE, CHUNK_SIZE, CIPHER, SOURCE};
#[derive(Debug, PartialEq)]
enum State {
    Init,
    ReadingChunkSize,
    ReadingChunk(usize),
    WritingBuffer,
    Eof,
}

pin_project! {
    pub struct DecipherRead<S: SOURCE, C: CIPHER>
    where
        <C as aead::AeadCore>::NonceSize: Sub<U5>,
        <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    {
        #[pin]
        reader: S,
        read: usize,
        last: bool,
        buffer: BytesMut,
        decryptor: Option<DecryptorBE32<C>>,
        state: State,
    }
}

impl<R: SOURCE, C: CIPHER> DecipherRead<R, C>
where
    <C as aead::AeadCore>::NonceSize: Sub<U5>,
    <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    pub fn new(reader: R, cipher: C, init_nonce: &[u8]) -> Self {
        let buffer = BytesMut::with_capacity(CHUNK_SIZE);
        let init_nonce = GenericArray::from_slice(init_nonce);
        let decryptor = StreamBE32::from_aead(cipher, init_nonce).decryptor();

        Self {
            reader,
            read: 0,
            last: false,
            decryptor: Some(decryptor),
            buffer,
            state: State::Init,
        }
    }

    fn read_chunk_size(buffer: &mut BytesMut) -> (bool, usize) {
        let value = buffer.get_u32_le() as usize;
        let last = buffer.get_u8();
        (last != 0, value)
    }

    fn poll_read_n(
        &mut self,
        cx: &mut Context<'_>,
        size_to_read: usize,
    ) -> Poll<std::io::Result<usize>> {
        let mut read_count = 0;
        while self.read < size_to_read {
            let dst = self.buffer.chunk_mut();
            let dst = unsafe { dst.as_uninit_slice_mut() };
            let mut buf = ReadBuf::uninit(dst);
            let mut buf2 = buf.take(size_to_read - self.read);
            ready!(Pin::new(&mut self.reader).poll_read(cx, &mut buf2))?;
            let n = buf2.filled().len();
            read_count += n;
            if n == 0 {
                return Poll::Ready(Ok(read_count));
            }
            // Safety: This is guaranteed to be the number of initialized (and read)
            // bytes due to the invariants provided by `ReadBuf::filled`.
            unsafe {
                self.buffer.advance_mut(n);
            }
            self.read += n;
        }
        Poll::Ready(Ok(read_count))
    }

    fn poll_read_chunk_size(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        let rc = ready!(self.poll_read_n(cx, CHUNK_INFO_SIZE))?;

        if rc == 0 {
            return Poll::Ready(Ok(0));
        }
        let (last, value) = Self::read_chunk_size(&mut self.buffer);
        self.read = 0;
        self.last = last;
        self.state = State::ReadingChunk(value);
        self.buffer.reserve(value as usize);
        Poll::Ready(Ok(rc))
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        chunk_size: usize,
    ) -> Poll<std::io::Result<()>> {
        ready!(self.poll_read_n(cx, chunk_size))?;

        if self.last {
            if let Some(decryptor) = self.decryptor.take() {
                decryptor
                    .decrypt_last_in_place(b"", &mut self.buffer)
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Decryption error: {:?}", e),
                        )
                    })?;
                self.state = State::WritingBuffer;
                self.read = 0;
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid state, decryptor consumed".to_string(),
                )))
            }
        } else if let Some(decryptor) = self.decryptor.as_mut() {
            decryptor
                .decrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Decryption error: {:?}", e),
                    )
                })?;
            self.state = State::WritingBuffer;
            self.read = 0;
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid state, decryptor consumed".to_string(),
            )))
        }
    }

    fn write_to_buffer(&mut self, dst: &mut ReadBuf) -> usize {
        let chunk = self.buffer.chunk();
        let amt = std::cmp::min(chunk.len(), dst.remaining());
        dst.put_slice(&chunk[..amt]);
        self.buffer.advance(amt);
        amt
    }
}

impl<R: SOURCE, C: CIPHER> AsyncRead for DecipherRead<R, C>
where
    <C as aead::AeadCore>::NonceSize: Sub<U5>,
    <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;

        loop {
            match me.state {
                State::Init => {
                    me.buffer.reserve(CHUNK_INFO_SIZE);
                    me.state = State::ReadingChunkSize;
                }
                State::ReadingChunkSize => {
                    let rc = ready!(me.poll_read_chunk_size(cx))?;
                    if rc == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                State::ReadingChunk(size) => {
                    ready!(me.poll_read_chunk(cx, size))?;
                }
                State::WritingBuffer => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    if me.buffer.remaining() == 0 {
                        if me.last {
                            me.state = State::Eof;
                        } else {
                            me.state = State::Init;
                        }
                    }
                    let w = me.write_to_buffer(buf);
                    if w != 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                State::Eof => {
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use aead::{
        generic_array::GenericArray,
        stream::{Nonce, StreamBE32},
    };
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
    use rand::{RngCore, SeedableRng};

    use super::DecipherRead;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[tokio::test]
    async fn it_can_read_empty() {
        let data = tokio::io::empty();
        let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
        let key = Key::from_slice(secret);
        let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut nonce: Nonce<ChaCha20Poly1305, StreamBE32<ChaCha20Poly1305>> =
            GenericArray::default();
        csprng.fill_bytes(&mut nonce);

        let reader = DecipherRead::new(data, cipher, nonce.as_slice());

        let buf_reader = BufReader::new(reader);
        let mut lines = buf_reader.lines();
        let mut lc = 0;
        while lines.next_line().await.unwrap().is_some() {
            lc += 1;
        }

        assert_eq!(lc, 0);
    }
}
