use std::{
    ops::Sub,
    pin::Pin,
    task::{ready, Context, Poll},
};

use aead::{
    consts::*,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    stream::{EncryptorBE32, NewStream, Nonce, StreamBE32, StreamPrimitive},
};
use bytes::{Buf, BufMut, BytesMut};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{CHUNK_INFO_SIZE, CHUNK_SIZE, CIPHER, RNG, SOURCE};

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
    pub struct CipherRead<S: SOURCE, C: CIPHER>
    where
        <C as aead::AeadCore>::NonceSize: Sub<U5>,
        <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
    {
        #[pin]
        reader: S,
        read: usize,
        last: bool,
        buffer: BytesMut,
        encryptor: Option<EncryptorBE32<C>>,
        state: State,
    }
}

impl<S: SOURCE, C: CIPHER> CipherRead<S, C>
where
    <C as aead::AeadCore>::NonceSize: Sub<U5>,
    <<C as aead::AeadCore>::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    const FETCH_SIZE: usize = CHUNK_SIZE - <C::CiphertextOverhead as Unsigned>::USIZE;
    pub fn new<R: RNG>(reader: S, cipher: C, csprng: &mut R) -> (Self, Nonce<C, StreamBE32<C>>) {
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
        if rc == 0 {
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

    fn write_size(&mut self, dst: &mut ReadBuf) -> usize {
        if dst.remaining() >= CHUNK_INFO_SIZE {
            let value = self.buffer.len() as u32;
            dst.put_slice(&value.to_le_bytes());
            let last = &[u8::from(self.last)];
            dst.put_slice(last);
            self.state = State::WritingChunk;
            CHUNK_INFO_SIZE
        } else {
            0
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

impl<S: SOURCE, C: CIPHER> AsyncRead for CipherRead<S, C>
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
                }
                State::WritingChunkSize => {
                    me.write_size(buf);
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
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
                        let w = me.write_to_buffer(buf);
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
