use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use rand::SeedableRng;

use async_io_crypto::{CipherRead, DecipherRead};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

#[tokio::test]
async fn it_can_cipher_and_decipher() {
    let value = "some_data";
    let data = value.as_bytes();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (ci_reader, nonce) = CipherRead::new(data, cipher.clone(), &mut csprng);

    let deci_reader = DecipherRead::new(ci_reader, cipher, nonce.as_slice());

    let buf_reader = BufReader::new(deci_reader);
    let mut lines = buf_reader.lines();
    let mut lc = 0;
    let mut output = Vec::new();
    while let Some(r) = lines.next_line().await.unwrap() {
        lc += 1;
        output.push(r);
    }

    assert_eq!(lc, 1);
    assert_eq!(output[0], value.to_string());
}

#[tokio::test]
async fn it_can_cipher_then_decipher() {
    let value = "some_data";
    let data = value.as_bytes();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (mut ci_reader, nonce) = CipherRead::new(data, cipher.clone(), &mut csprng);

    let mut vec = Vec::new();
    ci_reader.read_to_end(&mut vec).await.unwrap();
    assert!(!vec.is_empty());

    let mut deci_reader = DecipherRead::new(vec.as_slice(), cipher, nonce.as_slice());

    let mut vec_out = Vec::new();
    deci_reader.read_to_end(&mut vec_out).await.unwrap();

    assert_eq!(vec_out, data.to_vec());
}

#[tokio::test]
async fn it_can_cipher_files() {
    let value = tokio::fs::File::open("tests/data/lorem.txt").await.unwrap();
    let metadata = value.metadata().await.unwrap();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (mut ci_reader, _) = CipherRead::new(value, cipher.clone(), &mut csprng);

    let mut vec = Vec::with_capacity(1000000);
    ci_reader.read_to_end(&mut vec).await.unwrap();
    assert!(vec.len() as u64 >= metadata.len());
}

#[tokio::test]
async fn it_can_cipher_then_decipher_files() {
    let value = tokio::fs::File::open("tests/data/lorem.txt").await.unwrap();
    let metadata = value.metadata().await.unwrap();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (mut ci_reader, nonce) = CipherRead::new(value, cipher.clone(), &mut csprng);

    let mut vec = Vec::with_capacity(65000);
    ci_reader.read_to_end(&mut vec).await.unwrap();
    assert!(vec.len() as u64 >= metadata.len());

    let deci_reader = DecipherRead::new(vec.as_slice(), cipher, nonce.as_slice());

    let mut br = BufReader::new(deci_reader).lines();
    let mut lc = 0;
    while br.next_line().await.unwrap().is_some() {
        lc += 1;
    }
    assert_eq!(lc, 35);
}

#[tokio::test]
async fn it_can_cipher_big_files() {
    let value = tokio::fs::File::open("tests/data/lorem_big.txt")
        .await
        .unwrap();
    let metadata = value.metadata().await.unwrap();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (mut ci_reader, _) = CipherRead::new(value, cipher.clone(), &mut csprng);

    let mut vec = Vec::with_capacity(1000000);
    ci_reader.read_to_end(&mut vec).await.unwrap();
    assert!(vec.len() as u64 >= metadata.len());
}

#[tokio::test]
async fn it_can_cipher_then_decipher_big_files() {
    let value = tokio::fs::File::open("tests/data/lorem_big.txt")
        .await
        .unwrap();
    let metadata = value.metadata().await.unwrap();
    let secret = b"super_secret_aaaaaaaaaaaaaaaaaaa";
    let key = Key::from_slice(secret);
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(key);

    let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();
    let (mut ci_reader, nonce) = CipherRead::new(value, cipher.clone(), &mut csprng);

    let mut vec = Vec::with_capacity(65000);
    ci_reader.read_to_end(&mut vec).await.unwrap();
    assert!(vec.len() as u64 >= metadata.len());

    let deci_reader = DecipherRead::new(vec.as_slice(), cipher, nonce.as_slice());

    let mut br = BufReader::new(deci_reader).lines();
    let mut lc = 0;
    while br.next_line().await.unwrap().is_some() {
        lc += 1;
    }
    assert_eq!(lc, 325);
}
