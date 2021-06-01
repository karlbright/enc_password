//! Simple rust implementation of enc_password format and creation used by
//! Instagram. Based on existing implementation in encryptionUtils.js
//! as part of the webpack bundle.
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm::Aes256Gcm;
use sodiumoxide::{
    base64,
    crypto::{box_::PublicKey, sealedbox},
    randombytes,
};
use std::time::{SystemTime, UNIX_EPOCH};

const PREPACKSIZE: usize = 4;
const KEYSIZE: usize = 32;
const SEALEDKEYSIZE: usize = sealedbox::SEALBYTES + KEYSIZE;

#[derive(Debug)]
pub struct Error;

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error")
    }
}

/// Generate a key of the correct size to use when encrypting the password initially
/// as well as being sealed using instagram public key.
pub fn generate_key() -> [u8; KEYSIZE] {
    let mut key: [u8; 32] = [0; KEYSIZE];
    randombytes::randombytes_into(&mut key);
    key
}

fn encrypt_message(key: &[u8], msg: &[u8], aad: Option<&[u8]>) -> Vec<u8> {
    assert_eq!(key.len(), KEYSIZE);
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from([0; 12]);
    let payload = match aad {
        Some(aad) => Payload { msg, aad },
        None => Payload { msg, aad: &[] },
    };
    cipher
        .encrypt(&nonce, payload)
        .expect("Failed to encrypt message")
}

/// Generate encoded password format using current key id, key version, public key, and
/// a password. The first three arguments must be provided and match against current
/// instagram shared data.
pub fn enc_password(
    key_id: &str,
    key_version: &str,
    public_key: &str,
    password: &str,
) -> Result<String, crate::Error> {
    let parsed_public_key = parse_key(&public_key);
    let current_time = current_time_as_bytes();
    let message_key = generate_key();
    let encrypted_message = encrypt_message(&message_key, password.as_bytes(), Some(&current_time));
    let sealed_key = seal_key(&message_key, &parsed_public_key);
    let packed = pack(key_id, &sealed_key, &encrypted_message);
    Ok(enc_password_string(key_version, &current_time, &packed))
}

fn pack(key_id: &str, sealed_key: &[u8], encrypted_message: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::<u8>::new();
    buffer.push(1);
    buffer.push(u8::from_str_radix(key_id, 10).unwrap());
    buffer.push(sealed_key.len() as u8);
    buffer.push((sealed_key.len() >> 8) as u8);
    buffer.append(&mut sealed_key.to_vec());
    assert_eq!(buffer.len(), PREPACKSIZE + SEALEDKEYSIZE);
    buffer.append(&mut encrypted_message[(encrypted_message.len() - 16)..].to_vec());
    buffer.append(&mut encrypted_message[..(encrypted_message.len() - 16)].to_vec());
    buffer
}

fn enc_password_string(key_version: &str, current_time: &[u8], package: &[u8]) -> String {
    let encoded_package = base64::encode(package, base64::Variant::Original);
    let time_as_string = std::str::from_utf8(current_time).unwrap();
    format!(
        "#PWD_INSTAGRAM_BROWSER:{}:{}:{}",
        key_version, time_as_string, encoded_package
    )
}

fn current_time_as_bytes() -> Vec<u8> {
    let buffer = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
        .into_bytes();
    assert_eq!(buffer.len(), 10);
    buffer
}

fn seal_key(key: &[u8], pk: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), KEYSIZE);
    assert_eq!(pk.len(), KEYSIZE);
    let pk = PublicKey::from_slice(pk).unwrap();
    let sealed_key = sealedbox::seal(key, &pk);
    assert_eq!(sealed_key.len(), SEALEDKEYSIZE);
    sealed_key
}

fn parse_key(key: &str) -> Vec<u8> {
    let mut parsed_key = Vec::<u8>::new();
    let mut chars = key.char_indices();
    while let Some((start, _)) = &chars.next() {
        let end = start + 1;
        let byte = u8::from_str_radix(&key[*start..=end], 16).unwrap();
        parsed_key.push(byte);
        chars.next();
    }
    assert_eq!(parsed_key.len(), KEYSIZE);
    parsed_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_length() {
        let key = crate::generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_key_rand() {
        let key1 = crate::generate_key();
        let key2 = crate::generate_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn parsed_key_length() {
        let key = "c251eca108fa8c40acd2cad6eda30475fe779d9fd797cbccec654912c84f8a39";
        let parsed_key = parse_key(&key);
        assert_eq!(parsed_key.len(), key.len() / 2);
    }

    #[test]
    fn parsed_key_contents() {
        let key = "c251eca108fa8c40acd2cad6eda30475fe779d9fd797cbccec654912c84f8a39";
        let parsed_key = parse_key(&key);
        assert_eq!(parsed_key, b"\xc2\x51\xec\xa1\x08\xfa\x8c\x40\xac\xd2\xca\xd6\xed\xa3\x04\x75\xfe\x77\x9d\x9f\xd7\x97\xcb\xcc\xec\x65\x49\x12\xc8\x4f\x8a\x39");
    }

    #[test]
    fn encrypted_message_length() {
        let key = [0; 32];
        let message = "hello";
        let encrypted = crate::encrypt_message(&key, message.as_bytes(), None);
        assert_eq!(encrypted.len(), 21);
    }

    #[test]
    fn encrypted_message_contents() {
        let key = [0; 32];
        let message = "hello";
        let encrypted = crate::encrypt_message(&key, message.as_bytes(), None);
        assert_eq!(
            encrypted,
            b"\xa6\xc2\x2c\x51\x22\x8b\x90\x8F\x7f\x62\xff\xce\xa6\xa9\x2f\xab\xef\x39\xbf\x4d\x93"
        );
    }

    #[test]
    fn encrypted_additional_data() {
        let key = [0; 32];
        let message = "hello";
        let aad = b"123456";
        let encrypted = crate::encrypt_message(&key, message.as_bytes(), Some(aad));
        assert_eq!(
            encrypted,
            b"\xa6\xc2\x2c\x51\x22\x92\x84\xa2\xa2\x3e\xe9\x71\xdc\x6f\xa9\xda\xdd\x7a\x1b\xc2\xc6"
        );
    }

    #[test]
    fn encode_password_works() {
        let encoded_password = enc_password(
            "20",
            "10",
            "c251eca108fa8c40acd2cad6eda30475fe779d9fd797cbccec654912c84f8a39",
            "foobar",
        );
        assert_eq!(encoded_password.unwrap().len(), 181);
    }
}
