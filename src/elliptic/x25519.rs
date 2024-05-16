use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret as SecretKey};

use crate::compat::Vec;
use crate::consts::SharedSecret;
use crate::symmetric::hkdf_derive;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidMessage,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Generate a `(SecretKey, PublicKey)` pair
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random_from_rng(&mut OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

/// Calculate a shared symmetric key of our secret key and peer's public key by hkdf
pub fn encapsulate(sk: &SecretKey, peer_pk: &PublicKey) -> Result<SharedSecret, Error> {
    let shared_point = sk.diffie_hellman(&peer_pk);
    let sender_point = PublicKey::from(sk);
    Ok(get_shared_secret(sender_point.as_bytes(), shared_point.as_bytes()))
}

/// Calculate a shared symmetric key of our public key and peer's secret key by hkdf
pub fn decapsulate(pk: &PublicKey, peer_sk: &SecretKey) -> Result<SharedSecret, Error> {
    let shared_point = peer_sk.diffie_hellman(&pk);
    Ok(get_shared_secret(pk.as_bytes(), shared_point.as_bytes()))
}

/// Parse secret key bytes
pub fn parse_sk(sk: &[u8]) -> Result<SecretKey, Error> {
    let mut data = [0u8; 32];
    data.copy_from_slice(sk);
    Ok(SecretKey::from(data))
}

/// Parse public key bytes
pub fn parse_pk(pk: &[u8]) -> Result<PublicKey, Error> {
    let mut data = [0u8; 32];
    data.copy_from_slice(pk);
    Ok(PublicKey::from(data))
}

/// Public key to bytes
pub fn pk_to_vec(pk: &PublicKey, _compressed: bool) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

fn get_shared_secret(sender_point: &[u8], shared_point: &[u8]) -> SharedSecret {
    hkdf_derive(sender_point, shared_point)
}

#[cfg(test)]
mod lib_tests {
    use super::{generate_keypair, Error};
    use crate::{decrypt, encrypt};

    const MSG: &str = "helloworld🌍";
    const BIG_MSG_SIZE: usize = 2 * 1024 * 1024; // 2 MB
    const BIG_MSG: [u8; BIG_MSG_SIZE] = [1u8; BIG_MSG_SIZE];

    fn test_enc_dec(sk: &[u8], pk: &[u8]) {
        let msg = MSG.as_bytes();
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
        let msg = &BIG_MSG;
        assert_eq!(msg.to_vec(), decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap());
    }

    #[test]
    pub fn test_compressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (sk.as_bytes(), pk.as_bytes());
        test_enc_dec(sk, pk);
    }

    #[test]
    pub fn test_uncompressed_public() {
        let (sk, pk) = generate_keypair();
        let (sk, pk) = (sk.as_bytes(), pk.as_bytes());
        test_enc_dec(sk, pk);
    }
}
