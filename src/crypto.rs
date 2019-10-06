use hex::{decode, encode};

pub use sodiumoxide::crypto::sign::ed25519::PublicKey as ED25519PublicKey;
use sodiumoxide::crypto::sign::ed25519::Seed;
use sodiumoxide::crypto::sign::ed25519::Signature;
use sodiumoxide::crypto::sign::ed25519::{keypair_from_seed, verify_detached};

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::Nonce as BoxNonce;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey as BoxPublicKey;
pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey as BoxSecretKey;

use sodiumoxide::crypto::secretbox::open as secretbox_open;
pub use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Key as SecretBoxKey;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce as SecretBoxNonce;

use sodiumoxide::crypto::sign;

pub use crate::errors::*;

pub trait FromHex: Sized {
    fn from_hex(bs: &str) -> Result<Self, APIError>;
}

from_hex!(ED25519PublicKey, "ED25519PublicKey");
from_hex!(Seed, "Seed");
from_hex!(Signature, "Signature");

from_hex!(BoxNonce, "BoxNonce");
from_hex!(BoxSecretKey, "BoxSecretKey");
from_hex!(BoxPublicKey, "BoxPublicKeY");

from_hex!(SecretBoxKey, "SecretBoxKey");
from_hex!(SecretBoxNonce, "SecretBoxNonce");

pub fn verify_signature(
    public_key_hex: &str,
    msg: &str,
    signature_hex: &str,
) -> Result<(bool), APIError> {
    let public_key = ED25519PublicKey::from_hex(public_key_hex)?;
    let signature = Signature::from_hex(&signature_hex)?;
    Ok(verify_detached(&signature, msg.as_bytes(), &public_key))
}

pub fn open_secret_box(
    data_hex: &str,
    nonce_hex: &str,
    secret_hex: &str,
) -> Result<std::vec::Vec<u8>, APIError> {
    let data = decode(data_hex)?;
    let nonce = SecretBoxNonce::from_hex(&nonce_hex)?;
    let secret_key = SecretBoxKey::from_hex(&secret_hex)?;
    secretbox_open(&data, &nonce, &secret_key).or(Err(APIError::SecretBoxError {}))
}

pub fn open_box(
    data_hex: &str,
    nonce_hex: &str,
    pk_hex: &str,
    sk_hex: &str,
) -> Result<std::vec::Vec<u8>, APIError> {
    let data = decode(data_hex)?;
    let nonce = BoxNonce::from_hex(&nonce_hex)?;
    let pk = BoxPublicKey::from_hex(pk_hex)?;
    let sk = BoxSecretKey::from_hex(sk_hex)?;
    box_::open(&data, &nonce, &pk, &sk).or(Err(APIError::BoxError {}))
}

pub fn sign_string(msg: &str, pk_hex: &str) -> Result<String, APIError> {
    let seed = Seed::from_hex(pk_hex)?;
    let (_pk, sk) = keypair_from_seed(&seed);

    let signature = sign::sign_detached(msg.as_bytes(), &sk);
    let signature_hex = encode(signature);

    Ok(signature_hex)
}

pub fn create_session_keys_hex() -> (String, String) {
    let (session_pk, session_sk) = box_::gen_keypair();
    let session_pk_hex = encode(session_pk);
    let session_sk_hex = encode(session_sk);

    (session_pk_hex, session_sk_hex)
}
