use hex::{decode, encode};

use xsalsa20poly1305::aead::generic_array::{typenum::U24, GenericArray};
use xsalsa20poly1305::aead::{Aead, NewAead};
use xsalsa20poly1305::XSalsa20Poly1305;

use ring::signature::{Ed25519KeyPair, Signature, UnparsedPublicKey, ED25519};

use crate::APIError;
use crypto_box::{generate_nonce, PublicKey, SalsaBox, SecretKey};

pub const NONCE_LENGTH: usize = 24;
pub const SECRET_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_KEY_LENGTH: usize = 32;

pub trait FromHex: Sized {
    fn from_hex(bs: &str) -> Result<Self, APIError>;
}

fn decode_hex_with_length_check(s: &str, length: usize) -> Result<Vec<u8>, APIError> {
    let raw = decode(&s)?;

    if raw.len() != length {
        return Err(APIError::CryptoLengthError {
            error: format!("supplied: {}, required: {}", raw.len(), length),
        });
    }

    Ok(raw)
}

fn check_key(key_hex: &str, length: usize) -> Result<(), String> {
    let r = decode_hex_with_length_check(key_hex, length);

    if r.is_ok() {
        return Ok(());
    } else {
        return Err(r.unwrap_err().to_string());
    }
}

pub fn check_secret_box_key(key_hex: &str) -> Result<(), String> {
    check_key(key_hex, SECRET_LENGTH)
}

pub fn check_box_key(key_hex: &str) -> Result<(), String> {
    check_key(key_hex, SECRET_KEY_LENGTH)
}

pub fn check_signature_key(key_hex: &str) -> Result<(), String> {
    check_key(key_hex, SIGNATURE_KEY_LENGTH)
}

impl FromHex for XSalsa20Poly1305 {
    fn from_hex(bs: &str) -> Result<XSalsa20Poly1305, APIError> {
        let raw = decode(&bs)?;
        if raw.len() != SECRET_LENGTH {
            return Err(APIError::CryptoLengthError {
                error: "secretbox secret must be 32 bytes".to_owned(),
            });
        }

        let key = GenericArray::from_slice(&raw);

        Ok(XSalsa20Poly1305::new(*key))
    }
}

pub type Nonce = GenericArray<u8, U24>;

impl FromHex for Nonce {
    fn from_hex(bs: &str) -> Result<Nonce, APIError> {
        let raw = decode_hex_with_length_check(&bs, NONCE_LENGTH)?;

        let nonce = GenericArray::clone_from_slice(&raw);

        Ok(nonce)
    }
}

impl FromHex for SecretKey {
    fn from_hex(bs: &str) -> Result<SecretKey, APIError> {
        let raw = decode_hex_with_length_check(&bs, SECRET_KEY_LENGTH)?;

        let mut raw_array: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        raw.iter().enumerate().for_each(|(i, v)| raw_array[i] = *v);

        let sk = SecretKey::from(raw_array);

        Ok(sk)
    }
}

impl FromHex for PublicKey {
    fn from_hex(bs: &str) -> Result<PublicKey, APIError> {
        let raw = decode_hex_with_length_check(&bs, PUBLIC_KEY_LENGTH)?;

        let mut raw_array: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        raw.iter().enumerate().for_each(|(i, v)| raw_array[i] = *v);

        let pk = PublicKey::from(raw_array);

        Ok(pk)
    }
}

pub fn open_secret_box(
    cipher_message_hex: &str,
    nonce_hex: &str,
    key_hex: &str,
) -> Result<Vec<u8>, APIError> {
    let salsa = XSalsa20Poly1305::from_hex(&key_hex)?;
    let nonce = Nonce::from_hex(&nonce_hex)?;
    let cipher_message = decode(cipher_message_hex)?;

    salsa
        .decrypt(&nonce, cipher_message.as_slice())
        .map_err(|e| APIError::SecretBoxOpenError {
            error: format!("decrypt error: {:?}", e),
        })

    // String::from_utf8(message).map_err(|e| APIError::SecretBoxOpenError {
    //     error: format!("decrypted message invalid utf-8: {}", e),
    // })
}

pub fn secretbox_seal(message: &str, key_hex: &str, nonce_hex: &str) -> Result<Vec<u8>, APIError> {
    let salsa = XSalsa20Poly1305::from_hex(&key_hex)?;
    let nonce = Nonce::from_hex(&nonce_hex)?;
    let cipher_message =
        salsa
            .encrypt(&nonce, message.as_bytes())
            .map_err(|e| APIError::SecretBoxSealError {
                error: format!("encrypt error: {:?}", e),
            })?;

    Ok(cipher_message)
}

pub fn secretbox_seal_hex(
    message: &str,
    key_hex: &str,
    nonce_hex: &str,
) -> Result<String, APIError> {
    let cipher_message = secretbox_seal(message, key_hex, nonce_hex)?;

    let cipher_message_hex = encode(&cipher_message);

    Ok(cipher_message_hex)
}

/// returns a tuple (PublicKey, SecretKey) which can be used by box_seal
pub fn generate_box_session_keys() -> (PublicKey, SecretKey) {
    let mut rng = rand::thread_rng();
    let sk = SecretKey::generate(&mut rng);
    let pk = sk.public_key();

    (pk, sk)
}

/// return tuple (public_key, secret_key) hexified
pub fn create_session_keys_hex() -> (String, String) {
    let (pk, sk) = generate_box_session_keys();

    let sk_hex = encode(sk.to_bytes());
    let pk_hex = encode(pk.as_bytes());

    (pk_hex, sk_hex)
}

pub fn open_box(
    cipher_text_hex: &str,
    nonce_hex: &str,
    pk_hex: &str,
    sk_hex: &str,
) -> Result<Vec<u8>, APIError> {
    let secret_key = SecretKey::from_hex(&sk_hex)?;
    let public_key = PublicKey::from_hex(&pk_hex)?;
    let nonce = Nonce::from_hex(&nonce_hex)?;

    let ciphertext_raw = decode(&cipher_text_hex)?;

    let salsa_box = SalsaBox::new(&public_key, &secret_key);

    salsa_box
        .decrypt(&nonce, ciphertext_raw.as_slice())
        .map_err(|e| APIError::SessionBoxSecretKeyError {})
}

pub fn seal_box(
    message: &str,
    sk_hex: &str,
    pk_hex: &str,
    nonce_hex: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), APIError> {
    let mut rng = rand::thread_rng();

    let secret_key = SecretKey::from_hex(&sk_hex)?;
    let public_key = PublicKey::from_hex(&pk_hex)?;

    let nonce = match nonce_hex {
        Some(nonce_hex) => Nonce::from_hex(&nonce_hex)?,
        None => generate_nonce(&mut rng),
    };

    let salsa_box = SalsaBox::new(&public_key, &secret_key);

    let cipher_text =
        salsa_box
            .encrypt(&nonce, message.as_bytes())
            .map_err(|e| APIError::BoxSealError {
                error: format!("box encrypt error: {:?}", e),
            })?;

    let nonce_vec = Vec::from(nonce.as_slice());

    Ok((cipher_text, nonce_vec))
}

pub fn seal_box_hex(
    message: &str,
    sk_hex: &str,
    pk_hex: &str,
    nonce_hex: Option<&str>,
) -> Result<(String, String), APIError> {
    let (cipher_text, nonce) = seal_box(message, sk_hex, pk_hex, nonce_hex)?;

    let cipher_text_hex = encode(&cipher_text);
    let nonce_hex = encode(&nonce);

    Ok((cipher_text_hex, nonce_hex))
}

/// return a hex encoded ed25519 signature as raw byte vector
pub fn ed25519_sign_str(message: &str, sk_hex: &str) -> Result<Vec<u8>, APIError> {
    let sk_raw = decode_hex_with_length_check(&sk_hex, 32)?;

    let keypair =
        Ed25519KeyPair::from_seed_unchecked(&sk_raw).map_err(|e| APIError::SignatureKeyError {
            error: format!("ed25519 key rejected: {}", e),
        })?;

    let signature: Signature = keypair.sign(message.as_bytes());

    let sig_raw = Vec::from(signature.as_ref());

    Ok(sig_raw)
}

/// return a hex encoded ed25519 signature as hexified string
pub fn sign_string(message: &str, sk_hex: &str) -> Result<String, APIError> {
    let sig_raw = ed25519_sign_str(&message, &sk_hex)?;

    Ok(encode(&sig_raw))
}

pub fn ed25519_verify_str(message: &str, pk_hex: &str, sig_hex: &str) -> Result<bool, APIError> {
    let pk_raw = decode_hex_with_length_check(&pk_hex, 32)?;

    let sig = decode_hex_with_length_check(&sig_hex, 64)?;

    let peer_public_key = UnparsedPublicKey::new(&ED25519, &pk_raw);
    let verified = peer_public_key.verify(message.as_bytes(), sig.as_ref());

    Ok(verified.is_ok())
}

pub fn verify_signature(
    public_key_hex: &str,
    msg: &str,
    signature_hex: &str,
) -> Result<bool, APIError> {
    ed25519_verify_str(msg, public_key_hex, signature_hex)
}
