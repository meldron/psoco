use serde::{Deserialize, Serialize};
use serde_json::ser::to_string;

pub use crate::errors::*;

pub use crate::crypto::create_session_keys_hex;
pub use crate::crypto::open_box;
pub use crate::crypto::open_secret_box;
pub use crate::crypto::sign_string;
pub use crate::crypto::verify_signature;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientInfo {
    pub api_key_id: String,
    pub device_description: String,
    pub session_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientInfoSigned {
    pub info: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub username: String,
    pub public_key: String,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub private_key_nonce: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default)]
    pub secret_key_nonce: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginInfoEncrypted {
    pub login_info: String,
    pub login_info_signature: String,
    pub login_info_nonce: String,
    pub server_session_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginInfo {
    pub token: String,
    pub session_secret_key: String,
    pub api_key_restrict_to_secrets: bool,
    pub api_key_allow_insecure_access: bool,
    pub api_key_read: bool,
    pub api_key_write: bool,
    pub user: User,
}

impl LoginInfoEncrypted {
    fn decrypt(&self, session_sk_hex: &str) -> Result<(LoginInfo), APIError> {
        decrypt_login_info(
            &self.login_info,
            &self.login_info_nonce,
            &self.server_session_public_key,
            session_sk_hex,
        )
    }

    fn verify(&self, server_signature_hex: &str) -> Result<bool, APIError> {
        verify_signature(
            server_signature_hex,
            &self.login_info,
            &self.login_info_signature,
        )
    }

    pub fn open(
        &self,
        server_signature_hex: &str,
        session_sk_hex: &str,
    ) -> Result<(LoginInfo), APIError> {
        let verified = self.verify(server_signature_hex)?;

        if !verified {
            return Err(APIError::ServerVerificationError {});
        }

        let login_info = self.decrypt(session_sk_hex)?;

        Ok(login_info)
    }
}

impl LoginInfo {
    pub fn open_private_key(&self, api_secret_key_hex: &str) -> Result<String, APIError> {
        let private_key_encrypted_hex =
            self.user
                .private_key
                .as_ref()
                .ok_or(APIError::LoginInfoMissingItemError {
                    missing: "private_key".to_owned(),
                })?;
        let private_key_nonce_hex =
            self.user
                .private_key_nonce
                .as_ref()
                .ok_or(APIError::LoginInfoMissingItemError {
                    missing: "private_key_nonce".to_owned(),
                })?;

        let private_key_raw = open_secret_box(
            &private_key_encrypted_hex,
            &private_key_nonce_hex,
            &api_secret_key_hex,
        )?;

        let private_key = String::from_utf8(private_key_raw)?;

        Ok(private_key)
    }
    pub fn open_secret_key(&self, api_secret_key_hex: &str) -> Result<String, APIError> {
        let secret_key_encrypted_hex =
            self.user
                .secret_key
                .as_ref()
                .ok_or(APIError::LoginInfoMissingItemError {
                    missing: "secret_key".to_owned(),
                })?;
        let secret_key_nonce_hex =
            self.user
                .secret_key_nonce
                .as_ref()
                .ok_or(APIError::LoginInfoMissingItemError {
                    missing: "secret_key_nonce".to_owned(),
                })?;

        let secret_key_raw = open_secret_box(
            &secret_key_encrypted_hex,
            &secret_key_nonce_hex,
            &api_secret_key_hex,
        )?;

        let secret_key = String::from_utf8(secret_key_raw)?;

        Ok(secret_key)
    }
}

pub fn create_client_info_with_session_sk(
    api_private_key_hex: &str,
    api_key_id: &str,
) -> Result<(String, ClientInfoSigned), APIError> {
    let (session_pk_hex, session_sk_hex) = create_session_keys_hex();

    let client_info = ClientInfo {
        api_key_id: api_key_id.to_owned(),
        device_description: "psoco".to_owned(),
        session_public_key: session_pk_hex,
    };

    let client_info_serialized = to_string(&client_info)?;

    let signature_hex = sign_string(&client_info_serialized, &api_private_key_hex)?;

    let client_info_signed = ClientInfoSigned {
        info: client_info_serialized,
        signature: signature_hex,
    };

    Ok((session_sk_hex, client_info_signed))
}

pub fn decrypt_login_info(
    login_info_hex: &str,
    nonce_hex: &str,
    server_session_pk_hex: &str,
    session_sk_hex: &str,
) -> Result<LoginInfo, APIError> {
    let login_info_raw = open_box(
        &login_info_hex,
        &nonce_hex,
        &server_session_pk_hex,
        &session_sk_hex,
    )?;
    let login_info: LoginInfo = serde_json::from_slice(&login_info_raw)?;
    Ok(login_info)
}
