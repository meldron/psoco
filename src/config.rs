use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::crypto::{BoxSecretKey, ED25519PublicKey, FromHex, SecretBoxKey};
pub use crate::errors::*;

fn default_as_false() -> bool {
    false
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub api_key_id: String,
    pub api_key_private_key: String,
    pub api_key_secret_key: String,
    pub server_url: String,
    pub server_signature: String,
    #[serde(default = "default_as_false")]
    pub danger_disable_tls: bool,
}

#[allow(dead_code)]
impl Config {
    pub fn save(&self, path: PathBuf) -> Result<(), APIError> {
        let toml = toml::to_string_pretty(&self)?;
        fs::write(path, toml)?;
        Ok(())
    }
    pub fn load(path: PathBuf) -> Result<Self, APIError> {
        let toml_raw = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&toml_raw)?;

        config.verify()?;

        Ok(config)
    }
    fn verify(&self) -> Result<(), APIError> {
        let mut errors: Vec<String> = Vec::new();

        if let Err(e) = Uuid::parse_str(&self.api_key_id) {
            errors.push(format!("api_key_id error: {}", e).to_string());
        }

        if let Err(e) = ED25519PublicKey::from_hex(&self.server_signature) {
            errors.push(format!("server_signature error: {}", e).to_string());
        };

        if let Err(e) = BoxSecretKey::from_hex(&self.api_key_private_key) {
            errors.push(format!("api_key_private_key error: {}", e).to_string());
        };

        if let Err(e) = SecretBoxKey::from_hex(&self.api_key_secret_key) {
            errors.push(format!("api_key_secret_key error: {}", e).to_string());
        };

        if !errors.is_empty() {
            return Err(APIError::ConfigError {
                error: errors.join("\n"),
            });
        }

        Ok(())
    }
}
