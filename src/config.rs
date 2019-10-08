use std::io;
use std::io::Write;
use std::fs;
use std::path::PathBuf;

use reqwest::Url;
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

fn read_from_stdin(name: &str, validate: &dyn Fn(&str) -> Result<(), String>) -> String {
    let mut value: String;

    loop {
        value = String::new();
        print!("{}: ", name);
        io::stdout().flush().expect("could not flush");
        if let Err(e) = io::stdin().read_line(&mut value) {
            eprintln!("Error reading '{}' from stdin: {}", name, e);
            continue;
        }

        value = value.trim().to_owned();

        if let Err(e) = validate(&value) {
            eprintln!("Error reading '{}' from stdin: {}", name, e);
            continue;
        }

        break;
    }

    value
}

#[allow(dead_code)]
impl Config {
    pub fn from_stdin() -> Self {
        let api_key_id = read_from_stdin("api_key_id", &Config::validate_api_key_id);
        let api_key_private_key =
            read_from_stdin("api_key_private_key", &Config::validate_api_key_private_key);
        let api_key_secret_key =
            read_from_stdin("api_key_secret_key", &Config::validate_api_key_secret_key);
        let server_url = read_from_stdin("server_url", &Config::validate_server_url);
        let server_signature =
            read_from_stdin("server_signature", &Config::validate_server_signature);

        Config {
            api_key_id,
            api_key_private_key,
            api_key_secret_key,
            server_url,
            server_signature,
            danger_disable_tls: false,
        }
    }

    pub fn default() -> Self {
         Config {
            api_key_id: "00c0ffee-babe-dead-beef-dec0de000000".to_owned(),
            api_key_private_key: "1234567890123456789012345678901234567890123456789012345678901234".to_owned(),
            api_key_secret_key: "4321098765432109876543210987654321098765432109876543210987654321".to_owned(),
            server_url: "https://www.psono.pw/server".to_owned(),
            server_signature: "a16301bd25e3a445a83b279e7091ea91d085901933f310fdb1b137db9676de59".to_owned(),
            danger_disable_tls: false,
        }       
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), APIError> {
        let toml = toml::to_string_pretty(&self)?;
        fs::write(path, toml)?;
        Ok(())
    }
    pub fn load(path: &PathBuf) -> Result<Self, APIError> {
        let toml_raw = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&toml_raw)?;

        config.verify()?;

        Ok(config)
    }

    pub fn load_unverified(path: &PathBuf) -> Result<Self, APIError> {
        let toml_raw = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&toml_raw)?;
        Ok(config)
    }

    pub fn validate_api_key_id(api_key_id: &str) -> Result<(), String> {
        Uuid::parse_str(api_key_id)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn validate_server_signature(server_signature: &str) -> Result<(), String> {
        ED25519PublicKey::from_hex(server_signature)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn validate_api_key_private_key(api_key_private_key: &str) -> Result<(), String> {
        BoxSecretKey::from_hex(api_key_private_key)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn validate_api_key_secret_key(api_key_secret_key: &str) -> Result<(), String> {
        SecretBoxKey::from_hex(api_key_secret_key)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn validate_server_url(server_url: &str) -> Result<(), String> {
        Url::parse(server_url)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn verify(&self) -> Result<(), APIError> {
        let mut errors: Vec<String> = Vec::new();

        if let Err(e) = Config::validate_api_key_id(&self.api_key_id) {
            errors.push(format!("api_key_id error: {}", e).to_string());
        }

        if let Err(e) = Config::validate_server_signature(&self.server_signature) {
            errors.push(format!("server_signature error: {}", e).to_string());
        };

        if let Err(e) = Config::validate_api_key_private_key(&self.api_key_private_key) {
            errors.push(format!("api_key_private_key error: {}", e).to_string());
        };

        if let Err(e) = Config::validate_api_key_secret_key(&self.api_key_secret_key) {
            errors.push(format!("api_key_secret_key error: {}", e).to_string());
        };

        if let Err(e) = Config::validate_server_url(&self.server_url) {
            errors.push(format!("server_url error: {}", e).to_string());
        };

        if !errors.is_empty() {
            return Err(APIError::ConfigError {
                error: errors.join("\n"),
            });
        }

        Ok(())
    }
}
