use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum APIError {
    #[snafu(display("Hex decode Error: {}", error))]
    FromHexError { error: hex::FromHexError },
    #[snafu(display("Length error: {}", error))]
    CryptoLengthError { error: String },
    #[snafu(display("JSON error: {}", error))]
    JSONError {
        error: serde_json::error::Error,
        backtrace: snafu::Backtrace,
    },
    #[snafu(display("Could not open Box"))]
    BoxError {},
    #[snafu(display("FromUtf8Error: {}", error))]
    FromUtf8Error { error: std::string::FromUtf8Error },
    #[snafu(display("Server Verification failed"))]
    ServerVerificationError {},
    #[snafu(display("Opening secretbox failed"))]
    SecretBoxError {},
    #[snafu(display("Could not get: {}", missing))]
    OwnFolderError { missing: String },
    #[snafu(display("Could not get: {}", missing))]
    SharedFolderError { missing: String },
    #[snafu(display("Could not get: {}", missing))]
    OwnItemError { missing: String },
    #[snafu(display("reqwest error: {}", error))]
    ReqwuestError { error: reqwest::Error },
    #[snafu(display("SessionBoxSecretKeyError"))]
    SessionBoxSecretKeyError {},
    #[snafu(display("SessionSecretboxSecretKeyError"))]
    SessionSecretboxSecretKeyError {},
    #[snafu(display("TokenError"))]
    TokenError {},
    #[snafu(display("URLError: {}", error))]
    URLError { error: reqwest::UrlError },
    #[snafu(display("CallError {} ({}): {}", status, reason, content))]
    CallError {
        status: String,
        reason: String,
        content: String,
    },
    #[snafu(display("LoginInfoMissingItemError: {}", missing))]
    LoginInfoMissingItemError { missing: String },
    #[snafu(display("TOML serialize Error: {}", error))]
    TOMLSerializeError { error: toml::ser::Error },
    #[snafu(display("TOML deserialize Error: {}", error))]
    TOMLDeserializeError { error: toml::de::Error },
    #[snafu(display("IO Error: {}", error))]
    IOError { error: std::io::Error },
    #[snafu(display("Config Error: \n{}", error))]
    ConfigError { error: String },
}

impl std::convert::From<std::io::Error> for APIError {
    fn from(error: std::io::Error) -> Self {
        APIError::IOError { error }
    }
}

impl std::convert::From<toml::ser::Error> for APIError {
    fn from(error: toml::ser::Error) -> Self {
        APIError::TOMLSerializeError { error }
    }
}

impl std::convert::From<toml::de::Error> for APIError {
    fn from(error: toml::de::Error) -> Self {
        APIError::TOMLDeserializeError { error }
    }
}

impl std::convert::From<hex::FromHexError> for APIError {
    fn from(error: hex::FromHexError) -> Self {
        APIError::FromHexError { error }
    }
}

impl std::convert::From<serde_json::error::Error> for APIError {
    fn from(error: serde_json::error::Error) -> Self {
        APIError::JSONError {
            error,
            backtrace: snafu::Backtrace::new(),
        }
    }
}

impl std::convert::From<std::string::FromUtf8Error> for APIError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        APIError::FromUtf8Error { error }
    }
}

impl std::convert::From<reqwest::Error> for APIError {
    fn from(error: reqwest::Error) -> Self {
        APIError::ReqwuestError { error }
    }
}

impl std::convert::From<reqwest::UrlError> for APIError {
    fn from(error: reqwest::UrlError) -> Self {
        APIError::URLError { error }
    }
}
