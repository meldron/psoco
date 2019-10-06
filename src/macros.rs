macro_rules! from_hex {
    ($T:ty, $n:expr) => {
        impl FromHex for $T {
            fn from_hex(bs: &str) -> Result<$T, APIError> {
                let raw = decode(&bs)?;
                <$T>::from_slice(&raw).ok_or(APIError::CryptoLengthError {
                    error: $n.to_owned(),
                })
            }
        }
    };
}
