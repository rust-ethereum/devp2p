use std::io;

#[derive(Debug)]
pub enum ECIESError {
    SECP256K1(k256::ecdsa::Error),
    IO(io::Error),
    TagCheckFailed,
    InvalidAuthData,
    InvalidAckData,
}

impl From<ECIESError> for io::Error {
    fn from(error: ECIESError) -> Self {
        Self::new(io::ErrorKind::Other, format!("ECIES error: {:?}", error))
    }
}

impl From<io::Error> for ECIESError {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<k256::ecdsa::Error> for ECIESError {
    fn from(error: k256::ecdsa::Error) -> Self {
        Self::SECP256K1(error)
    }
}
