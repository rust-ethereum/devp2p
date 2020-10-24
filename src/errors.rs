use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ECIESError {
    #[error("IO error")]
    IO(#[from] io::Error),
    #[error("tag check failure")]
    TagCheckFailed,
    #[error("invalid auth data")]
    InvalidAuthData,
    #[error("invalid ack data")]
    InvalidAckData,
    #[error("other")]
    Other(#[from] anyhow::Error),
}

impl From<ECIESError> for io::Error {
    fn from(error: ECIESError) -> Self {
        Self::new(io::ErrorKind::Other, format!("ECIES error: {:?}", error))
    }
}

impl From<k256::ecdsa::Error> for ECIESError {
    fn from(error: k256::ecdsa::Error) -> Self {
        Self::Other(error.into())
    }
}
