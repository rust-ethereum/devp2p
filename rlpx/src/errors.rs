use crypto::symmetriccipher::SymmetricCipherError;
use std::io;

#[derive(Debug)]
pub enum ECIESError {
    SECP256K1(secp256k1::Error),
    IO(io::Error),
    Cipher(SymmetricCipherError),
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

impl From<SymmetricCipherError> for ECIESError {
    fn from(error: SymmetricCipherError) -> Self {
        Self::Cipher(error)
    }
}

impl From<secp256k1::Error> for ECIESError {
    fn from(error: secp256k1::Error) -> Self {
        Self::SECP256K1(error)
    }
}
