use secp256k1;
use std::io;
use crypto::symmetriccipher::SymmetricCipherError;

#[derive(Debug)]
pub enum ECIESError {
    SECP256K1(secp256k1::Error),
    IO(io::Error),
    Cipher(SymmetricCipherError),
    TagCheckFailed,
    InvalidAuthData,
    InvalidAckData,
}

impl From<io::Error> for ECIESError {
    fn from(error: io::Error) -> ECIESError {
        ECIESError::IO(error)
    }
}

impl From<SymmetricCipherError> for ECIESError {
    fn from(error: SymmetricCipherError) -> ECIESError {
        ECIESError::Cipher(error)
    }
}

impl From<secp256k1::Error> for ECIESError {
    fn from(error: secp256k1::Error) -> ECIESError {
        ECIESError::SECP256K1(error)
    }
}
