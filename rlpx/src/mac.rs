use bigint::{H128, H256};
use crypto::aessafe::AesSafe256Encryptor;
use crypto::blockmodes::EcbEncryptor;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::symmetriccipher::Encryptor;
use sha3::{Digest, Keccak256};

pub struct MAC {
    secret: H256,
    hasher: Keccak256,
}

impl MAC {
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.input(data)
    }

    pub fn update_header(&mut self, data: &[u8]) {
        let mut aes = EcbEncryptor::new(AesSafe256Encryptor::new(self.secret.as_ref()), NoPadding);
        let mut encrypted = vec![0u8; data.len()];
        aes.encrypt(
            &mut RefReadBuffer::new(self.digest().as_ref()),
            &mut RefWriteBuffer::new(encrypted.as_mut()),
            true,
        );
        for i in 0..data.len() {
            encrypted[i] = encrypted[i] ^ data[i];
        }
        self.hasher.input(encrypted.as_ref());
    }

    pub fn update_body(&mut self, data: &[u8]) {
        self.hasher.input(data);
        let prev = self.digest();
        let mut aes = EcbEncryptor::new(AesSafe256Encryptor::new(self.secret.as_ref()), NoPadding);
        let mut encrypted = vec![0u8; 16];
        aes.encrypt(
            &mut RefReadBuffer::new(self.digest().as_ref()),
            &mut RefWriteBuffer::new(encrypted.as_mut()),
            true,
        );
        for i in 0..16 {
            encrypted[i] = encrypted[i] ^ prev[i];
        }
        self.hasher.input(encrypted.as_ref());
    }

    pub fn digest(&self) -> H128 {
        H128::from(&self.hasher.clone().result()[0..16])
    }
}
