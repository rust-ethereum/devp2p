pub struct MAC {
    secret: H256,
    hasher: Keccak256,
}

impl MAC {
    pub fn new(secret: H256) -> Self {
        Self { secret }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.input(data)
    }

    pub fn update_header(&mut self, data: &[u8]) {
        let aes = EcbEncryptor::new(AesSafe256Encryptor::new(self.secret, NoPadding));
        let encrypted = aes.update(self.digest());
        self.hasher.input(encrypted ^ data);
    }

    pub fn update_body(&mut self, data: &[u8]) {
        self.hasher.input(data);
        let prev = self.digest();
        let aes = EcbEncryptor::new(AesSafe256Encryptor::new(self.secret, NoPadding));
        let encrypted = aes.update(self.digest());
        self.hasher.update(encrypted ^ prev);
    }

    pub fn digest() -> H128 {
        H128::from(self.hasher.clone().result()[0..16])
    }
}
