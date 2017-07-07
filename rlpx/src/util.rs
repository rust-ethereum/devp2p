use hash::SECP256K1;
use sha3::{Digest, Keccak256};
use secp256k1::key::PublicKey;
use bigint::{H256, H512};
use crypto::blockmodes::CtrMode;
use crypto::aessafe::AesSafe128Encryptor;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};

pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.input(data);
    let out = hasher.result();
    H256::from(out.as_ref())
}

pub fn sha256(data: &[u8]) -> H256 {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let out = hasher.result();
    H256::from(out.as_ref())
}

pub fn aes_encrypt(key: &[u8], iv: &[u8], plain: &[u8], dest: &mut [u8]) {
    let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(key), iv.into());
    encryptor.encrypt(&mut RefReadBuffer::new(plain), &mut RefWriteBuffer::new(dest), true).unwrap();
}

pub fn aes_decrypt(key: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) {
    let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(key), iv.into());
    encryptor.decrypt(&mut RefReadBuffer::new(encrypted), &mut RefWriteBuffer::new(dest), true).unwrap();
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> H256 {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(input);
    let mut result = [0u8; 32];
    hmac.raw_result(&mut result);
    H256::from(&result)
}

pub fn pk2id(pk: &PublicKey) -> H512 {
    let v = pk.serialize_vec(&SECP256K1, false);
    debug_assert!(v.len() == 65);
    H512::from(&v[1..])
}

pub fn id2pk(id: H512) -> PublicKey {
    let s: [u8; 64] = id.into();
    let mut sp: Vec<u8> = s.as_ref().into();
    let mut r = vec![0x04u8];
    r.append(&mut sp);
    PublicKey::from_slice(&SECP256K1, r.as_ref()).unwrap()
}

#[cfg(test)]
mod tests {
    use rand::os::OsRng;
    use hash::SECP256K1;
    use secp256k1::key::{SecretKey, PublicKey};
    use util::*;

    #[test]
    fn pk2id2pk() {
        let prikey = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let pubkey = PublicKey::from_secret_key(&SECP256K1, &prikey).unwrap();
        assert_eq!(pubkey, id2pk(pk2id(&pubkey)));
    }
}
