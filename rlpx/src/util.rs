use ethereum_types::{H256, H512};
use hmac::{Hmac, Mac, NewMac};
use libsecp256k1::{self, PublicKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let out = hasher.finalize();
    H256::from(out.as_ref())
}

pub fn sha256(data: &[u8]) -> H256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    H256::from(out.as_ref())
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).unwrap();
    hmac.update(input);
    H256::from_slice(&*hmac.finalize().into_bytes())
}

pub fn pk2id(pk: &PublicKey) -> H512 {
    H512::from_slice(&pk.serialize()[1..])
}

pub fn id2pk(id: H512) -> Result<PublicKey, libsecp256k1::Error> {
    let s: [u8; 64] = id.into();
    let mut sp: Vec<u8> = s.as_ref().into();
    let mut r = vec![0x04_u8];
    r.append(&mut sp);
    PublicKey::parse_slice(r.as_ref(), None)
}

#[cfg(test)]
mod tests {
    use crate::util::*;
    use libsecp256k1::{PublicKey, SecretKey};
    use rand::rngs::OsRng;

    #[test]
    fn pk2id2pk() {
        let prikey = SecretKey::random(&mut OsRng);
        let pubkey = PublicKey::from_secret_key(&prikey);
        assert_eq!(pubkey, id2pk(pk2id(&pubkey)).unwrap());
    }
}
