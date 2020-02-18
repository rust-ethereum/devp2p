use bigint::{H256, H512};
use crypto::{hmac::Hmac, mac::Mac};
use secp256k1::{self, key::PublicKey, SECP256K1};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.input(data);
    let out = hasher.result();
    H256::from(out.as_ref())
}

pub fn sha256(data: &[u8]) -> H256 {
    use sha2::Sha256;

    let mut hasher = Sha256::new();
    hasher.input(data);
    let out = hasher.result();
    H256::from(out.as_ref())
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> H256 {
    use crypto::sha2::Sha256;

    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(input);
    let mut result = [0u8; 32];
    hmac.raw_result(&mut result);
    H256::from(result.as_ref())
}

pub fn pk2id(pk: &PublicKey) -> H512 {
    let v = pk.serialize_vec(&SECP256K1, false);
    debug_assert!(v.len() == 65);
    H512::from(&v[1..])
}

pub fn id2pk(id: H512) -> Result<PublicKey, secp256k1::Error> {
    let s: [u8; 64] = id.into();
    let mut sp: Vec<u8> = s.as_ref().into();
    let mut r = vec![0x04u8];
    r.append(&mut sp);
    PublicKey::from_slice(&SECP256K1, r.as_ref())
}

#[cfg(test)]
mod tests {
    use crate::util::*;
    use rand::os::OsRng;
    use secp256k1::{
        key::{PublicKey, SecretKey},
        SECP256K1,
    };

    #[test]
    fn pk2id2pk() {
        let prikey = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let pubkey = PublicKey::from_secret_key(&SECP256K1, &prikey).unwrap();
        assert_eq!(pubkey, id2pk(pk2id(&pubkey)).unwrap());
    }
}
