use crate::types::*;
use ethereum_types::H256;
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use k256::{ecdsa::VerifyKey, EncodedPoint};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::fmt::{self, Formatter};

pub fn keccak256(data: &[u8]) -> H256 {
    H256::from(Keccak256::digest(data).as_ref())
}

pub fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

pub fn hmac_sha256(key: &[u8], input: &[u8], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).unwrap();
    hmac.update(input);
    hmac.update(auth_data);
    H256::from_slice(&*hmac.finalize().into_bytes())
}

pub fn pk2id(pk: &VerifyKey) -> PeerId {
    PeerId::from_slice(&*EncodedPoint::from(pk).to_untagged_bytes().unwrap())
}

pub fn id2pk(id: PeerId) -> Result<VerifyKey, signature::Error> {
    VerifyKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(
        GenericArray::from_slice(id.as_ref()),
    ))
}

pub fn hex_debug<T: AsRef<[u8]>>(s: &T, f: &mut Formatter) -> fmt::Result {
    f.write_str(&hex::encode(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use rand::thread_rng;

    #[test]
    fn pk2id2pk() {
        let prikey = SigningKey::random(thread_rng());
        let pubkey = prikey.verify_key();
        assert_eq!(pubkey, id2pk(pk2id(&pubkey)).unwrap());
    }
}
