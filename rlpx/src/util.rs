use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;
use bigint::H512;

pub fn pk2id(secp: &Secp256k1, pk: &PublicKey) -> H512 {
    let v = pk.serialize_vec(secp, false);
    debug_assert!(v.len() == 65);
    H512::from(&v[1..])
}

pub fn id2pk(secp: &Secp256k1, id: H512) -> PublicKey {
    let s: [u8; 64] = id.into();
    let mut sp: Vec<u8> = s.as_ref().into();
    let mut r = vec![0x04u8];
    r.append(&mut sp);
    PublicKey::from_slice(secp, r.as_ref()).unwrap()
}

#[cfg(test)]
mod tests {
    use rand::os::OsRng;
    use secp256k1::Secp256k1;
    use secp256k1::key::{SecretKey, PublicKey};
    use util::*;

    #[test]
    fn pk2id2pk() {
        let secp = Secp256k1::new();
        let prikey = SecretKey::new(&secp, &mut OsRng::new().unwrap());
        let pubkey = PublicKey::from_secret_key(&secp, &prikey).unwrap();
        assert_eq!(pubkey, id2pk(&secp, pk2id(&secp, &pubkey)));
    }
}
