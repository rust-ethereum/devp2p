use util::{keccak256, pk2id, id2pk};
use secp256k1::Message;
use secp256k1::ecdh::SharedSecret;
use secp256k1::key::{PublicKey, SecretKey};
use hash::SECP256K1;
use bigint::{H512, H256};
use rand::os::OsRng;

const AUTH_LEN: usize =
    65 /* signature with recovery */ + 32 /* keccak256 ephemeral */ +
    64 /* public key */ + 32 /* nonce */ + 1;

fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    let shared = SharedSecret::new(&SECP256K1, public_key, secret_key);
    H256::from(&shared[0..32])
}

pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    remote_public_key: PublicKey,

    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,

    nonce: H256,
}

impl ECIES {
    pub fn new(secret_key: SecretKey, remote_id: H512) -> Self {
        let public_key = PublicKey::from_secret_key(
            &SECP256K1, &secret_key).unwrap();
        let remote_public_key = id2pk(remote_id);
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let ephemeral_public_key = PublicKey::from_secret_key(
            &SECP256K1, &ephemeral_secret_key).unwrap();

        ECIES {
            secret_key, public_key, remote_public_key, ephemeral_secret_key,
            ephemeral_public_key, nonce
        }
    }

    pub fn create_auth(&self) -> [u8; AUTH_LEN] {
        let x = ecdh_x(&self.remote_public_key, &self.secret_key);
        let msg = Message::from_slice((x ^ self.nonce).as_ref()).unwrap();
        let sig_rec = SECP256K1.sign_recoverable(&msg, &self.ephemeral_secret_key).unwrap();
        let (rec, sig) = sig_rec.serialize_compact(&SECP256K1);
        let mut ret = [0u8; AUTH_LEN];

        ret[0..64].copy_from_slice(&sig[0..64]);
        ret[64] = rec.to_i32() as u8;
        ret[65..97].copy_from_slice(&keccak256(pk2id(&self.ephemeral_public_key).as_ref())[0..32]);
        ret[97..161].copy_from_slice(&pk2id(&self.public_key)[0..64]);
        ret[161..193].copy_from_slice(&self.nonce[0..32]);
        ret
    }
}

#[cfg(test)]
mod tests {
    use util::{keccak256, pk2id, id2pk};
    use secp256k1::Message;
    use secp256k1::ecdh::SharedSecret;
    use secp256k1::key::{PublicKey, SecretKey};
    use hash::SECP256K1;
    use bigint::{H512, H256};
    use rand::os::OsRng;
    use super::ECIES;

    #[test]
    fn handshake_auth() {
        let remote_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let remote_public_key = PublicKey::from_secret_key(
            &SECP256K1, &remote_secret_key).unwrap();
        let secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let ecies = ECIES::new(secret_key, pk2id(&remote_public_key));
        let auth = ecies.create_auth();
    }
}
