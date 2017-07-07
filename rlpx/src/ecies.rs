use util::{keccak256, pk2id};
use secp256k1::Message;
use secp256k1::ecdh::SharedSecret;
use secp256k1::key::{PublicKey, SecretKey};
use hash::SECP256K1;
use bigint::H256;

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
    pub fn create_auth(&self) -> [u8; AUTH_LEN] {
        let x = ecdh_x(&self.remote_public_key, &self.secret_key);
        let msg = Message::from_slice((x ^ self.nonce).as_ref()).unwrap();
        let sig = SECP256K1.sign(&msg, &self.ephemeral_secret_key).unwrap();
        let mut ret = [0u8; AUTH_LEN];

        ret[0..65].copy_from_slice(&sig[0..65]);
        ret[65..97].copy_from_slice(&keccak256(pk2id(&self.ephemeral_public_key).as_ref())[0..32]);
        ret[97..161].copy_from_slice(&pk2id(&self.public_key)[0..64]);
        ret[161..193].copy_from_slice(&self.nonce[0..32]);
        ret
    }
}
