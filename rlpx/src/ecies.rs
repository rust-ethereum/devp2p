use util::{keccak256, pk2id, id2pk};
use secp256k1::{Message, RecoverableSignature, RecoveryId};
use secp256k1::ecdh::SharedSecret;
use secp256k1::key::{PublicKey, SecretKey};
use hash::SECP256K1;
use sha2::{Digest, Sha256};
use bigint::{H512, H256};
use rand::os::OsRng;
use byteorder::{BigEndian, WriteBytesExt};

const AUTH_LEN: usize =
    65 /* signature with recovery */ + 32 /* keccak256 ephemeral */ +
    64 /* public key */ + 32 /* nonce */ + 1;

const ACK_LEN: usize =
    64 /* public key */ + 32 /* nonce */ + 1;

fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    let shared = SharedSecret::new(&SECP256K1, public_key, secret_key);
    H256::from(&shared[0..32])
}

fn concat_kdf(key_material: H256) -> H256 {
    const SHA256BlockSize: usize = 64;
    const reps: usize = (32 + 7) * 8 / (SHA256BlockSize * 8);

    let mut buffers: Vec<u8> = Vec::new();
    for counter in 0..(reps+1) {
        let mut sha256 = Sha256::new();
        let mut tmp: Vec<u8> = Vec::new();
        tmp.write_u32::<BigEndian>(counter as u32).unwrap();
        sha256.input(&tmp);
        sha256.input(&key_material);
        buffers.append(&mut sha256.result().as_ref().into());
    }

    H256::from(&buffers[0..32])
}

pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    remote_public_key: Option<PublicKey>,

    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: H256,
    remote_nonce: Option<H256>,
}

impl ECIES {
    pub fn new_client(secret_key: SecretKey, remote_id: H512) -> Self {
        let public_key = PublicKey::from_secret_key(
            &SECP256K1, &secret_key).unwrap();
        let remote_public_key = id2pk(remote_id);
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let ephemeral_public_key = PublicKey::from_secret_key(
            &SECP256K1, &ephemeral_secret_key).unwrap();

        ECIES {
            secret_key, public_key, ephemeral_secret_key,
            ephemeral_public_key, nonce,

            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            remote_nonce: None,
        }
    }

    pub fn new_server(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(
            &SECP256K1, &secret_key).unwrap();
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let ephemeral_public_key = PublicKey::from_secret_key(
            &SECP256K1, &ephemeral_secret_key).unwrap();

        ECIES {
            secret_key, public_key, ephemeral_secret_key,
            ephemeral_public_key, nonce,

            remote_public_key: None,
            remote_ephemeral_public_key: None,
            remote_nonce: None,
        }
    }

    pub fn encrypt_message(&self, data: &[u8]) -> Vec<u8> {
        let secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        unimplemented!()
    }

    pub fn create_auth_unencrypted(&self) -> [u8; AUTH_LEN] {
        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
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

    // pub fn parse_auth_unencrypted(&mut self, data: [u8; AUTH_LEN]) {
    //     let sig_rec = RecoverableSignature::from_compact(
    //         &SECP256K1, data[0..64], RecoveryId::from_i32(sig[64] as i32)).unwrap();
    //     let heid = H256::from(&data[65..97]);
    // }
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
        let ecies = ECIES::new_client(secret_key, pk2id(&remote_public_key));
        let auth = ecies.create_auth();
    }
}
