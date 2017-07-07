use util::{keccak256, pk2id, id2pk};
use secp256k1::{Message, RecoverableSignature, RecoveryId};
use secp256k1::ecdh::SharedSecret;
use secp256k1::key::{PublicKey, SecretKey};
use hash::SECP256K1;
use sha2::{Digest, Sha256};
use bigint::{H512, H256, H128};
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
    ephemeral_shared_secret: Option<H256>,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: H256,
    remote_nonce: Option<H256>,

    ingress_aes: CtrMode<AesSafe256Encryptor>,
    egress_aes: CtrMode<AesSafe256Encryptor>,

    init_msg: Option<Vec<u8>>,
    remote_init_msg: Option<Vec<u8>>,

    body_size: Option<usize>,
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
        let key = concat_kdf(x);
        let ekey = H128::from(&key[0..16]);
        let mkey = H256::from(&sha256(&key[16..32]));

        let iv = H128::random();
        let mut iv_encrypted = vec![0u8; 16 + data.len()];
        iv_encrypted[0..16].copy_from_slice(iv.as_ref());
        aes_encrypt(ekey, iv, data, &iv_encrypted[16..]);

        let tag = hmac_sha256(mkey, iv_encrypted);
        let public_key = PublicKey::from_secret_key(
            &SECP256K1, &secret_key).unwrap();

        let ret = vec![0u8; 65 + 16 + data.len() + 32];
        ret[0..65].copy_from_slice(public_key.serialize_vec(&SECP256K1, false));
        ret[65..(65 + 16 + data.len())].copy_from_slice(iv_encrypted);
        ret[(65 + 16 + data.len())..].copy_from_slice(tag);

        ret
    }

    pub fn decrypt_message(&self, encrypted: &[u8]) -> Vec<u8> {
        let public_key = PublicKey::from_slice(encrypted[0..65]);
        let data_iv = encrypted[65..(encrypted.len() - 32)];
        let tag = H256::from(encrypted[(encrypted.len() - 32)..]);

        let x = ecdh_x(self.private_key, public_key);
        let key = concat_kdf(x);
        let ekey = H128::from(key[0..16]);
        let mkey = H256::from(&sha256(&key[16..32]));

        let check_tag = hmac_sha256(mkey, data_iv);
        assert!(check_tag == tag);

        let iv = data_iv[0..16];
        let encrypted_data = data_iv[16..];
        let decrypted_data = vec![0u8; encrypted_data.len()];
        aes_decrypt(ekey, iv, encrypted_data, decrypted_data);

        decrypted_data
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

    pub fn create_auth(&self) -> Vec<u8> {
        let unencrypted = self.create_auth_unencrypted();
        let encrypted = self.encrypt_message(unencrypted);
        self.init_msg = encrypted.clone();
        init_msg
    }

    pub fn parse_auth_unencrypted(&mut self, data: [u8; AUTH_LEN]) {
        let sig_rec = RecoverableSignature::from_compact(
            &SECP256K1, data[0..64], RecoveryId::from_i32(sig[64] as i32)).unwrap();
        let heid = H256::from(&data[65..97]);
        self.remote_public_key = Some(id2pk(data[97..161]));
        self.remote_nonce = Some(H256::from(data[161..193]));
        assert!(data[193] == 0u8);

        let x = ecdh_x(self.remote_public_key, self.private_key);
        let msg = Message::from_slice((x ^ self.remote_nonce)).unwrap();
        self.remote_ephemeral_public_key = Some(SECP256K1.recover(msg, sig_rec).unwrap());
        self.ephemeral_shared_secret = Some(
            ecdh_x(self.remote_ephemeral_public_key, self.ephemeral_private_key));

        let check_heid = keccak256(pk2id(self.remote_ephemeral_public_key));
        assert!(heid == check_heid);
    }

    pub fn parse_auth(&mut self, data: Vec<u8>) {
        self.remote_init_msg = data.clone();
        let unencrypted = self.decrypt_message(&data);
        assert!(unencrypted.len() == AUTH_LEN);
        let data = [u8; AUTH_LEN];
        for i in 0..AUTH_LEN {
            data[i] = unencrypted[i];
        }
        self.parse_auth_unencrypted(unencrypted)
    }

    pub fn create_ack_unencrypted(&self) -> [u8; ACK_LEN] {
        let mut ret = [0u8; ACK_LEN];
        ret[0..64].copy_from_slice(pk2id(self.ephemeral_public_key));
        ret[64..96].copy_from_slice(self.nonce);
        ret[96] = 0u8;
        ret
    }

    pub fn create_ack(&self) -> Vec<u8> {
        let unencrypted = self.create_ack_unencrypted();
        let encrypted = self.encrypt_message(unencrypted);
        self.init_msg = encrypted.clone();
        self.setup_frame();
        encrypted
    }

    pub fn parse_ack_unencrypted(&mut self, data: [u8; ACK_LEN]) {
        self.remote_ephemeral_public_key = id2pk(H256::from(data[0..64]));
        self.remote_nonce = H128::from(data[64..96]);
        assert!(data[96] == 0u8);

        self.ephemeral_shared_secret = Some(
            ecdh_x(self.remote_ephemeral_public_key, self.ephemeral_private_key));
    }

    pub fn parse_ack(&mut self, data: Vec<u8>) {
        self.remote_init_msg = data.clone();
        let unencrypted = self.decrypt_message(&data);
        assert!(unencrypted.len() == ACK_LEN);
        let data = [u8; ACK_LEN];
        for i in 0..ACK_LEN {
            data[i] = unencrypted[i];
        }
        self.parse_ack_unencrypted(unencrypted);
        self.setup_frame();
    }

    pub fn setup_frame(incoming: bool) {
        let h_nonce = if incoming {
            let hasher = Keccak256::new();
            hasher.input(self.nonce);
            hasher.input(self.remote_nonce);
            hasher.result()
        } else {
            let hasher = Keccak256::new();
            hasher.input(self.remote_nonce);
            hasher.input(self.nonce);
            hasher.result()
        };

        let iv = H128::default();
        let shared_secret = {
            let hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret);
            hasher.input(h_nonce);
            hasher.result()
        };

        let aes_secret = {
            let hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret);
            hasher.input(shared_secret);
            hasher.result()
        };
        self.ingress_aes = CtrMode::new(AesSafe256Encryptor::new(aes_secret), iv.into());
        self.egress_aes = CtrMode::new(AesSafe256Encryptor::new(aes_secret), iv.into());

        let mac_secret = {
            let hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret);
            hasher.input(aes_secret);
            hasher.result()
        };
        self.ingress_mac = Mac::new(mac_secret);
        self.ingress_mac.update(mac_secret ^ self.nonce);
        self.ingress_mac.update(self.remote_init_msg);
        self.egress_mac = Mac::new(mac_secret);
        self.egress_mac.update(mac_secret ^ self.remote_nonce);
        self.egress_mac.update(self.init_msg);
    }

    pub fn create_header(&mut self, size: usize) -> Vec<u8> {
        let buffer = Vec::new();
        buffer.write_uint(size, 3);
        let header = [0u8; 16];
        header[0..3].copy_from_slice(buffer);
        let encrypted = [0u8; 16];
        self.egress_aes.encrypt(header, encrypted);
        self.egress_mac.update_header(encrypted);
        let tag = self.egress_mac.digest();

        let ret = Vec::new();
        ret.write_all(encrypted);
        ret.write_all(tag);
        ret
    }

    pub fn parse_header(&mut self, data: &[u8]) -> usize {
        let header = data[0..16];
        let mac = data[16..32];

        self.ingress_mac.update_header(header);
        let check_mac = self.ingress.digest();
        assert!(check_mac == mac);

        let decrypted = [0u8; 16];
        self.ingress_aes.decrypt(header, decrypted);
        self.body_size = decrypted.read_uint(3).unwrap() as usize;
        self.body_size
    }

    pub fn create_body(&mut self, data: &[u8]) -> Vec<u8> {
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };
        let encrypted = vec![0u8; len];
        self.egress_aes.encrypt(data, encrypted);
        self.egress_mac.update_body(encrypted);
        let tag = self.egress_mac.digest();
        let ret = vec![0u8; len + 16];
        ret[0..len].copy_from_slice(encrypted);
        ret[len..].copy_from_slice(tag);
        ret
    }

    pub fn parse_body(&mut self, data: &[u8]) -> Vec<u8> {
        let body = data[0..data.len()-16];
        let mac = data[data.len()-16..];
        self.ingress_mac.update_body(body);
        let check_mac = self.ingress_mac.digest();
        assert!(check_mac == mac);

        let size = self.body_size;
        self.body_size = None;
        let ret = vec![0u8; data.len()-16];
        self.ingress_aes.decrypt(body, ret);
        while ret.len() > size {
            ret.pop();
        }
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
        let ecies = ECIES::new_client(secret_key, pk2id(&remote_public_key));
        let auth = ecies.create_auth();
    }
}
