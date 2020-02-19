use crate::{
    errors::ECIESError,
    mac::MAC,
    util::{hmac_sha256, id2pk, keccak256, pk2id, sha256},
};
use bigint::{H128, H256, H512};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::{
    aessafe::{AesSafe128Encryptor, AesSafe256Encryptor},
    blockmodes::CtrMode,
    buffer::{RefReadBuffer, RefWriteBuffer},
    symmetriccipher::{Decryptor, Encryptor},
};
use rand::os::OsRng;
use secp256k1::{
    ecdh::SharedSecret,
    key::{PublicKey, SecretKey},
    Message, RecoverableSignature, RecoveryId, SECP256K1,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{convert::TryFrom, io};

const AUTH_LEN: usize = 65 /* signature with recovery */ + 32 /* keccak256 ephemeral */ +
    64 /* public key */ + 32 /* nonce */ + 1;

const ACK_LEN: usize = 64 /* public key */ + 32 /* nonce */ + 1;

fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    let shared = SharedSecret::new_raw(&SECP256K1, public_key, secret_key);
    H256::from(&shared[0..32])
}

fn concat_kdf(key_material: H256) -> H256 {
    const SHA256_BLOCK_SIZE: u32 = 64;
    const REPS: u32 = (32 + 7) * 8 / (SHA256_BLOCK_SIZE * 8);

    let mut buffers: Vec<u8> = Vec::new();
    for counter in 0..=REPS {
        let mut sha256 = Sha256::new();
        let mut tmp: Vec<u8> = Vec::new();
        tmp.write_u32::<BigEndian>(counter + 1).unwrap();
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

    remote_id: Option<H512>,

    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    ephemeral_shared_secret: Option<H256>,
    remote_ephemeral_public_key: Option<PublicKey>,

    nonce: H256,
    remote_nonce: Option<H256>,

    ingress_aes: Option<CtrMode<AesSafe256Encryptor>>,
    egress_aes: Option<CtrMode<AesSafe256Encryptor>>,
    ingress_mac: Option<MAC>,
    egress_mac: Option<MAC>,

    init_msg: Option<Vec<u8>>,
    remote_init_msg: Option<Vec<u8>>,

    body_size: Option<usize>,
}

impl ECIES {
    pub fn new_client(secret_key: SecretKey, remote_id: H512) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key)?;
        let remote_public_key = id2pk(remote_id)?;
        let nonce = H256::random();
        let (ephemeral_secret_key, ephemeral_public_key) =
            SECP256K1.generate_keypair(&mut OsRng::new()?)?;

        Ok(Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,

            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_msg: None,
            remote_init_msg: None,

            remote_id: Some(remote_id),

            body_size: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
        })
    }

    pub fn new_server(secret_key: SecretKey) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key)?;
        let nonce = H256::random();
        let (ephemeral_secret_key, ephemeral_public_key) =
            SECP256K1.generate_keypair(&mut OsRng::new()?)?;

        Ok(Self {
            secret_key,
            public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,

            remote_public_key: None,
            remote_ephemeral_public_key: None,
            remote_nonce: None,
            ephemeral_shared_secret: None,
            init_msg: None,
            remote_init_msg: None,

            remote_id: None,

            body_size: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
        })
    }

    pub fn remote_id(&self) -> H512 {
        self.remote_id.unwrap()
    }

    fn encrypt_message(&self, data: &[u8]) -> Result<Vec<u8>, ECIESError> {
        let secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new()?);
        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        let key = concat_kdf(x);
        let enc_key = H128::from(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        let iv = H128::random();
        let mut iv_encrypted = vec![0_u8; 16 + data.len()];
        iv_encrypted[0..16].copy_from_slice(iv.as_ref());

        let mut encryptor = CtrMode::new(
            AesSafe128Encryptor::new(enc_key.as_ref()),
            iv.as_ref().into(),
        );
        encryptor.encrypt(
            &mut RefReadBuffer::new(data),
            &mut RefWriteBuffer::new(&mut iv_encrypted[16..]),
            true,
        )?;

        let tag = hmac_sha256(mac_key.as_ref(), iv_encrypted.as_ref());
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key)?;

        let mut ret = vec![0_u8; 65 + 16 + data.len() + 32];
        ret[0..65].copy_from_slice(&public_key.serialize_vec(&SECP256K1, false));
        ret[65..(65 + 16 + data.len())].copy_from_slice(&iv_encrypted);
        ret[(65 + 16 + data.len())..].copy_from_slice(tag.as_ref());

        Ok(ret)
    }

    fn decrypt_message(&self, encrypted: &[u8]) -> Result<Vec<u8>, ECIESError> {
        let public_key = PublicKey::from_slice(&SECP256K1, &encrypted[0..65])?;
        let data_iv = &encrypted[65..(encrypted.len() - 32)];
        let tag = H256::from(&encrypted[(encrypted.len() - 32)..]);

        let x = ecdh_x(&public_key, &self.secret_key);
        let key = concat_kdf(x);
        let enc_key = H128::from(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        let check_tag = hmac_sha256(mac_key.as_ref(), data_iv);
        if check_tag != tag {
            return Err(ECIESError::TagCheckFailed);
        }

        let iv = &data_iv[0..16];
        let encrypted_data = &data_iv[16..];
        let mut decrypted_data = vec![0_u8; encrypted_data.len()];

        let mut encryptor = CtrMode::new(AesSafe128Encryptor::new(enc_key.as_ref()), iv.into());
        encryptor.decrypt(
            &mut RefReadBuffer::new(encrypted_data),
            &mut RefWriteBuffer::new(&mut decrypted_data),
            true,
        )?;

        Ok(decrypted_data)
    }

    fn create_auth_unencrypted(&self) -> Result<[u8; AUTH_LEN], ECIESError> {
        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        let msg = Message::from_slice((x ^ self.nonce).as_ref())?;
        let sig_rec = SECP256K1.sign_recoverable(&msg, &self.ephemeral_secret_key)?;
        let (rec, sig) = sig_rec.serialize_compact(&SECP256K1);
        let mut out = [0_u8; AUTH_LEN];

        out[0..64].copy_from_slice(&sig[0..64]);
        out[64] = u8::try_from(rec.to_i32()).expect("always u8");
        out[65..97].copy_from_slice(&keccak256(pk2id(&self.ephemeral_public_key).as_ref())[0..32]);
        out[97..161].copy_from_slice(&pk2id(&self.public_key)[0..64]);
        out[161..193].copy_from_slice(&self.nonce[0..32]);
        Ok(out)
    }

    pub fn create_auth(&mut self) -> Result<Vec<u8>, ECIESError> {
        let unencrypted = self.create_auth_unencrypted()?;
        let encrypted = self.encrypt_message(unencrypted.as_ref())?;
        self.init_msg = Some(encrypted.clone());
        Ok(encrypted)
    }

    fn parse_auth_unencrypted(&mut self, data: [u8; AUTH_LEN]) -> Result<(), ECIESError> {
        let sig_rec = RecoverableSignature::from_compact(
            &SECP256K1,
            &data[0..64],
            RecoveryId::from_i32(i32::from(data[64]))?,
        )?;
        let heid = H256::from(&data[65..97]);
        self.remote_id = Some(H512::from(&data[97..161]));
        self.remote_public_key = Some(id2pk(H512::from(&data[97..161]))?);
        self.remote_nonce = Some(H256::from(&data[161..193]));
        if data[193] != 0_u8 {
            return Err(ECIESError::InvalidAuthData);
        }

        let x = ecdh_x(self.remote_public_key.as_ref().unwrap(), &self.secret_key);
        let msg = Message::from_slice((x ^ self.remote_nonce.unwrap()).as_ref())?;
        self.remote_ephemeral_public_key = Some(SECP256K1.recover(&msg, &sig_rec)?);
        self.ephemeral_shared_secret = Some(ecdh_x(
            self.remote_ephemeral_public_key.as_ref().unwrap(),
            &self.ephemeral_secret_key,
        ));

        let check_heid =
            keccak256(pk2id(self.remote_ephemeral_public_key.as_ref().unwrap()).as_ref());
        if check_heid != heid {
            return Err(ECIESError::TagCheckFailed);
        }
        Ok(())
    }

    pub fn parse_auth(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(data.into());
        let unencrypted = self.decrypt_message(data)?;
        if unencrypted.len() != AUTH_LEN {
            return Err(ECIESError::InvalidAuthData);
        }
        let mut decrypted = [0_u8; AUTH_LEN];
        decrypted[..AUTH_LEN].clone_from_slice(&unencrypted[..AUTH_LEN]);
        self.parse_auth_unencrypted(decrypted)
    }

    fn create_ack_unencrypted(&self) -> [u8; ACK_LEN] {
        let mut ret = [0_u8; ACK_LEN];
        ret[0..64].copy_from_slice(pk2id(&self.ephemeral_public_key).as_ref());
        ret[64..96].copy_from_slice(self.nonce.as_ref());
        ret[96] = 0_u8;
        ret
    }

    pub fn create_ack(&mut self) -> Result<Vec<u8>, ECIESError> {
        let unencrypted = self.create_ack_unencrypted();
        let encrypted = self.encrypt_message(&unencrypted)?;
        self.init_msg = Some(encrypted.clone());
        self.setup_frame(true);
        Ok(encrypted)
    }

    fn parse_ack_unencrypted(&mut self, data: [u8; ACK_LEN]) -> Result<(), ECIESError> {
        self.remote_ephemeral_public_key = Some(id2pk(H512::from(&data[0..64]))?);
        self.remote_nonce = Some(H256::from(&data[64..96]));
        if data[96] != 0_u8 {
            return Err(ECIESError::InvalidAckData);
        }

        self.ephemeral_shared_secret = Some(ecdh_x(
            self.remote_ephemeral_public_key.as_ref().unwrap(),
            &self.ephemeral_secret_key,
        ));
        Ok(())
    }

    pub fn parse_ack(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(data.into());
        let unencrypted = self.decrypt_message(data)?;
        if unencrypted.len() != ACK_LEN {
            return Err(ECIESError::InvalidAckData);
        }
        let mut decrypted = [0_u8; ACK_LEN];
        decrypted[..ACK_LEN].clone_from_slice(&unencrypted[..ACK_LEN]);
        self.parse_ack_unencrypted(decrypted)?;
        self.setup_frame(false);
        Ok(())
    }

    fn setup_frame(&mut self, incoming: bool) {
        let h_nonce: H256 = if incoming {
            let mut hasher = Keccak256::new();
            hasher.input(self.nonce.as_ref());
            hasher.input(self.remote_nonce.unwrap().as_ref());
            H256::from(hasher.result().as_ref())
        } else {
            let mut hasher = Keccak256::new();
            hasher.input(self.remote_nonce.unwrap().as_ref());
            hasher.input(self.nonce.as_ref());
            H256::from(hasher.result().as_ref())
        };

        let iv = H128::default();
        let shared_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.input(h_nonce.as_ref());
            H256::from(hasher.result().as_ref())
        };

        let aes_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.input(shared_secret.as_ref());
            H256::from(hasher.result().as_ref())
        };
        self.ingress_aes = Some(CtrMode::new(
            AesSafe256Encryptor::new(aes_secret.as_ref()),
            iv.as_ref().into(),
        ));
        self.egress_aes = Some(CtrMode::new(
            AesSafe256Encryptor::new(aes_secret.as_ref()),
            iv.as_ref().into(),
        ));

        let mac_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.input(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.input(aes_secret.as_ref());
            H256::from(hasher.result().as_ref())
        };
        self.ingress_mac = Some(MAC::new(mac_secret));
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.nonce).as_ref());
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update(self.remote_init_msg.as_ref().unwrap());
        self.egress_mac = Some(MAC::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.remote_nonce.unwrap()).as_ref());
        self.egress_mac
            .as_mut()
            .unwrap()
            .update(self.init_msg.as_ref().unwrap());
    }

    pub fn create_header(&mut self, size: usize) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.write_uint::<BigEndian>(size as u64, 3).unwrap();
        let mut header = [0_u8; 16];
        header[0..3].copy_from_slice(buffer.as_ref());
        header[3..6].copy_from_slice([194_u8, 128_u8, 128_u8].as_ref());

        let mut encrypted = [0_u8; 16];
        self.egress_aes
            .as_mut()
            .unwrap()
            .encrypt(
                &mut RefReadBuffer::new(&header),
                &mut RefWriteBuffer::new(&mut encrypted),
                false,
            )
            .unwrap();
        self.egress_mac
            .as_mut()
            .unwrap()
            .update_header(encrypted.as_ref());
        let tag = self.egress_mac.as_mut().unwrap().digest();

        let mut ret = Vec::new();
        for item in &encrypted {
            ret.push(*item);
        }
        for item in tag.iter() {
            ret.push(*item);
        }
        ret
    }

    pub fn parse_header(&mut self, data: &[u8]) -> Result<usize, ECIESError> {
        let header = &data[0..16];
        let mac = H128::from(&data[16..32]);

        self.ingress_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckFailed);
        }

        let mut decrypted = [0_u8; 16];
        self.ingress_aes
            .as_mut()
            .unwrap()
            .decrypt(
                &mut RefReadBuffer::new(header),
                &mut RefWriteBuffer::new(&mut decrypted),
                false,
            )
            .unwrap();
        self.body_size = Some(
            usize::try_from(decrypted.as_ref().read_uint::<BigEndian>(3)?).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "32 bit systems are not supported")
            })?,
        );

        Ok(self.body_size.unwrap())
    }

    pub const fn auth_len() -> usize {
        65 + 16 + AUTH_LEN + 32
    }

    pub const fn ack_len() -> usize {
        65 + 16 + ACK_LEN + 32
    }

    pub const fn header_len() -> usize {
        32
    }

    pub fn body_len(&self) -> usize {
        let len = self.body_size.unwrap();
        (if len % 16 == 0 {
            len
        } else {
            (len / 16 + 1) * 16
        }) + 16
    }

    pub fn create_body(&mut self, data: &[u8]) -> Vec<u8> {
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };
        let mut data_padded = vec![0_u8; len];
        data_padded[..data.len()].clone_from_slice(&data[..]);
        let mut encrypted = vec![0_u8; len];
        self.egress_aes
            .as_mut()
            .unwrap()
            .encrypt(
                &mut RefReadBuffer::new(&data_padded),
                &mut RefWriteBuffer::new(&mut encrypted),
                false,
            )
            .unwrap();
        self.egress_mac
            .as_mut()
            .unwrap()
            .update_body(encrypted.as_ref());
        let tag = self.egress_mac.as_mut().unwrap().digest();
        let mut ret = vec![0_u8; len + 16];
        ret[0..len].copy_from_slice(encrypted.as_ref());
        ret[len..].copy_from_slice(tag.as_ref());
        ret
    }

    pub fn parse_body(&mut self, data: &[u8]) -> Result<Vec<u8>, ECIESError> {
        let body = &data[0..data.len() - 16];
        let mac = H128::from(&data[data.len() - 16..]);
        self.ingress_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckFailed);
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let mut ret = vec![0_u8; data.len() - 16];
        self.ingress_aes
            .as_mut()
            .unwrap()
            .decrypt(
                &mut RefReadBuffer::new(body),
                &mut RefWriteBuffer::new(&mut ret),
                false,
            )
            .unwrap();
        while ret.len() > size {
            ret.pop();
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::ECIES;
    use crate::util::pk2id;
    use rand::os::OsRng;
    use secp256k1::{
        key::{PublicKey, SecretKey},
        SECP256K1,
    };

    #[test]
    fn communicate() {
        let server_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());
        let server_public_key = PublicKey::from_secret_key(&SECP256K1, &server_secret_key).unwrap();
        let client_secret_key = SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap());

        let mut server_ecies = ECIES::new_server(server_secret_key).unwrap();
        let mut client_ecies =
            ECIES::new_client(client_secret_key, pk2id(&server_public_key)).unwrap();

        // Handshake
        let auth = client_ecies.create_auth().unwrap();
        assert_eq!(auth.len(), ECIES::auth_len());
        server_ecies.parse_auth(auth.as_ref()).unwrap();
        let ack = server_ecies.create_ack().unwrap();
        assert_eq!(ack.len(), ECIES::ack_len());
        client_ecies.parse_ack(ack.as_ref()).unwrap();

        let server_to_client_data = [0_u8, 1_u8, 2_u8, 3_u8, 4_u8];
        let client_to_server_data = [5_u8, 6_u8, 7_u8];

        // Test server to client 1
        let header = server_ecies.create_header(server_to_client_data.len());
        assert_eq!(header.len(), ECIES::header_len());
        client_ecies.parse_header(header.as_ref()).unwrap();
        let body = server_ecies.create_body(&server_to_client_data);
        assert_eq!(body.len(), client_ecies.body_len());
        let ret = client_ecies.parse_body(body.as_ref()).unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test client to server 1
        server_ecies
            .parse_header(
                client_ecies
                    .create_header(client_to_server_data.len())
                    .as_ref(),
            )
            .unwrap();
        let ret = server_ecies
            .parse_body(client_ecies.create_body(&client_to_server_data).as_ref())
            .unwrap();
        assert_eq!(ret, client_to_server_data);

        // Test server to client 2
        client_ecies
            .parse_header(
                server_ecies
                    .create_header(server_to_client_data.len())
                    .as_ref(),
            )
            .unwrap();
        let ret = client_ecies
            .parse_body(server_ecies.create_body(&server_to_client_data).as_ref())
            .unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test server to client 3
        client_ecies
            .parse_header(
                server_ecies
                    .create_header(server_to_client_data.len())
                    .as_ref(),
            )
            .unwrap();
        let ret = client_ecies
            .parse_body(server_ecies.create_body(&server_to_client_data).as_ref())
            .unwrap();
        assert_eq!(ret, server_to_client_data);

        // Test client to server 2
        server_ecies
            .parse_header(
                client_ecies
                    .create_header(client_to_server_data.len())
                    .as_ref(),
            )
            .unwrap();
        let ret = server_ecies
            .parse_body(client_ecies.create_body(&client_to_server_data).as_ref())
            .unwrap();
        assert_eq!(ret, client_to_server_data);

        // Test client to server 3
        server_ecies
            .parse_header(
                client_ecies
                    .create_header(client_to_server_data.len())
                    .as_ref(),
            )
            .unwrap();
        let ret = server_ecies
            .parse_body(client_ecies.create_body(&client_to_server_data).as_ref())
            .unwrap();
        assert_eq!(ret, client_to_server_data);
    }
}
