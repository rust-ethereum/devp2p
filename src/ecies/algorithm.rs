use crate::{
    errors::ECIESError,
    mac::MAC,
    util::{hmac_sha256, id2pk, keccak256, pk2id, sha256},
};
use aes_ctr::{
    stream_cipher::{NewStreamCipher, StreamCipher},
    Aes128Ctr, Aes256Ctr,
};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use digest::Digest;
use ethereum_types::{H128, H256, H512};
use generic_array::GenericArray;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use libsecp256k1::{Message, PublicKey, RecoveryId, SecretKey, Signature};
use rand::rngs::OsRng;
use sha2::Sha256;
use sha3::Keccak256;
use std::{convert::TryFrom, io};

const AUTH_LEN: usize = 65 /* signature with recovery */ + 32 /* keccak256 ephemeral */ +
    64 /* public key */ + 32 /* nonce */ + 1;

const ACK_LEN: usize = 64 /* public key */ + 32 /* nonce */ + 1;

fn ecdh_x(public_key: PublicKey, secret_key: SecretKey) -> H256 {
    H256::from_slice(
        k256::elliptic_curve::ecdh::PublicKey::from(
            (k256::ProjectivePoint::from(
                k256::elliptic_curve::AffinePoint::<k256::Secp256k1>::from_encoded_point(
                    &k256::elliptic_curve::ecdh::PublicKey::from_bytes(
                        public_key.serialize().as_ref(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ) * k256::SecretKey::from_bytes(secret_key.serialize())
                .unwrap()
                .secret_scalar())
            .to_affine(),
        )
        .x()
        .as_slice(),
    )
}

fn kdf(secret: H256, s1: &[u8], dest: &mut [u8]) {
    // SEC/ISO/Shoup specify counter size SHOULD be equivalent
    // to size of hash output, however, it also notes that
    // the 4 bytes is okay. NIST specifies 4 bytes.
    let mut ctr = 1_u32;
    let mut written = 0_usize;
    while written < dest.len() {
        let mut hasher = Sha256::default();
        let ctrs = [
            (ctr >> 24) as u8,
            (ctr >> 16) as u8,
            (ctr >> 8) as u8,
            ctr as u8,
        ];
        hasher.update(&ctrs);
        hasher.update(secret.as_bytes());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}

#[derive(Debug)]
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

    ingress_aes: Option<Aes256Ctr>,
    egress_aes: Option<Aes256Ctr>,
    ingress_mac: Option<MAC>,
    egress_mac: Option<MAC>,

    init_msg: Option<Vec<u8>>,
    remote_init_msg: Option<Vec<u8>>,

    body_size: Option<usize>,
}

impl ECIES {
    pub fn new_client(secret_key: SecretKey, remote_id: H512) -> Result<Self, ECIESError> {
        let public_key = PublicKey::from_secret_key(&secret_key);
        let remote_public_key = id2pk(remote_id)?;
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::random(&mut OsRng);
        let ephemeral_public_key = PublicKey::from_secret_key(&ephemeral_secret_key);

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
        let public_key = PublicKey::from_secret_key(&secret_key);
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::random(&mut OsRng);
        let ephemeral_public_key = PublicKey::from_secret_key(&ephemeral_secret_key);

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
        let secret_key = SecretKey::random(&mut OsRng);
        let x = ecdh_x(self.remote_public_key.unwrap(), secret_key);
        let mut key = [0_u8; 32];
        kdf(x, &[], &mut key);

        let enc_key = H128::from_slice(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        let iv = H128::random();
        let mut iv_encrypted = vec![0_u8; 16 + data.len()];
        iv_encrypted[0..16].copy_from_slice(iv.as_ref());

        let mut encryptor = Aes128Ctr::new(enc_key.as_ref().into(), iv.as_ref().into());

        let mut encrypted = data.to_vec();
        encryptor.encrypt(&mut encrypted);
        iv_encrypted[16..].copy_from_slice(&encrypted);

        let tag = hmac_sha256(mac_key.as_ref(), iv_encrypted.as_ref());
        let public_key = PublicKey::from_secret_key(&secret_key);

        let mut ret = vec![0_u8; 65 + 16 + data.len() + 32];
        ret[0..65].copy_from_slice(&public_key.serialize());
        ret[65..(65 + 16 + data.len())].copy_from_slice(&iv_encrypted);
        ret[(65 + 16 + data.len())..].copy_from_slice(tag.as_ref());

        Ok(ret)
    }

    fn decrypt_message(&self, encrypted: &[u8]) -> Result<Vec<u8>, ECIESError> {
        let public_key = PublicKey::parse_slice(&encrypted[0..65], None)?;
        let data_iv = &encrypted[65..(encrypted.len() - 32)];
        let tag = H256::from_slice(&encrypted[(encrypted.len() - 32)..]);

        let x = ecdh_x(public_key, self.secret_key);
        let mut key = [0_u8; 32];
        kdf(x, &[], &mut key);
        let enc_key = H128::from_slice(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        let check_tag = hmac_sha256(mac_key.as_ref(), data_iv);
        if check_tag != tag {
            return Err(ECIESError::TagCheckFailed);
        }

        let iv = &data_iv[0..16];
        let encrypted_data = &data_iv[16..];
        let mut decrypted_data = encrypted_data.to_vec();

        let mut decryptor = Aes128Ctr::new(enc_key.as_ref().into(), iv.into());
        decryptor.decrypt(&mut decrypted_data);

        Ok(decrypted_data)
    }

    fn create_auth_unencrypted(&self) -> Result<[u8; AUTH_LEN], ECIESError> {
        let x = ecdh_x(self.remote_public_key.unwrap(), self.secret_key);
        let msg = Message::parse_slice((x ^ self.nonce).as_ref())?;
        let (sig, rec) = libsecp256k1::sign(&msg, &self.ephemeral_secret_key);
        let mut out = [0_u8; AUTH_LEN];

        out[0..64].copy_from_slice(&sig.serialize());
        out[64] = rec.into();
        out[65..97]
            .copy_from_slice(keccak256(pk2id(&self.ephemeral_public_key).as_bytes()).as_bytes());
        out[97..161].copy_from_slice(pk2id(&self.public_key).as_bytes());
        out[161..193].copy_from_slice(self.nonce.as_bytes());
        Ok(out)
    }

    pub fn create_auth(&mut self) -> Result<Vec<u8>, ECIESError> {
        let unencrypted = self.create_auth_unencrypted()?;
        let encrypted = self.encrypt_message(unencrypted.as_ref())?;
        self.init_msg = Some(encrypted.clone());
        Ok(encrypted)
    }

    fn parse_auth_unencrypted(&mut self, data: [u8; AUTH_LEN]) -> Result<(), ECIESError> {
        let signature = Signature::parse_slice(&data[0..64])?;
        let rec = RecoveryId::parse(data[64])?;
        let heid = H256::from_slice(&data[65..97]);
        self.remote_id = Some(H512::from_slice(&data[97..161]));
        self.remote_public_key = Some(id2pk(H512::from_slice(&data[97..161]))?);
        self.remote_nonce = Some(H256::from_slice(&data[161..193]));
        if data[193] != 0_u8 {
            return Err(ECIESError::InvalidAuthData);
        }

        let x = ecdh_x(self.remote_public_key.unwrap(), self.secret_key);
        let msg = Message::parse_slice((x ^ self.remote_nonce.unwrap()).as_ref())?;
        self.remote_ephemeral_public_key = Some(libsecp256k1::recover(&msg, &signature, &rec)?);
        self.ephemeral_shared_secret = Some(ecdh_x(
            self.remote_ephemeral_public_key.unwrap(),
            self.ephemeral_secret_key,
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
        self.remote_ephemeral_public_key = Some(id2pk(H512::from_slice(&data[0..64]))?);
        self.remote_nonce = Some(H256::from_slice(&data[64..96]));
        if data[96] != 0_u8 {
            return Err(ECIESError::InvalidAckData);
        }

        self.ephemeral_shared_secret = Some(ecdh_x(
            self.remote_ephemeral_public_key.unwrap(),
            self.ephemeral_secret_key,
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
            hasher.update(self.nonce.as_ref());
            hasher.update(self.remote_nonce.unwrap().as_ref());
            H256::from(hasher.finalize().as_ref())
        } else {
            let mut hasher = Keccak256::new();
            hasher.update(self.remote_nonce.unwrap().as_ref());
            hasher.update(self.nonce.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        let iv = H128::default();
        let shared_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(h_nonce.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        let aes_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(shared_secret.as_ref());
            H256::from(hasher.finalize().as_ref())
        };
        self.ingress_aes = Some(Aes256Ctr::new(
            aes_secret.as_ref().into(),
            iv.as_ref().into(),
        ));
        self.egress_aes = Some(Aes256Ctr::new(
            aes_secret.as_ref().into(),
            iv.as_ref().into(),
        ));

        let mac_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(aes_secret.as_ref());
            H256::from(hasher.finalize().as_ref())
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

        let mut encrypted = GenericArray::from(header);
        self.egress_aes.as_mut().unwrap().encrypt(&mut encrypted);
        self.egress_mac
            .as_mut()
            .unwrap()
            .update_header(encrypted.as_ref());
        let tag = self.egress_mac.as_mut().unwrap().digest();

        let mut ret = Vec::new();
        for item in &encrypted {
            ret.push(*item);
        }
        for item in tag.as_bytes() {
            ret.push(*item);
        }
        ret
    }

    pub fn parse_header(&mut self, data: &[u8]) -> Result<usize, ECIESError> {
        let header = &data[0..16];
        let mac = H128::from_slice(&data[16..32]);

        self.ingress_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckFailed);
        }

        let mut decrypted = header.to_vec();
        self.ingress_aes.as_mut().unwrap().decrypt(&mut decrypted);
        self.body_size = Some(
            usize::try_from(decrypted.as_slice().read_uint::<BigEndian>(3)?).map_err(|_| {
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
        let mut encrypted = data_padded;
        self.egress_aes.as_mut().unwrap().encrypt(&mut encrypted);
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
        let mac = H128::from_slice(&data[data.len() - 16..]);
        self.ingress_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckFailed);
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let mut ret = body.to_vec();
        self.ingress_aes.as_mut().unwrap().decrypt(&mut ret);
        while ret.len() > size {
            ret.pop();
        }
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::{ecdh_x, ECIES};
    use crate::util::*;
    use hex_literal::hex;
    use libsecp256k1::{PublicKey, SecretKey};
    use rand::rngs::OsRng;

    #[test]
    fn ecdh() {
        let our_secret_key = SecretKey::parse(&hex!(
            "202a36e24c3eb39513335ec99a7619bad0e7dc68d69401b016253c7d26dc92f8"
        ))
        .unwrap();
        let remote_public_key = id2pk(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666").into()).unwrap();

        assert_eq!(
            ecdh_x(remote_public_key, our_secret_key),
            hex!("821ce7e01ea11b111a52b2dafae8a3031a372d83bdf1a78109fa0783c2b9d5d3").into()
        )
    }

    #[test]
    fn communicate() {
        let server_secret_key = SecretKey::random(&mut OsRng);
        let server_public_key = PublicKey::from_secret_key(&server_secret_key);
        let client_secret_key = SecretKey::random(&mut OsRng);

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
