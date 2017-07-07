extern crate secp256k1;
extern crate rand;
extern crate sha3;
extern crate sha2;
extern crate byteorder;
extern crate etcommon_bigint as bigint;
extern crate etcommon_hash as hash;
extern crate etcommon_util;

mod util;
mod ecies;
mod peer;

use bigint::H512;
use util::pk2id;
use hash::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};

#[derive(Debug, Clone)]
pub struct Capability {
    pub name: String,
    pub version: usize,
    pub length: usize,
}

pub struct RLPx {
    secret_key: SecretKey,
    id: H512,
    timeout: usize,
    max_peers: usize,
    client_id: String,
    capabilities: Vec<Capability>,
    listen_port: Option<usize>,
}

impl RLPx {
    pub fn with_options(
        secret_key: SecretKey, capabilities: &[Capability], listen_port: Option<usize>,
        timeout: usize, max_peers: usize, client_id: String
    ) -> Self {
        Self {
            secret_key, timeout, max_peers, listen_port, client_id,
            capabilities: capabilities.into(),
            id: pk2id(&PublicKey::from_secret_key(&SECP256K1, &secret_key).unwrap())
        }
    }

    pub fn new(
        secret_key: SecretKey, capabilities: &[Capability], listen_port: Option<usize>
    ) -> Self {
        Self::with_options(secret_key, capabilities, listen_port,
                           10 * 1000, 10,
                           format!("Rust etclient/${}",
                                   option_env!("CARGO_PKG_VERSION").unwrap_or("0.0")))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
