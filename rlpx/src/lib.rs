extern crate secp256k1;
extern crate rand;
extern crate sha3;
extern crate sha2;
extern crate byteorder;
extern crate crypto;
extern crate etcommon_bigint as bigint;
extern crate etcommon_crypto as hash;
extern crate etcommon_rlp as rlp;
extern crate etcommon_util;
extern crate bytes;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

mod util;
pub mod ecies;
pub mod peer;
mod mac;
mod errors;

use bigint::H512;
use util::pk2id;
use hash::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
