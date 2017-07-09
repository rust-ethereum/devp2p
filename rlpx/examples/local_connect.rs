extern crate rlpx;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_crypto;
extern crate etcommon_bigint;

#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

use etcommon_bigint::H512;
use etcommon_crypto::SECP256K1;
use tokio_core::reactor::Core;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::Future;
use std::str::FromStr;
use rlpx::peer::Peer;

const REMOTE_ID: &str = "88f3c9502af25f6e7b1269016b2147e6a68a39a91bd28203dd4763b5060ba6a66321a3e4a716b434b24f634c8a464f203d1efe83d814d170d7915e92bd06f55b";

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let client = Peer::connect_client(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        H512::from_str(REMOTE_ID).unwrap());
    core.run(client).unwrap();
}
