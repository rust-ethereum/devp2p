extern crate rlpx;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_crypto;
extern crate etcommon_bigint;
extern crate etcommon_rlp as rlp;

#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

use etcommon_bigint::H512;
use etcommon_crypto::SECP256K1;
use tokio_core::reactor::Core;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use rlpx::ecies::ECIESStream;
use rlpx::peer::{PeerStream, HelloMessage, Capability};

const REMOTE_ID: &str = "50706e6374d2f9953de6a29070cd0c6abc91a35311914d9c71b7e97085984ebbadefca391cc3bd52f2ac7d36dd034ed2d3fc86622626ef71d19ef92544706169";

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let client = PeerStream::connect(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        H512::from_str(REMOTE_ID).unwrap(),
        4, "etclient Rust/0.1.0".to_string(),
        vec![Capability { name: "eth".to_string(), version: 62 },
             Capability { name: "eth".to_string(), version: 63 }],
        0);
    core.run(client).unwrap();
}
