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
use rlpx::peer::{PeerStream, HelloMessage, CapabilityInfo};

const REMOTE_ID: &str = "428930fb9e8bb535dbcb142785d34c6dbfbb2d846b9cd98db91602dc844e139d0d69234a8f158c1d6da9ddd097fbaef248da95ec52849d07ac156feedd6b80fa";

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let client = PeerStream::connect(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        H512::from_str(REMOTE_ID).unwrap(),
        4, "etclient Rust/0.1.0".to_string(),
        vec![CapabilityInfo { name: "eth".to_string(), version: 62, length: 8 },
             CapabilityInfo { name: "eth".to_string(), version: 63, length: 17 }],
        0);
    core.run(client
             .and_then(|socket| socket.into_future().map_err(|(e, _)| e))
             .and_then(|(val, socket)| {
                 println!("val: {:?}", val);
                 future::ok(socket)
             })).unwrap();
}
