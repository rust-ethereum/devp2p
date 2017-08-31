extern crate rlpx;
extern crate rand;
extern crate secp256k1;
extern crate bigint;
extern crate rlp;
extern crate hexutil;

#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

use bigint::H512;
use tokio_core::reactor::Core;
use secp256k1::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use rlpx::{RLPxStream, CapabilityInfo};
use rlpx::ecies::ECIESStream;

const REMOTE_ID: &str = "d02c7c6d49c668f750cf6c007b4a9cc96be08c335d3e027afa110f86c48192725aa2e8a60c581044c7c489fee45a3d0acbbfe4d10eb1717bc6b3374364bf895d";

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let mut client = RLPxStream::new(
        &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        4, "etclient Rust/0.1.0".to_string(),
        vec![CapabilityInfo { name: "eth", version: 62, length: 8 },
             CapabilityInfo { name: "eth", version: 63, length: 17 }],
        None).unwrap();

    client.add_peer(&addr, H512::from_str(REMOTE_ID).unwrap());

    core.run(client.into_future().map_err(|(e, _)| e)
             .and_then(|(val, client)| {
                 println!("val: {:?}", val);
                 future::ok(client)
             })).unwrap();
}
