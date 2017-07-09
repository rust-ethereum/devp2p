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
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use rlpx::ecies::ECIESStream;

const REMOTE_ID: &str = "2b7ec30900da8c9353a4aa0431ea9be4b7d361a6a71d5c7240f85f06b5d821b423e2673ed9d0c5134e7a6ceba010c0b9d2837c192a7bb14eb06681f0ed2f89fe";

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let client = ECIESStream::connect(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        H512::from_str(REMOTE_ID).unwrap());
    core.run(client
             .and_then(|client| {
                 client.into_future().map_err(|(e, _)| e)
             })
             .and_then(|(val, client)| {
                 println!("next value: {:?}", val);
                 future::ok(client)
             })
    ).unwrap();
}
