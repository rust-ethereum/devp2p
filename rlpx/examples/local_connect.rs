extern crate rlpx;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_hash;
extern crate etcommon_bigint;

#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;

use etcommon_bigint::H512;
use etcommon_hash::SECP256K1;
use tokio_core::reactor::Core;
use tokio_proto::{TcpClient, TcpServer};
use rlpx::ecies::{ECIESServerProto, ECIESClientProto, ECIESValue};
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::Future;
use tokio_service::Service;
use std::str::FromStr;

fn main() {
    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let client = TcpClient::new(
        ECIESClientProto::new(
            SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()), H512::from_str("a0e5760cbe9bf16572a9b84e5906c6c53b9e0e7a08b3ed6d13798ea4cfcf9c8794c214ef9ede4433ba70041f09d605900ff5d8b5e67962d7e0e0dde3c2a62dbc"
            ).unwrap()))
        .connect(&addr, &handle)
        .map(|client_service| client_service);
    core.run(client.and_then(|client| {
        client.call(ECIESValue::Auth).
            and_then(|res| { println!("{:?}", res); Ok(()) })
    })).unwrap();
}
