extern crate dpt;
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
use dpt::{DPTMessage, DPTNode, DPTStream};

const REMOTE_ID: &str = "42d8f29d1db5f4b2947cd5c3d76c6d0d3697e6b9b3430c3d41e46b4bb77655433aeedc25d4b4ea9d8214b6a43008ba67199374a9b53633301bca0cd20c6928ab";

fn main() {
    let addr = "0.0.0.0:50505".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let mut client = DPTStream::new(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        vec![DPTNode {
            address: "104.155.176.151".parse().unwrap(),
            tcp_port: 30303,
            udp_port: 30303,
            id: H512::from_str(REMOTE_ID).unwrap(),
        }], 0).unwrap();

    let result = core.run(client.send(DPTMessage::RequestNewPeer)
                          .and_then(|client| {
                              client.into_future().map_err(|(e, _)| e)
                          })
                          .and_then(|(val, client)| {
                              println!("new peer: {:?}", val);
                              future::ok(client)
                          }));

    if result.is_err() {
        println!("err: {:?}", result.err());
    }
}
