extern crate devp2p;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_crypto;
extern crate etcommon_bigint;
extern crate etcommon_rlp as rlp;

#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate env_logger;

use etcommon_bigint::H512;
use etcommon_crypto::SECP256K1;
use tokio_core::reactor::Core;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use std::time::Duration;
use devp2p::DevP2PStream;
use devp2p::rlpx::CapabilityInfo;
use devp2p::dpt::DPTNode;

const BOOTSTRAP_ID: &str = "0e6e864a545fa1f22364ec781a4e2673a8c7e9d4fb02dbef02aeee46f1db4b9ea820f4479c0136cbc0a0e30501c2eba123eb7c16df45b539b69231db083edaf0";
const BOOTSTRAP_IP: &str = "127.0.0.1";
const BOOTSTRAP_PORT: u16 = 30303;

fn main() {
    env_logger::init();

    let addr = "0.0.0.0:50505".parse().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let mut client = DevP2PStream::new(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        4, "etclient Rust/0.1.0".to_string(),
        vec![CapabilityInfo { name: "eth", version: 62, length: 8 },
             CapabilityInfo { name: "eth", version: 63, length: 17 }],
        vec![DPTNode {
            address: BOOTSTRAP_IP.parse().unwrap(),
            tcp_port: BOOTSTRAP_PORT,
            udp_port: BOOTSTRAP_PORT,
            id: H512::from_str(BOOTSTRAP_ID).unwrap(),
        }],
        Duration::new(600, 0),
        Duration::new(700, 0),
        5,
        Duration::new(5, 0)).unwrap();

    loop {
        let (val, new_client) = core.run(client.into_future().map_err(|(e, _)| e)).unwrap();
        client = new_client;
        println!("received {:?}", val);
    }
}
