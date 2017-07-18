extern crate devp2p;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_crypto;
extern crate etcommon_bigint as bigint;
extern crate etcommon_rlp as rlp;

#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate env_logger;

use etcommon_crypto::SECP256K1;
use tokio_core::reactor::Core;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use std::time::Duration;
use devp2p::ETHStream;
use devp2p::dpt::DPTNode;
use bigint::{H256, U256, H512};

const GENESIS_HASH: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
const GENESIS_DIFFICULTY: usize = 17179869184;
const NETWORK_ID: usize = 1;

const BOOTSTRAP_ID: &str = "1b3e4c04a87a7ac3d075162b26d7c860be8d556b1d47698d19d8741411fc2ecb35cded5edf4f0daac96f3760d772aeb03bb938e39c46ab1a1cce3b485798fb6b";
const BOOTSTRAP_IP: &str = "127.0.0.1";
const BOOTSTRAP_PORT: u16 = 30303;

fn main() {
    env_logger::init();

    let addr = "0.0.0.0:50505".parse().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let mut client = ETHStream::new(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        "etclient Rust/0.1.0".to_string(), 1,
        H256::from_str(GENESIS_HASH).unwrap(),
        H256::from_str(GENESIS_HASH).unwrap(),
        U256::from(GENESIS_DIFFICULTY),
        vec![DPTNode {
            address: BOOTSTRAP_IP.parse().unwrap(),
            tcp_port: BOOTSTRAP_PORT,
            udp_port: BOOTSTRAP_PORT,
            id: H512::from_str(BOOTSTRAP_ID).unwrap(),
        }],
        Duration::new(5, 0),
        Duration::new(2, 0),
        5).unwrap();

    loop {
        let (val, new_client) = core.run(client.into_future().map_err(|(e, _)| e)).unwrap();
        client = new_client;
        println!("received {:?}, active {}", val, client.active_peers().len());
    }
}
