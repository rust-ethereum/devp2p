extern crate devp2p;
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
use std::time::Duration;
use devp2p::DevP2PStream;
use devp2p::rlpx::CapabilityInfo;
use devp2p::dpt::DPTNode;

const BOOTSTRAP_ID: &str = "42d8f29d1db5f4b2947cd5c3d76c6d0d3697e6b9b3430c3d41e46b4bb77655433aeedc25d4b4ea9d8214b6a43008ba67199374a9b53633301bca0cd20c6928ab";
const BOOTSTRAP_IP: &str = "104.155.176.151";
const BOOTSTRAP_PORT: u16 = 30303;

fn main() {
    let addr = "0.0.0.0:30303".parse().unwrap();

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
        Duration::new(60, 0),
        Duration::new(10, 0),
        5).unwrap();

    loop {
        let (val, new_client) = core.run(client.into_future().map_err(|(e, _)| e)).unwrap();
        client = new_client;
    }
}
