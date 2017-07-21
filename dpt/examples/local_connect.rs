extern crate dpt;
extern crate rand;
extern crate secp256k1;
extern crate etcommon_crypto;
extern crate etcommon_bigint;
extern crate etcommon_rlp as rlp;
extern crate url;

#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

#[macro_use]
extern crate log;
extern crate env_logger;

use etcommon_bigint::H512;
use etcommon_crypto::SECP256K1;
use tokio_core::reactor::{Core, Timeout};
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use dpt::{DPTMessage, DPTNode, DPTStream};
use url::Url;
use std::time::{Instant, Duration};

// const BOOTSTRAP_NODES: [&str; 10] = [
//     "enode://e809c4a2fec7daed400e5e28564e23693b23b2cc5a019b612505631bbe7b9ccf709c1796d2a3d29ef2b045f210caf51e3c4f5b6d3587d43ad5d6397526fa6179@174.112.32.157:30303",
//     "enode://6e538e7c1280f0a31ff08b382db5302480f775480b8e68f8febca0ceff81e4b19153c6f8bf60313b93bef2cc34d34e1df41317de0ce613a201d1660a788a03e2@52.206.67.235:30303",
//     "enode://5fbfb426fbb46f8b8c1bd3dd140f5b511da558cd37d60844b525909ab82e13a25ee722293c829e52cb65c2305b1637fa9a2ea4d6634a224d5f400bfe244ac0de@162.243.55.45:30303",
//     "enode://42d8f29d1db5f4b2947cd5c3d76c6d0d3697e6b9b3430c3d41e46b4bb77655433aeedc25d4b4ea9d8214b6a43008ba67199374a9b53633301bca0cd20c6928ab@104.155.176.151:30303",
//     "enode://814920f1ec9510aa9ea1c8f79d8b6e6a462045f09caa2ae4055b0f34f7416fca6facd3dd45f1cf1673c0209e0503f02776b8ff94020e98b6679a0dc561b4eba0@104.154.136.117:30303",
//     "enode://72e445f4e89c0f476d404bc40478b0df83a5b500d2d2e850e08eb1af0cd464ab86db6160d0fde64bd77d5f0d33507ae19035671b3c74fec126d6e28787669740@104.198.71.200:30303",
//     "enode://5cd218959f8263bc3721d7789070806b0adff1a0ed3f95ec886fb469f9362c7507e3b32b256550b9a7964a23a938e8d42d45a0c34b332bfebc54b29081e83b93@35.187.57.94:30303",
//     "enode://39abab9d2a41f53298c0c9dc6bbca57b0840c3ba9dccf42aa27316addc1b7e56ade32a0a9f7f52d6c5db4fe74d8824bcedfeaecf1a4e533cacb71cf8100a9442@144.76.238.49:30303",
//     "enode://f50e675a34f471af2438b921914b5f06499c7438f3146f6b8936f1faeb50b8a91d0d0c24fb05a66f05865cd58c24da3e664d0def806172ddd0d4c5bdbf37747e@144.76.238.49:30306",
//     "enode://6dd3ac8147fa82e46837ec8c3223d69ac24bcdbab04b036a3705c14f3a02e968f7f1adfcdb002aacec2db46e625c04bf8b5a1f85bb2d40a479b3cc9d45a444af@104.237.131.102:30303"
// ];

// const BOOTSTRAP_NODES: [&str; 8] = [
//     "enode://e809c4a2fec7daed400e5e28564e23693b23b2cc5a019b612505631bbe7b9ccf709c1796d2a3d29ef2b045f210caf51e3c4f5b6d3587d43ad5d6397526fa6179@174.112.32.157:30303",
// 	"enode://6e538e7c1280f0a31ff08b382db5302480f775480b8e68f8febca0ceff81e4b19153c6f8bf60313b93bef2cc34d34e1df41317de0ce613a201d1660a788a03e2@52.206.67.235:30303",
// 	"enode://5fbfb426fbb46f8b8c1bd3dd140f5b511da558cd37d60844b525909ab82e13a25ee722293c829e52cb65c2305b1637fa9a2ea4d6634a224d5f400bfe244ac0de@162.243.55.45:30303",
// 	"enode://42d8f29d1db5f4b2947cd5c3d76c6d0d3697e6b9b3430c3d41e46b4bb77655433aeedc25d4b4ea9d8214b6a43008ba67199374a9b53633301bca0cd20c6928ab@104.155.176.151:30303",
// 	"enode://814920f1ec9510aa9ea1c8f79d8b6e6a462045f09caa2ae4055b0f34f7416fca6facd3dd45f1cf1673c0209e0503f02776b8ff94020e98b6679a0dc561b4eba0@104.154.136.117:30303",
// 	"enode://72e445f4e89c0f476d404bc40478b0df83a5b500d2d2e850e08eb1af0cd464ab86db6160d0fde64bd77d5f0d33507ae19035671b3c74fec126d6e28787669740@104.198.71.200:30303",
// 	"enode://39abab9d2a41f53298c0c9dc6bbca57b0840c3ba9dccf42aa27316addc1b7e56ade32a0a9f7f52d6c5db4fe74d8824bcedfeaecf1a4e533cacb71cf8100a9442@144.76.238.49:30303",
//     "enode://f50e675a34f471af2438b921914b5f06499c7438f3146f6b8936f1faeb50b8a91d0d0c24fb05a66f05865cd58c24da3e664d0def806172ddd0d4c5bdbf37747e@144.76.238.49:30306"
// ];

// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://d02c7c6d49c668f750cf6c007b4a9cc96be08c335d3e027afa110f86c48192725aa2e8a60c581044c7c489fee45a3d0acbbfe4d10eb1717bc6b3374364bf895d@127.0.0.1:30303"
// ];

const BOOTSTRAP_NODES: [&str; 1] = [
    "enode://1a686737c260539c2a80b8defe649a356806ca43f71e1915ae00c65245b893e2eee31bc0ca41f7733d31ba7cdcd60584e3c3f89cccabba08ca5bce889f44244c@127.0.0.1:30303"
];

// Parity
// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://3321955ec86feb439a20a295189408ac498c5390933e269fea0db3de949d0b23b69c6bab276cdf2c8ab56d019cfa6a1548e773de761151353b4390e62ce81318@127.0.0.1:30303"
// ];

fn main() {
    env_logger::init();

    let addr = "0.0.0.0:50505".parse().unwrap();
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let mut client = DPTStream::new(
        &addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        BOOTSTRAP_NODES.iter().map(|v| DPTNode::from_url(&Url::parse(v).unwrap()).unwrap()).collect(),
        "127.0.0.1".parse().unwrap(), 50505).unwrap();

    let dur = Duration::new(1, 0);

    let (mut client_sender, mut client_receiver) = client.split();
    let mut client_future = client_receiver.into_future();
    let mut timeout = Timeout::new(dur, &handle).unwrap().boxed();

    loop {
        let ret = match core.run(
            client_future
                .select2(timeout)
        ) {
            Ok(ret) => ret,
            Err(_) => break,
        };

        let (val, new_client_receiver) = match ret {
            future::Either::A(((val, new_client), t)) => {
                timeout = t.boxed();
                (val, new_client)
            },
            future::Either::B((_, fu)) => {
                client_future = fu;
                client_sender = core.run(client_sender.send(DPTMessage::RequestNewPeer)).unwrap();
                timeout = Timeout::new(dur, &handle).unwrap().boxed();

                continue;
            }
        };

        if val.is_none() {
            break;
        }
        let val = val.unwrap();

        println!("new peer: {:?}", val);
        client_future = new_client_receiver.into_future();
    }
}
