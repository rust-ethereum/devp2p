extern crate devp2p;
extern crate rand;
extern crate secp256k1;
extern crate bigint;
extern crate rlp;
extern crate block;
extern crate hexutil;

#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate env_logger;
extern crate url;
extern crate sha3;

use tokio_core::reactor::{Core, Timeout};
use secp256k1::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};
use rand::os::OsRng;
use futures::future;
use futures::{Stream, Sink, Future};
use std::str::FromStr;
use std::time::{Instant, Duration};
use devp2p::{ETHSendMessage, ETHReceiveMessage, ETHMessage, ETHStream, DevP2PConfig};
use devp2p::rlpx::RLPxNode;
use devp2p::dpt::DPTNode;
use bigint::{H256, U256, H512};
use url::Url;
use sha3::{Digest, Keccak256};
use block::{Header, Block};
use hexutil::*;

const GENESIS_HASH: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
const GENESIS_DIFFICULTY: usize = 17179869184;
const NETWORK_ID: usize = 1;

const ETC_DAO_BLOCK: &str = "f903cff9020fa0a218e2c611f21232d857e3c8cecdcdf1f65f25a4477f98f6f47e4063807f2308a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479461c808d82a3ac53231750dadc13c777b59310bd9a0614d7d358b03cbdaf0343529673be20ad45809d02487f023e047efdce9da8affa0d33068a7f21bff5018a00ca08a3566a06be4196dfe9e39f96e431565a619d455a07bda9aa65977800376129148cbfe89d35a016dd51c95d6e6dc1e76307d315468b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008638c3bf2616aa831d4c008347e7c08301482084578f7aa78fe4b883e5bda9e7a59ee4bb99e9b1bca0c52daa7054babe515b17ee98540c0889cf5e1595c5dd77496997ca84a68c8da18805276a600980199df901b9f86c018504a817c8008252089453d284357ec70ce289d6d64134dfac8e511c8a3d888b6cfa3afc058000801ba08d94a55c7ac7adbfa2285ef7f4b0c955ae1a02647452cd4ead03ee6f449675c6a067149821b74208176d78fc4dffbe37c8b64eecfd47532406b9727c4ae8eb7c9af86d018504a817c8008252089453d284357ec70ce289d6d64134dfac8e511c8a3d890116db7272d6d94000801ca06d31e3d59bfea97a34103d8ce767a8fe7a79b8e2f30af1e918df53f9e78e69aba0098e5b80e1cc436421aa54eb17e96b08fe80d28a2fbd46451b56f2bca7a321e7f86c018504a817c8008252089453d284357ec70ce289d6d64134dfac8e511c8a3d8814da2c24e0d37014801ba0fdbbc462a8a60ac3d8b13ee236b45af9b7991cf4f0f556d3af46aa5aeca242aba05de5dc03fdcb6cf6d14609dbe6f5ba4300b8ff917c7d190325d9ea2144a7a2fbf86c018504a817c8008252089453d284357ec70ce289d6d64134dfac8e511c8a3d880e301365046d5000801ba0bafb9f71cef873b9e0395b9ed89aac4f2a752e2a4b88ba3c9b6c1fea254eae73a01cef688f6718932f7705d9c1f0dd5a8aad9ddb196b826775f6e5703fdb997706c0";

const BOOTSTRAP_NODES: [&str; 10] = [
    "enode://e809c4a2fec7daed400e5e28564e23693b23b2cc5a019b612505631bbe7b9ccf709c1796d2a3d29ef2b045f210caf51e3c4f5b6d3587d43ad5d6397526fa6179@174.112.32.157:30303",
    "enode://6e538e7c1280f0a31ff08b382db5302480f775480b8e68f8febca0ceff81e4b19153c6f8bf60313b93bef2cc34d34e1df41317de0ce613a201d1660a788a03e2@52.206.67.235:30303",
    "enode://5fbfb426fbb46f8b8c1bd3dd140f5b511da558cd37d60844b525909ab82e13a25ee722293c829e52cb65c2305b1637fa9a2ea4d6634a224d5f400bfe244ac0de@162.243.55.45:30303",
    "enode://42d8f29d1db5f4b2947cd5c3d76c6d0d3697e6b9b3430c3d41e46b4bb77655433aeedc25d4b4ea9d8214b6a43008ba67199374a9b53633301bca0cd20c6928ab@104.155.176.151:30303",
    "enode://814920f1ec9510aa9ea1c8f79d8b6e6a462045f09caa2ae4055b0f34f7416fca6facd3dd45f1cf1673c0209e0503f02776b8ff94020e98b6679a0dc561b4eba0@104.154.136.117:30303",
    "enode://72e445f4e89c0f476d404bc40478b0df83a5b500d2d2e850e08eb1af0cd464ab86db6160d0fde64bd77d5f0d33507ae19035671b3c74fec126d6e28787669740@104.198.71.200:30303",
    "enode://5cd218959f8263bc3721d7789070806b0adff1a0ed3f95ec886fb469f9362c7507e3b32b256550b9a7964a23a938e8d42d45a0c34b332bfebc54b29081e83b93@35.187.57.94:30303",
    "enode://39abab9d2a41f53298c0c9dc6bbca57b0840c3ba9dccf42aa27316addc1b7e56ade32a0a9f7f52d6c5db4fe74d8824bcedfeaecf1a4e533cacb71cf8100a9442@144.76.238.49:30303",
    "enode://f50e675a34f471af2438b921914b5f06499c7438f3146f6b8936f1faeb50b8a91d0d0c24fb05a66f05865cd58c24da3e664d0def806172ddd0d4c5bdbf37747e@144.76.238.49:30306",
    "enode://6dd3ac8147fa82e46837ec8c3223d69ac24bcdbab04b036a3705c14f3a02e968f7f1adfcdb002aacec2db46e625c04bf8b5a1f85bb2d40a479b3cc9d45a444af@104.237.131.102:30303"
];

// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://1a686737c260539c2a80b8defe649a356806ca43f71e1915ae00c65245b893e2eee31bc0ca41f7733d31ba7cdcd60584e3c3f89cccabba08ca5bce889f44244c@127.0.0.1:30303"
// ];

// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://52656243997655790c1015e4c62e1afefd2f7d6b30c4434ea0a1557523348ad8515d15d0014002bdec80daba786714aa9bc4970ce99afa9e4fd6b94c98782669@35.194.140.8:30303"
// ];

// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://1a686737c260539c2a80b8defe649a356806ca43f71e1915ae00c65245b893e2eee31bc0ca41f7733d31ba7cdcd60584e3c3f89cccabba08ca5bce889f44244c@127.0.0.1:60606"
// ];

// const BOOTSTRAP_NODES: [&str; 1] = [
//     "enode://3321955ec86feb439a20a295189408ac498c5390933e269fea0db3de949d0b23b69c6bab276cdf2c8ab56d019cfa6a1548e773de761151353b4390e62ce81318@127.0.0.1:30303"
// ];

pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.input(data);
    let out = hasher.result();
    H256::from(out.as_ref())
}

fn main() {
    env_logger::init();

    let addr = "0.0.0.0:60606".parse().unwrap();
    let public_addr = "127.0.0.1".parse().unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let mut client = ETHStream::new(
        &addr, &public_addr, &handle,
        SecretKey::new(&SECP256K1, &mut OsRng::new().unwrap()),
        "etclient Rust/0.1.0".to_string(), 1,
        H256::from_str(GENESIS_HASH).unwrap(),
        H256::from_str(GENESIS_HASH).unwrap(),
        U256::from(GENESIS_DIFFICULTY),
        BOOTSTRAP_NODES.iter().map(|v| DPTNode::from_url(&Url::parse(v).unwrap()).unwrap()).collect(),
        DevP2PConfig {
            ping_interval: Duration::new(600, 0),
            ping_timeout_interval: Duration::new(700, 0),
            optimal_peers_len: 25,
            optimal_peers_interval: Duration::new(5, 0),
            reconnect_dividend: 5,
        }).unwrap();

    let mut best_number: U256 = U256::zero();
    let mut best_hash: H256 = H256::from_str(GENESIS_HASH).unwrap();
    let mut got_bodies_for_current = true;

    let dur = Duration::new(10, 0);
    let req_max_headers = 2048;
    let mut when = Instant::now() + dur;

    let (mut client_sender, mut client_receiver) = client.split();
    let mut client_future = client_receiver.into_future();
    let mut timeout = Timeout::new(dur, &handle).unwrap().boxed();

    let mut active_peers = 0;

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

                println!("request downloading header ...");
                client_sender = core.run(client_sender.send(ETHSendMessage {
                    node: RLPxNode::Any,
                    data: ETHMessage::GetBlockHeadersByHash {
                        hash: best_hash,
                        max_headers: req_max_headers,
                        skip: 0,
                        reverse: false,
                    }
                })).unwrap();

                timeout = Timeout::new(dur, &handle).unwrap().boxed();

                continue;
            }
        };

        if val.is_none() {
            break;
        }
        let val = val.unwrap();

        match val {
            ETHReceiveMessage::Normal {
                node, data, version
            } => {
                match data {
                    ETHMessage::Status { .. } => (),

                    ETHMessage::Transactions(_) => {
                        println!("received new transactions");
                    },

                    ETHMessage::GetBlockHeadersByNumber {
                        number, max_headers, skip, reverse
                    } => {
                        if number == U256::from(1920000) {
                            println!("requested DAO header");
                            let block_raw = read_hex(ETC_DAO_BLOCK).unwrap();
                            let block: Block = rlp::decode(&block_raw);
                            client_sender = core.run(client_sender.send(ETHSendMessage {
                                node: RLPxNode::Peer(node),
                                data: ETHMessage::BlockHeaders(vec![ block.header ]),
                            })).unwrap();
                        } else {
                            println!("requested header {}", number);
                            client_sender = core.run(client_sender.send(ETHSendMessage {
                                node: RLPxNode::Peer(node),
                                data: ETHMessage::BlockHeaders(Vec::new()),
                            })).unwrap();
                        }
                    },

                    ETHMessage::GetBlockHeadersByHash {
                        hash, max_headers, skip, reverse
                    } => {
                        println!("requested header {}", hash);
                        client_sender = core.run(client_sender.send(ETHSendMessage {
                            node: RLPxNode::Peer(node),
                            data: ETHMessage::BlockHeaders(Vec::new()),
                        })).unwrap();
                    },

                    ETHMessage::GetBlockBodies(hash) => {
                        println!("requested body {:?}", hash);
                        client_sender = core.run(client_sender.send(ETHSendMessage {
                            node: RLPxNode::Peer(node),
                            data: ETHMessage::BlockBodies(Vec::new()),
                        })).unwrap();
                    },

                    ETHMessage::BlockHeaders(ref headers) => {
                        println!("received block headers of len {}", headers.len());
                        if got_bodies_for_current {
                            for header in headers {
                                if header.parent_hash == best_hash {
                                    best_hash = keccak256(&rlp::encode(header).to_vec());
                                    best_number = header.number;
                                    println!("updated best number: {}", header.number);
                                    println!("updated best hash: 0x{:x}", best_hash);
                                }
                            }
                        }
                        client_sender = core.run(client_sender.send(ETHSendMessage {
                            node: RLPxNode::Any,
                            data: ETHMessage::GetBlockHeadersByHash {
                                hash: best_hash,
                                max_headers: req_max_headers,
                                skip: 0,
                                reverse: false,
                            }
                        })).unwrap();
                        timeout = Timeout::new(dur, &handle).unwrap().boxed();
                    },

                    ETHMessage::BlockBodies(ref bodies) => {
                        println!("received block bodies of len {}", bodies.len());
                    },

                    msg => {
                        println!("received {:?}", msg);
                    },
                }
            },
            ETHReceiveMessage::Connected { .. } => {
                active_peers += 1;
            },
            ETHReceiveMessage::Disconnected { .. } => {
                active_peers -= 1;
            },
        }

        println!("current active peers: {}", active_peers);

        client_future = new_client_receiver.into_future();
    }
}
