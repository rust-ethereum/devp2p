mod proto;

use futures::{StartSend, Async, Poll, Stream, Sink, AsyncSink, Future, future};
use rlp::{self, UntrustedRlp};
use bigint::{H512, H256, U256};
use rlpx::{RLPxSendMessage, RLPxReceiveMessage, RLPxNode, CapabilityInfo};
use dpt::DPTNode;
use secp256k1::key::SecretKey;
use tokio_core::reactor::Handle;
use std::io;
use std::time::Duration;
use std::net::SocketAddr;

use super::DevP2PStream;

pub use self::proto::ETHMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETHReceiveMessage {
    Connected {
        node: H512,
        version: usize,
    },
    Disconnected {
        node: H512
    },
    Normal {
        node: H512,
        version: usize,
        data: ETHMessage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ETHSendMessage {
    pub node: RLPxNode,
    pub data: ETHMessage,
}

pub struct ETHStream {
    stream: DevP2PStream,
    genesis_hash: H256,
    best_hash: H256,
    total_difficulty: U256,
    network_id: usize,
}

impl ETHStream {
    pub fn new(addr: &SocketAddr,
               handle: &Handle, secret_key: SecretKey,
               client_version: String, network_id: usize,
               genesis_hash: H256, best_hash: H256,
               total_difficulty: U256,
               bootstrap_nodes: Vec<DPTNode>,
               ping_interval: Duration, ping_timeout_interval: Duration,
               optimal_peers_len: usize) -> Result<Self, io::Error> {
        Ok(ETHStream {
            stream: DevP2PStream::new(addr, handle, secret_key,
                                      4, client_version,
                                      vec![CapabilityInfo { name: "eth", version: 62, length: 8 },
                                           CapabilityInfo { name: "eth", version: 63, length: 17 }],
                                      bootstrap_nodes,
                                      ping_interval, ping_timeout_interval,
                                      optimal_peers_len)?,
            genesis_hash, best_hash, total_difficulty, network_id
        })
    }

    pub fn disconnect_peer(&mut self, remote_id: H512) {
        self.stream.disconnect_peer(remote_id);
    }

    pub fn active_peers(&mut self) -> &[H512] {
        self.stream.active_peers()
    }

    pub fn set_best_hash(&mut self, hash: H256) {
        self.best_hash = hash;
    }

    pub fn set_total_difficulty(&mut self, diff: U256) {
        self.total_difficulty = diff;
    }
}

impl Stream for ETHStream {
    type Item = ETHReceiveMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let result = try_ready!(self.stream.poll());

        if result.is_none() {
            return Ok(Async::Ready(None));
        }
        let result = result.unwrap();

        match result {
            RLPxReceiveMessage::Connected { node, capabilities } => {
                if capabilities.len() == 0 {
                    debug!("connected a node without matching capability, ignoring.");
                    return self.poll();
                }

                let version = capabilities[0].version;
                let total_difficulty = self.total_difficulty;
                let best_hash = self.best_hash;
                let genesis_hash = self.genesis_hash;

                // Send Status
                self.start_send(ETHSendMessage {
                    node: RLPxNode::Peer(node),
                    data: ETHMessage::Status {
                        network_id: 1,
                        total_difficulty,
                        best_hash,
                        genesis_hash,
                        protocol_version: version,
                    }
                })?;
                self.poll_complete()?;

                return Ok(Async::Ready(Some(ETHReceiveMessage::Connected {
                    node, version
                })))
            },
            RLPxReceiveMessage::Disconnected { node } => {
                return Ok(Async::Ready(Some(ETHReceiveMessage::Disconnected {
                    node
                })))
            },
            RLPxReceiveMessage::Normal {
                node, capability, id, data,
            } => {
                let message = match ETHMessage::decode(&UntrustedRlp::new(&data), id) {
                    Ok(val) => val,
                    Err(_) => {
                        debug!("got an ununderstandable message, ignoring.");
                        return self.poll();
                    },
                };
                return Ok(Async::Ready(Some(ETHReceiveMessage::Normal {
                    node, version: capability.version,
                    data: message,
                })))
            },
        }
    }
}

impl Sink for ETHStream {
    type SinkItem = ETHSendMessage;
    type SinkError = io::Error;

    fn start_send(&mut self, val: ETHSendMessage) -> StartSend<Self::SinkItem, Self::SinkError> {
        match self.stream.start_send(RLPxSendMessage {
            node: val.node,
            capability_name: "eth",
            id: val.data.id(),
            data: rlp::encode(&val.data).to_vec(),
        }) {
            Ok(AsyncSink::Ready) => Ok(AsyncSink::Ready),
            Ok(AsyncSink::NotReady(v)) => Ok(AsyncSink::NotReady(val)),
            Err(e) => Err(e),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }
}
