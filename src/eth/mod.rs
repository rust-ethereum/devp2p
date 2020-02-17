mod proto;

use bigint::{H256, H512, U256};
use dpt::DPTNode;
use futures::{try_ready, Async, AsyncSink, Poll, Sink, StartSend, Stream};
use log::*;
use rlp::{self, UntrustedRlp};
use rlpx::{CapabilityInfo, RLPxNode, RLPxReceiveMessage, RLPxSendMessage};
use secp256k1::key::SecretKey;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
use tokio_core::reactor::Handle;

use super::{DevP2PConfig, DevP2PStream};

pub use self::proto::ETHMessage;

/// Receiving message of ETH
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETHReceiveMessage {
    Connected {
        node: H512,
        version: usize,
    },
    Disconnected {
        node: H512,
    },
    Normal {
        node: H512,
        version: usize,
        data: ETHMessage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Sending message of ETH
pub struct ETHSendMessage {
    pub node: RLPxNode,
    pub data: ETHMessage,
}

/// Represent a ETH stream over DevP2P protocol
#[allow(dead_code)]
pub struct ETHStream {
    stream: DevP2PStream,
    genesis_hash: H256,
    best_hash: H256,
    total_difficulty: U256,
    network_id: usize,
}

impl ETHStream {
    /// Create a new ETH stream
    pub fn new(
        addr: &SocketAddr,
        public_addr: &IpAddr,
        handle: &Handle,
        secret_key: SecretKey,
        client_version: String,
        network_id: usize,
        genesis_hash: H256,
        best_hash: H256,
        total_difficulty: U256,
        bootstrap_nodes: Vec<DPTNode>,
        config: DevP2PConfig,
    ) -> Result<Self, io::Error> {
        Ok(ETHStream {
            stream: DevP2PStream::new(
                addr,
                public_addr,
                handle,
                secret_key,
                4,
                client_version,
                vec![
                    CapabilityInfo {
                        name: "eth",
                        version: 62,
                        length: 8,
                    },
                    // CapabilityInfo { name: "eth", version: 63, length: 17 },
                ],
                bootstrap_nodes,
                config,
            )?,
            genesis_hash,
            best_hash,
            total_difficulty,
            network_id,
        })
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub fn disconnect_peer(&mut self, remote_id: H512) {
        self.stream.disconnect_peer(remote_id);
    }

    /// Active peers
    pub fn active_peers(&mut self) -> &[H512] {
        self.stream.active_peers()
    }

    /// Set the best hash of the blockchain
    pub fn set_best_hash(&mut self, hash: H256) {
        self.best_hash = hash;
    }

    /// Set the total difficulty of the blockchain
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
                    },
                })?;
                self.poll_complete()?;

                return Ok(Async::Ready(Some(ETHReceiveMessage::Connected {
                    node,
                    version,
                })));
            }
            RLPxReceiveMessage::Disconnected { node } => {
                return Ok(Async::Ready(Some(ETHReceiveMessage::Disconnected { node })))
            }
            RLPxReceiveMessage::Normal {
                node,
                capability,
                id,
                data,
            } => {
                debug!("got eth message with id {}", id);
                let message = match ETHMessage::decode(&UntrustedRlp::new(&data), id) {
                    Ok(val) => val,
                    Err(_) => {
                        debug!(
                            "got an ununderstandable message with id {}, data {:?}, ignoring.",
                            id, data
                        );
                        return self.poll();
                    }
                };
                return Ok(Async::Ready(Some(ETHReceiveMessage::Normal {
                    node,
                    version: capability.version,
                    data: message,
                })));
            }
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
            Ok(AsyncSink::NotReady(_)) => Ok(AsyncSink::NotReady(val)),
            Err(e) => Err(e),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }
}
