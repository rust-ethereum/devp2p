mod proto;

pub use self::proto::*;
use super::raw::*;
use async_trait::async_trait;
use bigint::{H256, H512, U256};
use ethereum_types::*;
use futures::prelude::*;
use log::*;
use rlp::{self, UntrustedRlp};
use rlpx::{CapabilityInfo, RLPxReceiveMessage, RLPxSendMessage};
use secp256k1::key::SecretKey;
use std::{
    collections::{HashMap, HashSet},
    io,
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{prelude::*, sync::oneshot::Sender as OneshotSender};

pub struct PooledTransactionHashes();

#[async_trait]
pub trait EthGossipHandler: Send + Sync {
    async fn handle_gossip_message(&self, message: EthGossipMessage);
}

#[async_trait]
pub trait EthProtocol {
    async fn get_pooled_transaction_hashes(
        &self,
        hashes: HashSet<H256>,
    ) -> Result<PooledTransactionHashes, Shutdown>;
}

pub struct Server<P2P: ProtocolRegistrar, G: EthGossipHandler> {
    inflight_requests: Arc<Mutex<HashMap<H512, HashMap<u64, OneshotSender<Vec<u8>>>>>>,

    gossip_handler: Arc<G>,
    devp2p_handle: Arc<P2P::ServerHandle>,
    devp2p_owned_handle: Option<Arc<P2P>>,
}

impl<P2P: ProtocolRegistrar, G: EthGossipHandler> Server<P2P, G> {
    pub fn new(registrator: &P2P, gossip_handler: Arc<G>) -> Self {
        let devp2p_handle = Arc::new(
            registrator.register_handler("eth".to_string(), Box::pin(futures::sink::drain())),
        );
        Self {
            inflight_requests: Default::default(),
            gossip_handler,
            devp2p_handle,
            devp2p_owned_handle: None,
        }
    }

    pub fn new_owned(registrator: Arc<P2P>, gossip_handler: Arc<G>) -> Self {
        let mut this = Self::new(&*registrator, gossip_handler);
        this.devp2p_owned_handle = Some(registrator);
        this
    }
}

#[async_trait]
impl<P2P: ProtocolRegistrar, G: EthGossipHandler> EthProtocol for Server<P2P, G> {
    async fn get_pooled_transaction_hashes(
        &self,
        _hashes: HashSet<H256>,
    ) -> Result<PooledTransactionHashes, Shutdown> {
        let peer_handle = self.devp2p_handle.get_peer(65).await?;

        let request_id = rand::random();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.inflight_requests
            .lock()
            .unwrap()
            .entry(peer_handle.peer_id())
            .or_default()
            .insert(request_id, tx);

        // Make a GetPooledTransactions message
        let msg = Arc::new(request_id.to_be_bytes().to_vec());

        peer_handle.send_message(msg).await;

        let msg = rx.await.unwrap();

        // Parse PooledTransactionHashes

        unimplemented!()
    }
}

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

// #[derive(Debug, Clone, PartialEq, Eq)]
// /// Sending message of ETH
// pub struct ETHSendMessage {
//     pub node: RLPxNode,
//     pub data: ETHMessage,
// }

// /// Represent a ETH stream over `devp2p` protocol
// #[allow(dead_code)]
// pub struct ETHStream {
//     stream: DevP2PServer,
//     genesis_hash: H256,
//     best_hash: H256,
//     total_difficulty: U256,
//     network_id: usize,
// }

// impl ETHStream {
//     /// Create a new ETH stream
//     pub fn new(
//         addr: SocketAddr,
//         public_addr: IpAddr,
//         handle: &Handle,
//         secret_key: SecretKey,
//         client_version: String,
//         network_id: usize,
//         genesis_hash: H256,
//         best_hash: H256,
//         total_difficulty: U256,
//         bootstrap_nodes: Vec<DPTNode>,
//         config: DevP2PConfig,
//     ) -> Result<Self, io::Error> {
//         Ok(Self {
//             stream: DevP2PStream::new(
//                 addr,
//                 public_addr,
//                 handle,
//                 secret_key,
//                 4,
//                 client_version,
//                 vec![CapabilityInfo {
//                     name: "eth",
//                     version: 66,
//                     length: 8,
//                 }],
//                 bootstrap_nodes,
//                 config,
//             )?,
//             genesis_hash,
//             best_hash,
//             total_difficulty,
//             network_id,
//         })
//     }

//     /// Force disconnecting a peer if it is already connected or about
//     /// to be connected. Useful for removing peers on a different hard
//     /// fork network
//     pub fn disconnect_peer(&mut self, remote_id: H512) {
//         self.stream.disconnect_peer(remote_id);
//     }

//     /// Active peers
//     pub fn active_peers(&mut self) -> &[H512] {
//         self.stream.active_peers()
//     }

//     /// Set the best hash of the blockchain
//     pub fn set_best_hash(&mut self, hash: H256) {
//         self.best_hash = hash;
//     }

//     /// Set the total difficulty of the blockchain
//     pub fn set_total_difficulty(&mut self, diff: U256) {
//         self.total_difficulty = diff;
//     }
// }

// impl Stream for ETHStream {
//     type Item = ETHReceiveMessage;
//     type Error = io::Error;

//     fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
//         let result = try_ready!(self.stream.poll());

//         if result.is_none() {
//             return Ok(Async::Ready(None));
//         }
//         let result = result.unwrap();

//         match result {
//             RLPxReceiveMessage::Connected { node, capabilities } => {
//                 if capabilities.is_empty() {
//                     debug!("connected a node without matching capability, ignoring.");
//                     return self.poll();
//                 }

//                 let version = capabilities[0].version;
//                 let total_difficulty = self.total_difficulty;
//                 let best_hash = self.best_hash;
//                 let genesis_hash = self.genesis_hash;

//                 // Send Status
//                 self.start_send(ETHSendMessage {
//                     node: RLPxNode::Peer(node),
//                     data: ETHMessage::Status {
//                         network_id: 1,
//                         total_difficulty,
//                         best_hash,
//                         genesis_hash,
//                         protocol_version: version,
//                     },
//                 })?;
//                 self.poll_complete()?;

//                 Ok(Async::Ready(Some(ETHReceiveMessage::Connected {
//                     node,
//                     version,
//                 })))
//             }
//             RLPxReceiveMessage::Disconnected { node } => {
//                 Ok(Async::Ready(Some(ETHReceiveMessage::Disconnected { node })))
//             }
//             RLPxReceiveMessage::Normal {
//                 node,
//                 capability,
//                 id,
//                 data,
//             } => {
//                 debug!("got eth message with id {}", id);
//                 let message = if let Ok(val) = ETHMessage::decode(&UntrustedRlp::new(&data), id) {
//                     val
//                 } else {
//                     debug!(
//                         "got an ununderstandable message with id {}, data {:?}, ignoring.",
//                         id, data
//                     );
//                     return self.poll();
//                 };
//                 Ok(Async::Ready(Some(ETHReceiveMessage::Normal {
//                     node,
//                     version: capability.version,
//                     data: message,
//                 })))
//             }
//         }
//     }
// }

// impl Sink for ETHStream {
//     type SinkItem = ETHSendMessage;
//     type SinkError = io::Error;

//     fn start_send(&mut self, val: ETHSendMessage) -> StartSend<Self::SinkItem, Self::SinkError> {
//         match self.stream.start_send(RLPxSendMessage {
//             node: val.node,
//             capability_name: "eth",
//             id: val.data.id(),
//             data: rlp::encode(&val.data).to_vec(),
//         }) {
//             Ok(AsyncSink::Ready) => Ok(AsyncSink::Ready),
//             Ok(AsyncSink::NotReady(_)) => Ok(AsyncSink::NotReady(val)),
//             Err(e) => Err(e),
//         }
//     }

//     fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
//         self.stream.poll_complete()
//     }
// }
