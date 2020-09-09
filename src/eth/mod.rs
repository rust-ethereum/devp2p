pub mod proto;

use self::proto::*;
use crate::types::*;
use arrayvec::ArrayString;
use async_trait::async_trait;
use bytes::Bytes;
use ethereum::{Block, Transaction};
use ethereum_types::*;
use log::*;
use maplit::btreemap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::Debug,
    sync::Arc,
};
use tokio::sync::oneshot::{channel as oneshot, Sender as OneshotSender};

static ETH_PROTOCOL_ID: Lazy<CapabilityName> =
    Lazy::new(|| CapabilityName(ArrayString::from("eth").unwrap()));

pub enum Error {
    NoPeers,
    PeerGone,
    Shutdown,
}

impl From<Shutdown> for Error {
    fn from(_: Shutdown) -> Self {
        Self::Shutdown
    }
}

#[async_trait]
pub trait EthRequestHandler: Send + Sync + 'static {
    async fn handle_status(&self, status: ());
    async fn handle_new_block_hashes(&self, hashes: Vec<(H256, U256)>);
    async fn handle_new_pooled_transaction_hashes(&self, hashes: ());
    async fn handle_new_block(&self, block: Block, total_difficulty: U256);
}

#[async_trait]
pub trait EthProtocol {
    async fn new_block_hashes(&self, hashes: Vec<(H256, U256)>) -> Result<(), Error>;
    async fn get_pooled_transactions(
        &self,
        hashes: HashSet<H256>,
    ) -> Result<Vec<Transaction>, Error>;
}

#[derive(Debug)]
struct RequestCallbackData<ResponseKind: Debug> {
    data: RequestCallback,
    expected_response_id: ResponseKind,
}

type RequestCallback = OneshotSender<(Bytes, OneshotSender<()>)>;

#[derive(Debug)]
struct RequestMultiplexer<RK: Debug> {
    inner: HashMap<H512, HashMap<u64, RequestCallbackData<RK>>>,
}

impl<RK: Debug> Default for RequestMultiplexer<RK> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<RK: Debug> RequestMultiplexer<RK> {
    fn save_callback(&mut self, peer_id: PeerId, callback: RequestCallbackData<RK>) -> u64 {
        let peer = self.inner.entry(peer_id).or_default();
        loop {
            let request_id = rand::random();

            if let Entry::Vacant(vacant) = peer.entry(request_id) {
                vacant.insert(callback);
                return request_id;
            }
        }
    }

    fn retrieve_callback(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
    ) -> Option<RequestCallbackData<RK>> {
        if let Entry::Occupied(mut entry) = self.inner.entry(peer_id) {
            if let Some(callback) = entry.get_mut().remove(&request_id) {
                if entry.get().is_empty() {
                    entry.remove();
                }
                return Some(callback);
            }
        }

        None
    }
}

pub enum MessageKind<Request, Response, Gossip> {
    Request(Request),
    Response(Response),
    Gossip(Gossip),
}

#[async_trait]
pub trait MuxProtocol: Send + Sync + 'static {
    type RequestKind: Send;
    type ResponseKind: From<Self::ResponseKind> + PartialEq + Eq + Debug + Send;
    type GossipKind: Send;

    fn capabilities(&self) -> BTreeMap<CapabilityId, usize>;
    fn message_kind(
        &self,
        id: usize,
    ) -> Option<MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>>;
    async fn handle_request(
        &self,
        id: Self::RequestKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> (Option<(usize, Bytes)>, ReputationReport);
    async fn handle_response(
        &self,
        id: Self::ResponseKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> ReputationReport;
    async fn handle_gossip(
        &self,
        id: Self::GossipKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> ReputationReport;
}

/// Generic multiplexing protocol server shim.
pub struct Mux<P2P: ProtocolRegistrar, Protocol: MuxProtocol> {
    inflight_requests: Arc<Mutex<RequestMultiplexer<<Protocol as MuxProtocol>::ResponseKind>>>,

    protocol: Arc<Protocol>,
    devp2p_handle: Arc<P2P::ServerHandle>,
    devp2p_owned_handle: Option<Arc<P2P>>,
}

impl<P2P: ProtocolRegistrar, Protocol: MuxProtocol> Mux<P2P, Protocol> {
    /// Register the protocol server with the RLPx node.
    pub fn new(registrar: &P2P, protocol: Arc<Protocol>) -> Self {
        let inflight_requests = Arc::new(Mutex::new(RequestMultiplexer::default()));
        let ingress_handler = {
            let inflight_requests = inflight_requests.clone();
            let protocol = protocol.clone();
            Arc::new(move |peer: P2P::IngressPeerToken, id, message| {
                let inflight_requests = inflight_requests.clone();
                let protocol = protocol.clone();
                Box::pin(async move {
                    match protocol.message_kind(id) {
                        None => debug!("Skipping unidentified message from with id {}", id),
                        Some(MessageKind::Response(response)) => {
                            let request_id: u64 = todo!();

                            let sender = inflight_requests
                                .lock()
                                .retrieve_callback(peer.id(), request_id);

                            // TODO: handle gossip and incoming requests.
                            if let Some(RequestCallbackData {
                                data: sender,
                                expected_response_id,
                            }) = sender
                            {
                                if expected_response_id != response {
                                    debug!(
                                        "Peer sent us wrong reply! Expected: {:?}, Got: {:?}",
                                        expected_response_id, response
                                    );
                                    return (None, ReputationReport::Kick);
                                } else {
                                    let (tx, rx) = oneshot();
                                    sender.send((message, tx));
                                    rx.await;
                                }
                            }
                        }
                        Some(MessageKind::Request(request)) => todo!(),
                        Some(MessageKind::Gossip(gossip)) => todo!(),
                    }

                    return (None, ReputationReport::Good);
                }) as IngressHandlerFuture
            }) as IngressHandler<P2P::IngressPeerToken>
        };

        let devp2p_handle =
            Arc::new(registrar.register_protocol_server(protocol.capabilities(), ingress_handler));
        Self {
            inflight_requests,
            protocol,
            devp2p_handle,
            devp2p_owned_handle: None,
        }
    }

    /// Register the protocol server with the devp2p client and make protocol server the owner of devp2p instance
    pub fn new_owned(registrar: Arc<P2P>, request_handler: Arc<Protocol>) -> Self {
        let mut this = Self::new(&*registrar, request_handler);
        this.devp2p_owned_handle = Some(registrar);
        this
    }
}

pub struct Server;

#[async_trait]
impl MuxProtocol for Server {
    type RequestKind = proto::RequestMessageId;
    type ResponseKind = proto::ResponseMessageId;
    type GossipKind = proto::GossipMessageId;

    fn capabilities(&self) -> BTreeMap<CapabilityId, usize> {
        btreemap! { CapabilityId { name: *ETH_PROTOCOL_ID, version: 66 } => 17 }
    }
    fn message_kind(
        &self,
        id: usize,
    ) -> Option<MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>> {
        Some(match id {
            0x00 => MessageKind::Gossip(Self::GossipKind::Status),
            0x01 => MessageKind::Gossip(Self::GossipKind::NewBlockHashes),
            0x02 => MessageKind::Gossip(Self::GossipKind::Transactions),
            0x03 => MessageKind::Request(Self::RequestKind::GetBlockHeaders),
            0x04 => MessageKind::Response(Self::ResponseKind::BlockHeaders),
            0x05 => MessageKind::Request(Self::RequestKind::GetBlockBodies),
            0x06 => MessageKind::Response(Self::ResponseKind::BlockBodies),
            0x07 => MessageKind::Gossip(Self::GossipKind::NewBlock),
            0x08 => MessageKind::Gossip(Self::GossipKind::NewPooledTransactionHashes),
            0x09 => MessageKind::Request(Self::RequestKind::GetPooledTransactions),
            0x0a => MessageKind::Response(Self::ResponseKind::PooledTransactions),
            0x0d => MessageKind::Request(Self::RequestKind::GetNodeData),
            0x0e => MessageKind::Response(Self::ResponseKind::NodeData),
            0x0f => MessageKind::Request(Self::RequestKind::GetReceipts),
            0x10 => MessageKind::Response(Self::ResponseKind::Receipts),
            _ => return None,
        })
    }
    async fn handle_request(
        &self,
        id: Self::RequestKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> (Option<(usize, Bytes)>, ReputationReport) {
        // TODO
        (None, ReputationReport::Good)
    }
    async fn handle_response(
        &self,
        id: Self::ResponseKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> ReputationReport {
        // TODO
        ReputationReport::Good
    }
    async fn handle_gossip(
        &self,
        id: Self::GossipKind,
        cap: CapabilityId,
        payload: Bytes,
    ) -> ReputationReport {
        // TODO
        ReputationReport::Good
    }
}

// #[async_trait]
// impl<P2P: ProtocolRegistrar, G: EthRequestHandler> EthProtocol for Mux<P2P, G> {
//     async fn new_block_hashes(&self, hashes: Vec<(H256, U256)>) -> Result<(), Error> {
//         todo!()
//     }

//     async fn get_pooled_transactions(
//         &self,
//         _hashes: HashSet<H256>,
//     ) -> Result<Vec<Transaction>, Error> {
//         let peer_handle = self
//             .devp2p_handle
//             .get_peer(*ETH_PROTOCOL_ID, btreeset![65])
//             .await?
//             .ok_or(Error::NoPeers)?;

//         let (tx, rx) = tokio::sync::oneshot::channel();
//         let request_id = self
//             .inflight_requests
//             .lock()
//             .save_callback(peer_handle.peer_id(), tx);

//         // Make a GetPooledTransactions message
//         let msg = request_id.to_be_bytes().to_vec().into();

//         peer_handle.send_message(msg).await;

//         let msg = rx.await.unwrap();

//         // Parse PooledTransactionHashes
//         todo!()
//     }
// }

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
