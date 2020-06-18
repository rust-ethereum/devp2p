use async_trait::async_trait;
use bigint::{H512, H512 as PeerId};
use bytes::Bytes;
use discv5::Discv5;
use futures::prelude::*;
use log::*;
use rand::{thread_rng, Rng};
use rlpx::*;
use secp256k1::key::SecretKey;
use std::{
    cmp::min,
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::{oneshot::Sender as OneShotSender, Mutex as AsyncMutex};

pub struct Shutdown;

pub enum PeerSendError {
    Shutdown,
    PeerGone,
}

pub type Enr = enr::Enr<SecretKey>;

/// Peer handle that freezes the peer in the pool.
#[async_trait]
pub trait PeerHandle: Send + Sync {
    fn capability_version(&self) -> u8;
    fn peer_id(&self) -> PeerId;
    async fn send_message(self, message: Bytes) -> Result<(), PeerSendError>;
}

pub struct PeerHandleImpl {
    capability: CapabilityName,
    capability_version: u8,
    peer_id: PeerId,
    pool: Weak<AsyncMutex<RLPxStream>>,
}

#[async_trait]
impl PeerHandle for PeerHandleImpl {
    fn capability_version(&self) -> u8 {
        self.capability_version
    }
    fn peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }
    async fn send_message(self, message: Bytes) -> Result<(), PeerSendError> {
        self.pool
            .upgrade()
            .ok_or(PeerSendError::Shutdown)?
            .lock()
            .await
            .send(RLPxSendMessage {
                id: todo!(),
                peer: self.peer_id.clone(),
                capability_name: self.capability.clone(),
                data: message,
            })
            .await?;

        Ok(())
    }
}

/// DevP2P server handle that can be used by the owning protocol server to access peer pool.
#[async_trait]
pub trait ServerHandle: Send + Sync {
    type PeerHandle: PeerHandle;
    /// Get random peer that matches the specified capability version. Returns peer ID and actual capability version.
    async fn get_peer(&self, min_capability_version: usize) -> Result<Self::PeerHandle, Shutdown>;
    /// Number of peers that support the specified capability version.
    async fn num_peers(&self, min_capability_version: usize) -> Result<usize, Shutdown>;
}

pub struct ServerHandleImpl {
    pool: Weak<RLPxStream>,
}

#[async_trait]
impl ServerHandle for ServerHandleImpl {
    type PeerHandle = PeerHandleImpl;

    async fn get_peer(&self, min_capability_version: usize) -> Result<Self::PeerHandle, Shutdown> {
        let peer_id = {
            let pool = self.pool.upgrade().ok_or(Shutdown)?;
            pool.get_peers(
                1,
                PeerFilter {
                    is_connected: Some(true),
                    capability: Some(CapabilityFilter {
                        name: "eth".to_string(),
                        versions: std::iter::once(min_capability_version).collect(),
                    }),
                },
            )
        };

        Self::PeerHandle {
            capability_version: unimplemented!(),
            peer_id,
            pool: self.pool.clone(),
        }
    }

    async fn num_peers(&self, min_capability_version: usize) -> Result<usize, Shutdown> {
        unimplemented!()
    }
}

pub struct IncomingMessage {
    pub peer_id: PeerId,
    pub message: Vec<u8>,
}

pub type IncomingHandler =
    Pin<Box<dyn Sink<IncomingMessage, Error = std::convert::Infallible> + Send + 'static>>;

#[async_trait]
pub trait ProtocolRegistrar: Send + Sync {
    type ServerHandle: ServerHandle;

    /// Register support for the protocol. Takes the sink as incoming handler for the protocol. Returns personal handle to the peer pool.
    fn register_incoming_handler(
        &self,
        protocol: CapabilityName,
        handler: IncomingHandler,
    ) -> Self::ServerHandle;
}

impl ProtocolRegistrar for Server {
    type ServerHandle = ServerHandleImpl;

    fn register_handler(
        &self,
        protocol: CapabilityName,
        handler: IncomingHandler,
    ) -> Self::ServerHandle {
        self.protocol_handlers
            .lock()
            .unwrap()
            .insert(protocol, Box::pin(handler));
        let pool = Arc::downgrade(&self.rlpx);
        Self::ServerHandle {
            pool,
            inner: Box::pin({ async move { unimplemented!() } }),
        }
    }
}

/// Config for devp2p
pub struct Config {
    pub ping_interval: Duration,
    pub ping_timeout_interval: Duration,
    pub optimal_peers_len: usize,
    pub optimal_peers_interval: Duration,
    pub reconnect_dividend: usize,
    pub listen: bool,
}

/// An Ethereum devp2p stream that handles peers management
pub struct Server {
    discovery: Arc<Mutex<Discv5>>,
    rlpx: Arc<AsyncMutex<RLPxStream>>,
    config: Config,
    protocol_handlers: Arc<Mutex<HashMap<String, IncomingHandler>>>,
}

// impl DevP2PServer {
//     /// Create a new devp2p stream
//     pub fn new(
//         addr: SocketAddr,
//         public_addr: IpAddr,
//         local_enr: Enr,
//         secret_key: SecretKey,
//         protocol_version: usize,
//         client_version: String,
//         capabilities: Vec<CapabilityInfo>,
//         bootstrap_nodes: Vec<Enr>,
//         config: DevP2PConfig,
//     ) -> Result<Self, io::Error> {
//         let port = addr.port();

//         let rlpx = RLPxStream::new(
//             handle,
//             secret_key,
//             protocol_version,
//             client_version,
//             capabilities,
//             if config.listen { Some(addr) } else { None },
//         )?;

//         let discovery = Discv5::new(
//             addr,
//             secret_key,
//             secret_key,
//             bootstrap_nodes,
//             public_addr,
//             port,
//         )?;

//         Ok(Self { dpt, rlpx, config })
//     }

//     /// Force disconnecting a peer if it is already connected or about
//     /// to be connected. Useful for removing peers on a different hard
//     /// fork network
//     pub fn disconnect_peer(&mut self, remote_id: H512) {
//         self.rlpx.disconnect_peer(remote_id);
//         self.dpt.disconnect_peer(remote_id);
//     }

//     /// Active peers
//     pub fn active_peers(&mut self) -> &[H512] {
//         self.rlpx.active_peers()
//     }

//     fn poll_dpt_receive_peers(&mut self) -> Poll<(), io::Error> {
//         loop {
//             let node = match self.dpt.poll() {
//                 Ok(Async::Ready(Some(node))) => node,
//                 Ok(_) => return Ok(Async::Ready(())),
//                 Err(e) => return Err(e),
//             };
//             self.rlpx
//                 .add_peer(&SocketAddr::new(node.address, node.tcp_port), node.id);
//         }
//     }

//     fn poll_dpt_request_new_peers(&mut self) -> Poll<(), io::Error> {
//         let mut result = self.optimal_peers_timeout.poll()?;

//         loop {
//             match result {
//                 Async::NotReady => return Ok(Async::Ready(())),
//                 Async::Ready(()) => {
//                     if self.rlpx.active_peers().len() < self.config.optimal_peers_len {
//                         error!(
//                             "not enough peers (only {}), requesting new ...",
//                             self.rlpx.active_peers().len()
//                         );
//                         self.dpt.start_send(DPTMessage::RequestNewPeer)?;
//                         self.dpt.poll_complete()?;

//                         debug!("reconnect to old connected peers ...");
//                         let mut connected: Vec<DPTNode> = self.dpt.connected_peers().into();
//                         thread_rng().shuffle(&mut connected);
//                         for dpt_node in connected.iter().take(min(
//                             self.config.optimal_peers_len - self.rlpx.active_peers().len(),
//                             connected.len() / self.config.reconnect_dividend,
//                         )) {
//                             self.rlpx.add_peer(
//                                 &SocketAddr::new(dpt_node.address, dpt_node.tcp_port),
//                                 dpt_node.id,
//                             );
//                         }
//                     }

//                     self.optimal_peers_timeout =
//                         Timeout::new(self.config.optimal_peers_interval, &self.handle)?;

//                     result = self.optimal_peers_timeout.poll()?;
//                 }
//             }
//         }
//     }
// }

// impl Stream for DevP2PServer {
//     type Item = RLPxReceiveMessage;
//     type Error = io::Error;

//     fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
//         self.poll_dpt_receive_peers()?;
//         let result = self.rlpx.poll()?;
//         self.poll_dpt_request_new_peers()?;
//         self.poll_dpt_ping()?;
//         Ok(result)
//     }
// }

// impl Sink for DevP2PServer {
//     type SinkItem = RLPxSendMessage;
//     type SinkError = io::Error;

//     fn start_send(&mut self, val: RLPxSendMessage) -> StartSend<Self::SinkItem, Self::SinkError> {
//         self.poll_dpt_receive_peers()?;
//         let result = self.rlpx.start_send(val)?;
//         self.poll_dpt_request_new_peers()?;
//         self.poll_dpt_ping()?;
//         Ok(result)
//     }

//     fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
//         try_ready!(self.dpt.poll_complete());
//         try_ready!(self.rlpx.poll_complete());
//         Ok(Async::Ready(()))
//     }
// }
