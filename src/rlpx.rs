//! `RLPx` protocol implementation in Rust

use crate::{node_filter::*, peer::*, types::*, util::*};
use async_trait::async_trait;
use bytes::Bytes;
use discv5::Discv5;
use ethereum_types::H512;
use futures::{
    future::abortable,
    sink::{Sink, SinkExt},
    stream::SplitStream,
};
use libsecp256k1::SecretKey;
use log::*;
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use std::{
    cmp::min,
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt, StreamMap},
    sync::Mutex as AsyncMutex,
};

pub struct EgressPeerHandleImpl {
    capability: CapabilityName,
    capability_version: u8,
    peer_id: PeerId,
    sender: tokio::sync::mpsc::Sender<RLPxSendMessage>,
}

#[async_trait]
impl EgressPeerHandle for EgressPeerHandleImpl {
    fn capability_version(&self) -> u8 {
        self.capability_version
    }
    fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    async fn send_message(mut self, message: Bytes) -> Result<(), PeerSendError> {
        self.sender
            .send(RLPxSendMessage {
                id: todo!(),
                capability_name: self.capability.clone(),
                data: message,
            })
            .await
            .map_err(|_| PeerSendError::PeerGone);

        Ok(())
    }
}

pub struct ServerHandleImpl {
    pool: Weak<Server>,
}

#[async_trait]
impl ServerHandle for ServerHandleImpl {
    type EgressPeerHandle = EgressPeerHandleImpl;

    async fn get_peer(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
    ) -> Result<Option<Self::EgressPeerHandle>, Shutdown> {
        let (peer_id, sender) = {
            let pool = self.pool.upgrade().ok_or(Shutdown)?;
            match pool
                .connected_peers(|_| 1, Some(&CapabilityFilter { name, versions }))
                .into_iter()
                .next()
            {
                Some(peer_id) => peer_id,
                None => return Ok(None),
            }
        };

        Ok(Some(EgressPeerHandleImpl {
            capability: name,
            capability_version: todo!(),
            peer_id,
            sender,
        }))
    }

    async fn num_peers(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
    ) -> Result<usize, Shutdown> {
        unimplemented!()
    }
}

pub struct IngressPeerTokenImpl {
    id: PeerId,
}

impl IngressPeerToken for IngressPeerTokenImpl {
    fn id(&self) -> PeerId {
        self.id
    }

    fn finalize(self, response: Bytes, report: ReputationReport) {
        todo!()
    }
}

/// Sending message for `RLPx`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLPxSendMessage {
    pub capability_name: CapabilityName,
    pub id: usize,
    pub data: Bytes,
}

#[async_trait]
impl Discovery for Discv5 {
    async fn get_new_peer(&mut self) -> Result<(SocketAddr, PeerId), io::Error> {
        loop {
            for node in self.find_node(enr::NodeId::random()).await.map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Discovery error: {}", e))
            })? {
                if let Some(ip) = node.ip() {
                    if let Some(port) = node.tcp() {
                        if let enr::CombinedPublicKey::Secp256k1(pk) = node.public_key() {
                            return Ok((
                                (ip, port).into(),
                                // TODO: remove after version harmonization
                                pk2id(&libsecp256k1::PublicKey::parse(&pk.serialize()).unwrap()),
                            ));
                        }
                    }
                }
            }
        }
    }
}

pub type PeerSender = tokio::sync::mpsc::Sender<RLPxSendMessage>;

struct StreamHandle {
    sender: PeerSender,
    capabilities: HashMap<CapabilityName, BTreeSet<usize>>,
}

enum PeerState {
    Connecting,
    Connected(StreamHandle),
}

impl PeerState {
    const fn is_connected(&self) -> bool {
        if let Self::Connected(_) = self {
            true
        } else {
            false
        }
    }

    const fn get_handle(&self) -> Option<&StreamHandle> {
        if let Self::Connected(handle) = self {
            Some(handle)
        } else {
            None
        }
    }
}

struct StreamMapEntry<Io> {
    inner: SplitStream<PeerStream<Io>>,
    done: bool,
}

impl<Io> From<SplitStream<PeerStream<Io>>> for StreamMapEntry<Io> {
    fn from(inner: SplitStream<PeerStream<Io>>) -> Self {
        Self { inner, done: false }
    }
}

enum PeerStreamUpdate {
    Data((CapabilityInfo, usize, Bytes)),
    Error(io::Error),
    Finished,
}

impl<Io: AsyncRead + AsyncWrite + Unpin> Stream for StreamMapEntry<Io> {
    type Item = PeerStreamUpdate;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        if let Poll::Ready(res) = Pin::new(&mut this.inner).poll_next(cx) {
            match res {
                Some(Ok(data)) => Poll::Ready(Some(PeerStreamUpdate::Data(data))),
                Some(Err(e)) => {
                    this.done = true;
                    Poll::Ready(Some(PeerStreamUpdate::Error(e)))
                }
                None => {
                    this.done = true;
                    Poll::Ready(Some(PeerStreamUpdate::Finished))
                }
            }
        } else {
            Poll::Pending
        }
    }
}

struct PeerStreams<Io> {
    streams: StreamMap<H512, StreamMapEntry<Io>>,
    /// Mapping of remote IDs to streams in `StreamMap`
    mapping: HashMap<H512, PeerState>,
}

impl<Io> Default for PeerStreams<Io> {
    fn default() -> Self {
        Self {
            streams: StreamMap::new(),
            mapping: HashMap::new(),
        }
    }
}

type DisconnectCb = Box<dyn FnOnce(bool) + Send + 'static>;

/// Removes peer from internal state on request.
async fn disconnecter_task<S>(
    mut disconnect_requests: S,
    streams: Arc<Mutex<PeerStreams<TcpStream>>>,
    mut newly_disconnected_notify: tokio::sync::mpsc::Sender<H512>,
) where
    S: Stream<Item = (H512, Option<DisconnectCb>)> + Send + Unpin,
{
    while let Some((remote_id, disconnect_cb)) = disconnect_requests.next().await {
        debug!("disconnecting peer {}", remote_id);

        let peer_dropped = {
            let mut s = streams.lock();
            let PeerStreams { streams, mapping } = &mut *s;
            // If this was a known peer, remove it.
            if mapping.remove(&remote_id).is_some() {
                // If the connection was successfully established, drop it.
                streams.remove(&remote_id).unwrap();
                true
            } else {
                false
            }
        };
        let _ = newly_disconnected_notify.send(remote_id).await;
        if let Some(disconnect_cb) = disconnect_cb {
            (disconnect_cb)(peer_dropped)
        }
    }
}

#[derive(Clone)]
struct PeerStreamHandshakeData {
    port: u16,
    protocol_version: usize,
    secret_key: SecretKey,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
}

async fn handle_incoming(
    task_group: Weak<TaskGroup>,
    mut tcp_incoming: TcpListener,
    handshake_data: PeerStreamHandshakeData,
    streams: Arc<Mutex<PeerStreams<TcpStream>>>,
    newly_connected: tokio::sync::mpsc::Sender<(H512, Vec<CapabilityInfo>)>,
    disconnecter: tokio::sync::mpsc::UnboundedSender<(H512, Option<DisconnectCb>)>,
) {
    loop {
        match tcp_incoming.accept().await {
            Err(e) => {
                error!("failed to accept peer: {:?}, shutting down", e);
                return;
            }
            Ok((stream, _remote_addr)) => {
                if let Some(tasks) = task_group.upgrade() {
                    let f = handle_incoming_request(
                        stream,
                        handshake_data.clone(),
                        streams.clone(),
                        newly_connected.clone(),
                        disconnecter.clone(),
                    );
                    tasks.spawn(f);
                }
            }
        }
    }
}

/// Establishes the connection with peer and adds them to internal state.
async fn handle_incoming_request<Io: AsyncRead + AsyncWrite + Send + Unpin>(
    stream: Io,
    handshake_data: PeerStreamHandshakeData,
    streams: Arc<Mutex<PeerStreams<Io>>>,

    mut newly_connected: tokio::sync::mpsc::Sender<(H512, Vec<CapabilityInfo>)>,
    disconnecter: tokio::sync::mpsc::UnboundedSender<(H512, Option<DisconnectCb>)>,
) {
    let PeerStreamHandshakeData {
        secret_key,
        protocol_version,
        client_version,
        capabilities,
        port,
    } = handshake_data;
    // Do handshake and convert incoming connection into stream.
    let peer_res = PeerStream::incoming(
        stream,
        secret_key,
        protocol_version,
        client_version,
        capabilities,
        port,
    )
    .await;
    match peer_res {
        Ok(peer) => {
            let (remote_id, capabilities, mut peer_sender_rx, mut sink) = {
                let remote_id = peer.remote_id();
                let mut s = streams.lock();
                let PeerStreams { streams, mapping } = &mut *s;
                let peer_state = mapping.entry(remote_id).or_insert(PeerState::Connecting);
                if peer_state.is_connected() {
                    // Turns out that remote peer's already connected. Drop connection request.
                    warn!("we are already connected to remote peer {}!", remote_id);
                    return;
                }
                // If we are connecting, incoming connection request takes precedence
                debug!("new peer connected: {}", remote_id);
                let capabilities = peer.capabilities().to_vec();
                let (sink, stream) = futures::StreamExt::split(peer);
                let (peer_sender_tx, peer_sender_rx) = tokio::sync::mpsc::channel(1);

                assert!(streams.insert(remote_id, stream.into()).is_none());
                *peer_state = PeerState::Connected(StreamHandle {
                    sender: peer_sender_tx,
                    capabilities: {
                        let mut v = HashMap::<CapabilityName, BTreeSet<usize>>::new();
                        for cap in &capabilities {
                            v.entry(cap.name).or_default().insert(cap.version);
                        }
                        v
                    },
                });

                (remote_id, capabilities, peer_sender_rx, sink)
            };
            let _ = newly_connected.send((remote_id, capabilities)).await;

            while let Some(RLPxSendMessage {
                capability_name,
                id,
                data,
            }) = peer_sender_rx.recv().await
            {
                if let Err(e) = sink.send((capability_name, id, data)).await {
                    debug!("peer disconnected with error {:?}", e);
                    let _ = disconnecter.send((remote_id, None));
                }
            }
        }
        Err(e) => {
            error!("peer disconnected with error {}", e);
        }
    }
}

/// RLPx server
pub struct Server {
    #[allow(unused)]
    tasks: Arc<TaskGroup>,

    streams: Arc<Mutex<PeerStreams<TcpStream>>>,

    node_filter: Arc<Mutex<dyn NodeFilter>>,

    protocol_handlers: Arc<Mutex<HashMap<CapabilityName, IngressHandler<IngressPeerTokenImpl>>>>,

    newly_connected_tx: tokio::sync::mpsc::Sender<(H512, Vec<CapabilityInfo>)>,
    newly_connected: tokio::sync::mpsc::Receiver<(H512, Vec<CapabilityInfo>)>,
    newly_disconnected: tokio::sync::mpsc::Receiver<H512>,
    disconnect_cmd_tx: tokio::sync::mpsc::UnboundedSender<(H512, Option<DisconnectCb>)>,

    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: u16,
}

pub struct CapabilityFilter {
    pub name: CapabilityName,
    pub versions: BTreeSet<usize>,
}

const PROTOCOL_VERSION: usize = 4;

pub struct ListenOptions {
    pub discovery: Option<Arc<AsyncMutex<dyn Discovery>>>,
    pub max_peers: usize,
    pub addr: SocketAddr,
}

/// This is an asynchronous devp2p server implementation.
///
/// `Server` is the RLPx server handle that supports adding and removing peers and
/// supports registration for capability servers.
///
/// This implementation is based on the concept of structured concurrency.
/// Internal state is managed by a multitude of workers that run in separate runtime tasks
/// spawned on the running executor during the server creation and addition of new peers.
/// All continuously running workers are inside the task scope owned by the server struct.
impl Server {
    /// Create a new devp2p server
    pub async fn new(
        // runtime: R,
        secret_key: SecretKey,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        listen_options: Option<ListenOptions>,
    ) -> Result<Arc<Self>, io::Error> {
        let tasks = Arc::new(TaskGroup::default());
        let (newly_connected_tx, newly_connected) = tokio::sync::mpsc::channel(1);
        let (newly_disconnected_tx, newly_disconnected) = tokio::sync::mpsc::channel(1);

        let port = listen_options
            .as_ref()
            .map_or(0, |options| options.addr.port());

        let streams = Arc::new(Mutex::new(PeerStreams::default()));
        let node_filter = Arc::new(Mutex::new(MemoryNodeFilter::new(Arc::new(
            listen_options
                .as_ref()
                .map_or(0.into(), |options| options.max_peers.into()),
        ))));

        let protocol_handlers = Arc::new(Mutex::new(Default::default()));

        let (disconnect_cmd_tx, disconnect_requests) =
            tokio::sync::mpsc::unbounded_channel::<(_, Option<DisconnectCb>)>();

        tasks.spawn(disconnecter_task(
            disconnect_requests,
            streams.clone(),
            newly_disconnected_tx.clone(),
        ));

        if let Some(options) = &listen_options {
            let tcp_incoming = TcpListener::bind(options.addr).await?;
            tasks.spawn(handle_incoming(
                Arc::downgrade(&tasks),
                tcp_incoming,
                PeerStreamHandshakeData {
                    port,
                    protocol_version: PROTOCOL_VERSION,
                    secret_key,
                    client_version: client_version.clone(),
                    capabilities: capabilities.clone(),
                },
                streams.clone(),
                newly_connected_tx.clone(),
                disconnect_cmd_tx.clone(),
            ));
        }

        let server = Arc::new(Self {
            tasks: tasks.clone(),
            streams,
            node_filter,
            protocol_handlers,
            secret_key,
            protocol_version: PROTOCOL_VERSION,
            client_version,
            capabilities,
            newly_connected,
            newly_connected_tx,
            newly_disconnected,
            disconnect_cmd_tx,
            port,
        });

        // TODO: Use semaphore
        if let Some(discovery) = listen_options.and_then(|options| options.discovery) {
            tasks.spawn({
                let server = Arc::downgrade(&server);
                async move {
                    loop {
                        if let Some(server) = server.upgrade() {
                            let mut discovery = discovery.lock().await;

                            let streams_len = server.streams.lock().mapping.len();

                            if streams_len < server.node_filter.lock().max_peers() {
                                match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    discovery.get_new_peer(),
                                )
                                .await
                                .unwrap_or_else(|_| {
                                    Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
                                }) {
                                    Ok((addr, remote_id)) => {
                                        if let Err(e) = server.add_peer(addr, remote_id).await {
                                            warn!("Failed to add new peer: {}", e);
                                        }
                                    }
                                    Err(e) => warn!("Failed to get new peer: {}", e),
                                }
                            }

                            tokio::time::delay_for(Duration::from_secs(2)).await;
                        } else {
                            return;
                        }
                    }
                }
            });
        }

        Ok(server)
    }

    /// Add a new peer to this `RLPx` stream. Returns `true` if it was inserted successfully (did not exist before, accepted by node filter).
    pub fn add_peer(
        &self,
        addr: SocketAddr,
        remote_id: H512,
    ) -> impl Future<Output = io::Result<bool>> + Send + 'static {
        let tasks_handle = Arc::downgrade(&self.tasks);

        let node_filter = self.node_filter.clone();
        let streams = self.streams.clone();
        let disconnect_cmd_tx = self.disconnect_cmd_tx.clone();
        let mut newly_connected = self.newly_connected_tx.clone();

        let secret_key = self.secret_key;
        let protocol_version = self.protocol_version;
        let client_version = self.client_version.clone();
        let capabilities = self.capabilities.clone();
        let port = self.port;

        async move {
            let mut inserted = false;
            {
                let mut streams = streams.lock();
                let node_filter = node_filter.lock();

                let connection_num = streams.mapping.len();

                match streams.mapping.entry(remote_id) {
                    Entry::Occupied(key) => {
                        warn!(
                            "we are already {} to remote peer {}!",
                            if key.get().is_connected() {
                                "connected"
                            } else {
                                "connecting"
                            },
                            remote_id
                        );
                    }
                    Entry::Vacant(vacant) => {
                        if node_filter.allow(connection_num, remote_id) {
                            info!("connecting to peer {}", remote_id);
                            vacant.insert(PeerState::Connecting);
                            inserted = true;
                        }
                    }
                }
            }

            if !inserted {
                return Ok(false);
            }

            // Connecting to peer is a long running operation so we have to break the mutex lock.
            let peer_res = async {
                let transport = TcpStream::connect(addr).await?;
                PeerStream::connect(
                    transport,
                    secret_key,
                    remote_id,
                    protocol_version,
                    client_version,
                    capabilities,
                    port,
                )
                .await
            }
            .await;
            let newly_connected_data = {
                let mut s = streams.lock();
                let PeerStreams { streams, mapping } = &mut *s;

                // Adopt the new connection if the peer has not been dropped or superseded by incoming connection.
                if let Entry::Occupied(mut peer_state) = mapping.entry(remote_id) {
                    if !peer_state.get().is_connected() {
                        match peer_res {
                            Ok(peer) => {
                                assert_eq!(peer.remote_id(), remote_id);
                                debug!("new peer connected: {}", remote_id);
                                let capabilities = peer.capabilities().to_vec();
                                let (mut sink, stream) = futures::StreamExt::split(peer);
                                let (peer_sender_tx, mut peer_sender_rx) =
                                    tokio::sync::mpsc::channel(1);

                                // Outgoing router -> PeerStream connector
                                if let Some(tasks) = tasks_handle.upgrade() {
                                    tasks.spawn(async move {
                                        while let Some(RLPxSendMessage {
                                            capability_name,
                                            id,
                                            data,
                                        }) = peer_sender_rx.recv().await
                                        {
                                            if let Err(e) =
                                                sink.send((capability_name, id, data)).await
                                            {
                                                debug!("peer disconnected with error {:?}", e);
                                                let _ = disconnect_cmd_tx
                                                    .clone()
                                                    .send((remote_id, None));
                                                return;
                                            }
                                        }
                                    });
                                }
                                assert!(streams.insert(remote_id, stream.into()).is_none());
                                *peer_state.get_mut() = PeerState::Connected(StreamHandle {
                                    sender: peer_sender_tx,
                                    capabilities: {
                                        let mut v =
                                            HashMap::<CapabilityName, BTreeSet<usize>>::new();
                                        for cap in &capabilities {
                                            v.entry(cap.name).or_default().insert(cap.version);
                                        }
                                        v
                                    },
                                });
                                drop(s);

                                Some((remote_id, capabilities))
                            }
                            Err(e) => {
                                error!("peer disconnected with error {}", e);
                                peer_state.remove();
                                return Err(e);
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some((remote_id, capabilities)) = newly_connected_data {
                let _ = newly_connected.send((remote_id, capabilities)).await;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub fn disconnect_peer(&self, remote_id: H512) -> impl Future<Output = bool> + Send + 'static {
        let (cb_tx, disconnection_res) = tokio::sync::oneshot::channel();
        let disconnecter_alive = self
            .disconnect_cmd_tx
            .send((
                remote_id,
                Some(Box::new(move |b| {
                    let _ = cb_tx.send(b);
                })),
            ))
            .is_err();

        async move {
            if !disconnecter_alive {
                return false;
            }
            disconnection_res.await.unwrap_or(false)
        }
    }

    /// Active peers
    #[must_use]
    pub fn active_peers(&self) -> HashSet<H512> {
        self.streams.lock().mapping.keys().copied().collect()
    }

    /// Get peers by capability with desired limit.
    #[must_use]
    pub fn connected_peers(
        &self,
        limit: impl Fn(usize) -> usize,
        filter: Option<&CapabilityFilter>,
    ) -> HashMap<H512, PeerSender> {
        let peers = self.streams.lock();

        let peer_num = peers.mapping.len();

        peers
            .mapping
            .iter()
            .filter(|(_, peer)| {
                match peer {
                    PeerState::Connecting => {
                        // Peer is connecting, not yet live
                        return false;
                    }
                    PeerState::Connected(handle) => {
                        // Check if peer supports capability
                        if let Some(cap_filter) = &filter {
                            if let Some(versions) = handle.capabilities.get(&cap_filter.name) {
                                if cap_filter.versions.is_empty() {
                                    // No cap version filter
                                    return true;
                                }

                                if !cap_filter.versions.is_disjoint(versions) {
                                    // We have an intersection of at least *some* versions
                                    return true;
                                }
                            }
                        } else {
                            // No cap filter
                            return true;
                        }
                    }
                };
                false
            })
            // TODO: what if user holds sender past peer drop?
            .map(|(remote_id, state)| (*remote_id, state.get_handle().unwrap().sender.clone()))
            .take((limit)(peer_num))
            .collect()
    }
}

impl ProtocolRegistrar for Arc<Server> {
    type ServerHandle = ServerHandleImpl;
    type IngressPeerToken = IngressPeerTokenImpl;

    fn register_incoming_handler(
        &self,
        protocol: CapabilityName,
        handler: IngressHandler<Self::IngressPeerToken>,
    ) -> Self::ServerHandle {
        self.protocol_handlers.lock().insert(protocol, handler);
        let pool = Arc::downgrade(&self);
        Self::ServerHandle { pool }
    }
}
