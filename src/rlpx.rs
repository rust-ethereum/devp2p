//! `RLPx` protocol implementation in Rust

use crate::{node_filter::*, peer::*, types::*, util::*};
use async_trait::async_trait;
use bytes::Bytes;
use discv5::Discv5;
use ethereum_types::H512;
use futures::{sink::SinkExt, stream::SplitStream};
use libsecp256k1::SecretKey;
use log::*;
use parking_lot::Mutex;
use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Display,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt},
    sync::Mutex as AsyncMutex,
};

const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_TIMEOUT_SECS: u64 = 5;

pub struct EgressPeerHandleImpl {
    capability: CapabilityName,
    capability_version: usize,
    peer_id: PeerId,
    sender: tokio::sync::mpsc::Sender<RLPxSendMessage>,
}

#[async_trait]
impl EgressPeerHandle for EgressPeerHandleImpl {
    fn capability_version(&self) -> usize {
        self.capability_version
    }
    fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    async fn send_message(mut self, Message { id, data }: Message) -> Result<(), PeerSendError> {
        self.sender
            .send(RLPxSendMessage {
                id,
                capability_name: self.capability.clone(),
                data,
            })
            .await
            .map_err(|_| PeerSendError::PeerGone);

        Ok(())
    }
}

pub struct ServerHandleImpl {
    capabilities: BTreeSet<CapabilityId>,
    pool: Weak<Server>,
}

impl Drop for ServerHandleImpl {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            let mut streams = pool.streams.lock();
            let mut protocols = pool.protocols.lock();

            // Kick all peers with capability
            streams.mapping.retain(|_, state| match state {
                PeerState::Connecting => false,
                PeerState::Connected(handle) => handle.capabilities.is_disjoint(&self.capabilities),
            });

            // Remove protocol handler
            protocols.delete_capabilities(&self.capabilities)
        }
    }
}

#[async_trait]
impl ServerHandle for ServerHandleImpl {
    type EgressPeerHandle = EgressPeerHandleImpl;

    async fn get_peers(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
    ) -> Result<Vec<Self::EgressPeerHandle>, Shutdown> {
        let pool = self.pool.upgrade().ok_or(Shutdown)?;
        Ok(pool
            .connected_peers(|_| 1, Some(&CapabilityFilter { name, versions }))
            .into_iter()
            .map(|(peer_id, (sender, capabilities))| EgressPeerHandleImpl {
                capability: name,
                capability_version: capabilities[&name],
                peer_id,
                sender,
            })
            .collect())
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
    tasks: TaskGroup,
    capabilities: BTreeSet<CapabilityId>,
    notes: HashMap<String, String>,
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

    fn get_handle_mut(&mut self) -> Option<&mut StreamHandle> {
        if let Self::Connected(handle) = self {
            Some(handle)
        } else {
            None
        }
    }
}

struct PeerStreams {
    /// Mapping of remote IDs to streams in `StreamMap`
    mapping: HashMap<PeerId, PeerState>,
}

impl PeerStreams {
    fn disconnect_peer(&mut self, remote_id: PeerId) -> bool {
        debug!("disconnecting peer {}", remote_id);

        self.mapping.remove(&remote_id).is_some()
    }
}

impl Default for PeerStreams {
    fn default() -> Self {
        Self {
            mapping: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct PeerStreamHandshakeData {
    port: u16,
    protocol_version: ProtocolVersion,
    secret_key: SecretKey,
    client_version: String,
    capabilities: Arc<Mutex<CapabilityMap>>,
}

async fn handle_incoming(
    task_group: Weak<TaskGroup>,
    streams: Arc<Mutex<PeerStreams>>,
    node_filter: Arc<Mutex<dyn NodeFilter>>,
    mut tcp_incoming: TcpListener,
    handshake_data: PeerStreamHandshakeData,
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
                        streams.clone(),
                        node_filter.clone(),
                        stream,
                        handshake_data.clone(),
                    );
                    tasks.spawn(f);
                }
            }
        }
    }
}

fn setup_peer_state<Io: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    streams: Arc<Mutex<PeerStreams>>,
    capabilities: Arc<Mutex<CapabilityMap>>,
    remote_id: PeerId,
    peer: PeerStream<Io>,
) -> StreamHandle {
    let capability_set = peer
        .capabilities()
        .iter()
        .copied()
        .map(From::from)
        .collect::<BTreeSet<_>>();
    let (mut sink, mut stream) = futures::StreamExt::split(peer);
    let (peer_sender_tx, mut peer_sender_rx) = tokio::sync::mpsc::channel(1);
    let tasks = TaskGroup::default();
    // Ingress router
    tasks.spawn({
        let streams = streams.clone();
        let capabilities = capabilities.clone();
        let mut peer_sender_tx = peer_sender_tx.clone();
        async move {
            while let Some(message) = stream.next().await {
                match message {
                    Ok((capability, message_id, message)) => {
                        // Extract capability's ingress handler
                        let handler = capabilities.lock().get_inner().get(&capability.into()).map(
                            |CapabilityData {
                                 incoming_handler, ..
                             }| incoming_handler.clone(),
                        );

                        // Actually handle the message
                        if let Some(handler) = handler {
                            let (message, report) = (handler)(
                                IngressPeer {
                                    id: remote_id,
                                    capability: capability.into(),
                                },
                                message_id,
                                message,
                            )
                            .await
                            .unwrap_or_else(|err| {
                                debug!("Ingress handler error: {:?}", err);
                                (None, err.to_reputation_report())
                            });

                            // Check reputation report
                            match report {
                                Some(ReputationReport::Kick) | Some(ReputationReport::Ban) => {
                                    debug!("Received damning report about peer, disconnecting");
                                    break;
                                }
                                _ => {
                                    // TODO: ignore other reputation reports for now
                                }
                            }

                            // And send any reply if necessary
                            if let Some((id, data)) = message {
                                let _ = peer_sender_tx
                                    .send(RLPxSendMessage {
                                        capability_name: capability.name,
                                        id,
                                        data,
                                    })
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Peer incoming error: {}", e);
                        break;
                    }
                }
            }

            streams.lock().disconnect_peer(remote_id);
        }
    });
    // Egress router
    tasks.spawn({
        let capability_set = capability_set.clone();
        async move {
            // Send initial messages
            let messages = capabilities
                .lock()
                .get_inner()
                .iter()
                .filter_map(|(cap, data)| {
                    if capability_set.contains(cap) {
                        Some((data.on_peer_connect)())
                    } else {
                        None
                    }
                });

            while let Some(RLPxSendMessage {
                capability_name,
                id,
                data,
            }) = peer_sender_rx.recv().await
            {
                if let Err(e) = sink.send((capability_name, id, data)).await {
                    debug!("peer disconnected with error {:?}", e);
                    streams.lock().disconnect_peer(remote_id);
                }
            }
        }
    });
    StreamHandle {
        sender: peer_sender_tx,
        tasks,
        capabilities: capability_set,
        notes: Default::default(),
    }
}

/// Establishes the connection with peer and adds them to internal state.
async fn handle_incoming_request<Io: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    streams: Arc<Mutex<PeerStreams>>,
    node_filter: Arc<Mutex<dyn NodeFilter>>,
    stream: Io,
    handshake_data: PeerStreamHandshakeData,
) {
    let PeerStreamHandshakeData {
        secret_key,
        protocol_version,
        client_version,
        capabilities,
        port,
    } = handshake_data;
    let capability_set = capabilities.lock().get_capabilities().to_vec();
    // Do handshake and convert incoming connection into stream.
    let peer_res = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        PeerStream::incoming(
            stream,
            secret_key,
            protocol_version,
            client_version,
            capability_set,
            port,
        ),
    )
    .await
    .unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "incoming connection timeout",
        ))
    });
    match peer_res {
        Ok(peer) => {
            let remote_id = peer.remote_id();
            let s = streams.clone();
            let mut s = s.lock();
            let node_filter = node_filter.clone();
            let PeerStreams { mapping } = &mut *s;
            let total_connections = mapping.len();

            match mapping.entry(remote_id) {
                Entry::Occupied(entry) => {
                    warn!(
                        "We are already {} to remote peer {}!",
                        if entry.get().is_connected() {
                            "connected"
                        } else {
                            "connecting"
                        },
                        remote_id
                    );
                }
                Entry::Vacant(entry) => {
                    if node_filter.lock().allow(total_connections, remote_id) {
                        debug!("New peer connected: {}", remote_id);
                        entry.insert(PeerState::Connected(setup_peer_state(
                            streams,
                            capabilities,
                            remote_id,
                            peer,
                        )));
                    } else {
                        trace!("Node filter rejected peer {}, disconnecting", remote_id);
                    }
                }
            }
        }
        Err(e) => {
            error!("Peer disconnected with error {}", e);
        }
    }
}

struct CapabilityData {
    length: usize,
    incoming_handler: IngressHandler,
    on_peer_connect: OnPeerConnect,
}

#[derive(Default)]
struct CapabilityMap {
    inner: BTreeMap<CapabilityId, CapabilityData>,

    capability_cache: Vec<CapabilityInfo>,
}

impl CapabilityMap {
    fn update_cache(&mut self) {
        self.capability_cache = self
            .inner
            .iter()
            .map(
                |(&CapabilityId { name, version }, &CapabilityData { length, .. })| {
                    CapabilityInfo {
                        name,
                        version,
                        length,
                    }
                },
            )
            .collect();
    }

    fn register_capabilities(
        &mut self,
        caps: BTreeMap<CapabilityId, usize>,
        incoming_handler: &IngressHandler,
        on_peer_connect: &OnPeerConnect,
    ) {
        for (id, length) in caps {
            let incoming_handler = incoming_handler.clone();
            let on_peer_connect = on_peer_connect.clone();
            self.inner.insert(
                id,
                CapabilityData {
                    length,
                    incoming_handler,
                    on_peer_connect,
                },
            );
        }

        self.update_cache()
    }

    fn delete_capabilities<'a>(&mut self, caps: impl IntoIterator<Item = &'a CapabilityId>) {
        for cap in caps {
            self.inner.remove(cap);
        }

        self.update_cache()
    }

    fn get_capabilities(&self) -> &[CapabilityInfo] {
        &self.capability_cache
    }

    fn get_inner(&self) -> &BTreeMap<CapabilityId, CapabilityData> {
        &self.inner
    }
}

/// RLPx server
pub struct Server {
    #[allow(unused)]
    tasks: Arc<TaskGroup>,

    streams: Arc<Mutex<PeerStreams>>,

    node_filter: Arc<Mutex<dyn NodeFilter>>,

    protocols: Arc<Mutex<CapabilityMap>>,

    secret_key: SecretKey,
    protocol_version: ProtocolVersion,
    client_version: String,
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
        listen_options: Option<ListenOptions>,
    ) -> Result<Arc<Self>, io::Error> {
        let tasks = Arc::new(TaskGroup::default());

        let port = listen_options
            .as_ref()
            .map_or(0, |options| options.addr.port());

        let streams = Arc::new(Mutex::new(PeerStreams::default()));
        let node_filter = Arc::new(Mutex::new(MemoryNodeFilter::new(Arc::new(
            listen_options
                .as_ref()
                .map_or(0.into(), |options| options.max_peers.into()),
        ))));

        let protocols = Arc::new(Mutex::new(Default::default()));

        if let Some(options) = &listen_options {
            let tcp_incoming = TcpListener::bind(options.addr).await?;
            tasks.spawn(handle_incoming(
                Arc::downgrade(&tasks),
                streams.clone(),
                node_filter.clone(),
                tcp_incoming,
                PeerStreamHandshakeData {
                    port,
                    protocol_version: ProtocolVersion::V5,
                    secret_key,
                    client_version: client_version.clone(),
                    capabilities: protocols.clone(),
                },
            ));
        }

        let server = Arc::new(Self {
            tasks: tasks.clone(),
            streams,
            node_filter,
            protocols,
            secret_key,
            protocol_version: ProtocolVersion::V5,
            client_version,
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
                                    Duration::from_secs(DISCOVERY_TIMEOUT_SECS),
                                    discovery.get_new_peer(),
                                )
                                .await
                                .unwrap_or_else(|_| {
                                    Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
                                }) {
                                    Ok((addr, remote_id)) => {
                                        if let Err(e) =
                                            server.add_peer_inner(addr, remote_id, true).await
                                        {
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
        node_record: NodeRecord,
    ) -> impl Future<Output = io::Result<bool>> + Send + 'static {
        let NodeRecord { addr, id } = node_record;
        self.add_peer_inner(addr, id, false)
    }

    fn add_peer_inner(
        &self,
        addr: SocketAddr,
        remote_id: PeerId,
        check_peer: bool,
    ) -> impl Future<Output = io::Result<bool>> + Send + 'static {
        let streams = self.streams.clone();
        let node_filter = self.node_filter.clone();

        let capabilities = self.protocols.clone();
        let capability_set = capabilities.lock().get_capabilities().to_vec();

        let secret_key = self.secret_key;
        let protocol_version = self.protocol_version;
        let client_version = self.client_version.clone();
        let port = self.port;

        async move {
            trace!("Received request to add peer {}", remote_id);
            let mut inserted = false;
            {
                trace!("locking streams");
                let mut streams = streams.lock();
                trace!("locking node_filter");
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
                        if check_peer && !node_filter.allow(connection_num, remote_id) {
                            trace!("rejecting peer {}", remote_id);
                        } else {
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
                    capability_set.clone(),
                    port,
                )
                .await
            }
            .await;

            let s = streams.clone();
            let mut s = s.lock();
            let PeerStreams { mapping } = &mut *s;

            // Adopt the new connection if the peer has not been dropped or superseded by incoming connection.
            if let Entry::Occupied(mut peer_state) = mapping.entry(remote_id) {
                if !peer_state.get().is_connected() {
                    match peer_res {
                        Ok(peer) => {
                            assert_eq!(peer.remote_id(), remote_id);
                            debug!("new peer connected: {}", remote_id);

                            *peer_state.get_mut() = PeerState::Connected(setup_peer_state(
                                streams,
                                capabilities,
                                remote_id,
                                peer,
                            ));

                            return Ok(true);
                        }
                        Err(e) => {
                            error!("peer disconnected with error {}", e);
                            peer_state.remove();
                            return Err(e);
                        }
                    }
                }
            }

            Ok(false)
        }
    }

    /// Add a note to the peer
    #[must_use]
    pub fn note_peer(&self, remote_id: PeerId, key: impl Display, value: impl Display) -> bool {
        if let Some(peer) = self.streams.lock().mapping.get_mut(&remote_id) {
            if let Some(state) = peer.get_handle_mut() {
                state.notes.insert(key.to_string(), value.to_string());

                return true;
            }
        }

        false
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    #[must_use]
    pub fn disconnect_peer(&self, remote_id: PeerId) -> bool {
        self.streams.lock().disconnect_peer(remote_id)
    }

    /// Active peers
    #[must_use]
    pub fn active_peers(&self) -> HashSet<PeerId> {
        self.streams.lock().mapping.keys().copied().collect()
    }

    /// Get peers by capability with desired limit.
    #[must_use]
    pub fn connected_peers(
        &self,
        limit: impl Fn(usize) -> usize,
        filter: Option<&CapabilityFilter>,
    ) -> HashMap<PeerId, (PeerSender, BTreeMap<CapabilityName, usize>)> {
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
                            if cap_filter.versions.is_empty() {
                                // No cap version filter
                                for cap in &handle.capabilities {
                                    if cap.name == cap_filter.name {
                                        return true;
                                    }
                                }
                            } else if !handle.capabilities.is_disjoint(
                                &cap_filter
                                    .versions
                                    .iter()
                                    .map(|&version| CapabilityId {
                                        name: cap_filter.name,
                                        version,
                                    })
                                    .collect(),
                            ) {
                                // We have an intersection of at least *some* versions
                                return true;
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
            .map(|(remote_id, state)| {
                let state = state.get_handle().unwrap();
                (
                    *remote_id,
                    (
                        state.sender.clone(),
                        state
                            .capabilities
                            .iter()
                            .map(|&CapabilityId { name, version }| (name, version))
                            .collect(),
                    ),
                )
            })
            .take((limit)(peer_num))
            .collect()
    }
}

impl ProtocolRegistrar for Arc<Server> {
    type ServerHandle = ServerHandleImpl;

    fn register_protocol_server(
        &self,
        capabilities: BTreeMap<CapabilityId, usize>,
        incoming_handler: IngressHandler,
        on_peer_connect: OnPeerConnect,
    ) -> Self::ServerHandle {
        let mut protocols = self.protocols.lock();
        protocols.register_capabilities(capabilities.clone(), &incoming_handler, &on_peer_connect);
        let pool = Arc::downgrade(self);
        Self::ServerHandle {
            pool,
            capabilities: capabilities.keys().copied().collect(),
        }
    }
}
