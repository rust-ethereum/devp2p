//! RLPx protocol implementation in Rust

use crate::{disc::*, node_filter::*, peer::*, types::*};
use anyhow::anyhow;
use async_trait::async_trait;
use derivative::Derivative;
use futures::sink::SinkExt;
use k256::ecdsa::SigningKey;
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::{Debug, Display},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    time::Duration,
};
use task_group::TaskGroup;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::{self, Stream, StreamExt},
    sync::Mutex as AsyncMutex,
};
use tracing::*;
use uuid::Uuid;

const GRACE_PERIOD_SECS: u64 = 2;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_TIMEOUT_SECS: u64 = 5;
const DISCOVERY_CONNECT_TIMEOUT_SECS: u64 = 5;

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
    async fn send_message(mut self, message: Message) -> Result<(), PeerSendError> {
        self.sender
            .send(RLPxSendMessage {
                capability_name: self.capability,
                message,
            })
            .await
            .map_err(|_| PeerSendError::PeerGone)?;

        Ok(())
    }
}

pub struct ServerHandleImpl {
    capability: CapabilityId,
    pool: Weak<Server>,
}

impl Drop for ServerHandleImpl {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            let mut streams = pool.streams.lock();
            let mut protocols = pool.protocols.write();

            // Kick all peers with capability
            streams.mapping.retain(|_, state| match state {
                PeerState::Connecting { .. } => false,
                PeerState::Connected(handle) => !handle.capabilities.contains(&self.capability),
            });

            // Remove protocol handler
            protocols.delete_capability(self.capability)
        }
    }
}

#[async_trait]
impl ServerHandle for ServerHandleImpl {
    type EgressPeerHandle = EgressPeerHandleImpl;

    async fn get_peers(
        &self,
        versions: BTreeSet<usize>,
        note: Option<(String, String)>,
    ) -> Result<Vec<Self::EgressPeerHandle>, Shutdown> {
        let pool = self.pool.upgrade().ok_or(Shutdown)?;
        Ok(pool
            .connected_peers(
                |_| 1,
                Some(&CapabilityFilter {
                    name: self.capability.name,
                    versions,
                }),
                note.as_ref(),
            )
            .into_iter()
            .map(|(peer_id, (sender, capabilities))| EgressPeerHandleImpl {
                capability: self.capability.name,
                capability_version: capabilities[&self.capability.name],
                peer_id,
                sender,
            })
            .collect())
    }
}

/// Sending message for RLPx
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLPxSendMessage {
    pub capability_name: CapabilityName,
    pub message: Message,
}

pub type PeerSender = tokio::sync::mpsc::Sender<RLPxSendMessage>;

#[derive(Debug)]
struct StreamHandle {
    sender: PeerSender,
    tasks: TaskGroup,
    capabilities: BTreeSet<CapabilityId>,
    notes: HashMap<String, String>,
}

#[derive(Debug)]
enum PeerState {
    Connecting { connection_id: Uuid },
    Connected(StreamHandle),
}

impl PeerState {
    const fn is_connected(&self) -> bool {
        matches!(self, Self::Connected(_))
    }
}

#[derive(Debug)]
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
    secret_key: Arc<SigningKey>,
    client_version: String,
    capabilities: Arc<RwLock<CapabilityMap>>,
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

/// Set up newly connected peer's state, start its tasks
fn setup_peer_state<Io: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static>(
    streams: Arc<Mutex<PeerStreams>>,
    capabilities: Arc<RwLock<CapabilityMap>>,
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
    let (mut peer_disconnect_tx, peer_disconnect_rx) = tokio::sync::mpsc::channel(1);
    let (peer_sender_tx, peer_sender_rx) = tokio::sync::mpsc::channel(1);
    let tasks = TaskGroup::default();

    // Ingress router
    tasks.spawn({
        let capabilities = capabilities.clone();
        let peer_sender_tx = peer_sender_tx.clone();
        async move {
            let reason = {
                let mut peer_sender_tx = peer_sender_tx.clone();
                async move {
                    while let Some(message) = stream.next().await {
                        match message {
                            Ok((capability, message_id, message)) => {
                                // Extract capability's ingress handler
                                let handler =
                                    capabilities.read().get_inner().get(&capability.into()).map(
                                        |CapabilityMeta {
                                             protocol_server, ..
                                         }| {
                                            protocol_server.clone()
                                        },
                                    );

                                // Actually handle the message
                                if let Some(handler) = handler {
                                    let (message, report) = handler
                                        .on_ingress_message(
                                            IngressPeer {
                                                id: remote_id,
                                                capability: capability.into(),
                                            },
                                            Message {
                                                id: message_id,
                                                data: message,
                                            },
                                        )
                                        .await
                                        .unwrap_or_else(|err| {
                                            debug!("Ingress handler error: {:?}", err);
                                            (None, err.to_reputation_report())
                                        });

                                    // Check reputation report
                                    if let Some(ReputationReport::Kick { reason, .. }) = report {
                                        debug!("Received damning report about peer, disconnecting");
                                        return reason
                                            .unwrap_or(DisconnectReason::DisconnectRequested);
                                    }

                                    // And send any reply if necessary
                                    if let Some(message) = message {
                                        let _ = peer_sender_tx
                                            .send(RLPxSendMessage {
                                                capability_name: capability.name,
                                                message,
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

                    DisconnectReason::DisconnectRequested
                }
            }
            .await;

            let _ = peer_disconnect_tx.send(reason).await;
        }
        .instrument(span!(
            Level::DEBUG,
            "ingress router",
            "peer={}",
            remote_id.to_string(),
        ))
    });
    // Egress router & disconnector
    tasks.spawn({
        async move {
            // Send initial messages
            let mut useless_peer = false;
            let mut initial_messages = vec![];
            let caps = capabilities.read().get_inner().iter().map(|(cap, cap_info)| (cap.name, cap_info.protocol_server.clone())).collect::<Vec<_>>();
            for (capability_name, ps) in caps {
                if let PeerConnectOutcome::Retain { hello } =
                    ps.on_peer_connect(remote_id).await
                {
                    useless_peer = false;
                    if let Some(message) = hello {
                        initial_messages.push(RLPxSendMessage {
                            capability_name,
                            message,
                        });
                    }
                } else {
                    useless_peer = true;
                }
            }

            let mut peer_disconnect_rx: Pin<Box<dyn Stream<Item = DisconnectReason> + Send + Sync>> = if useless_peer {
                debug!("peer disavowed by all caps, disconnecting");
                Box::pin(stream::iter(vec![DisconnectReason::UselessPeer]))
            } else {
                Box::pin(peer_disconnect_rx)
            };
            let mut message_stream = stream::iter(initial_messages)
                .chain(peer_sender_rx)
                .map(|v| EgressMessage::Subprotocol {
                    cap_name: v.capability_name,
                    message: v.message,
                }).fuse();

            loop {
                let mut disconnecting = false;
                let message;
                tokio::select! {
                    v = message_stream.next() => {
                        match v {
                            Some(msg) => {
                                message = msg;
                            }
                            None => {
                                disconnecting = true;
                                message = EgressMessage::Disconnect { reason: DisconnectReason::DisconnectRequested };
                            }
                        }
                    },
                    v = peer_disconnect_rx.next() => {
                        disconnecting = true;
                        message = EgressMessage::Disconnect { reason: v.unwrap_or(DisconnectReason::DisconnectRequested) };
                    },
                };

                if let Err(e) = sink.send(message).await {
                    debug!("peer disconnected with error {:?}", e);
                    break;
                }

                if disconnecting {
                    tokio::time::delay_for(Duration::from_secs(GRACE_PERIOD_SECS)).await;
                    break;
                }
            }

            streams.lock().disconnect_peer(remote_id);
        }
        .instrument(span!(
            Level::DEBUG,
            "egress router",
            "peer={}",
            remote_id.to_string(),
        ))
    });
    StreamHandle {
        sender: peer_sender_tx,
        tasks,
        capabilities: capability_set,
        notes: Default::default(),
    }
}

/// Establishes the connection with peer and adds them to internal state.
async fn handle_incoming_request<Io: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static>(
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
    let capability_set = capabilities.read().get_capabilities().to_vec();
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
                        debug!("New incoming peer connected: {}", remote_id);
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
            debug!("Peer disconnected with error {}", e);
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
struct CapabilityMeta {
    length: usize,
    #[derivative(Debug = "ignore")]
    protocol_server: Arc<dyn CapabilityServer>,
}

#[derive(Debug, Default)]
struct CapabilityMap {
    inner: BTreeMap<CapabilityId, CapabilityMeta>,

    capability_cache: Vec<CapabilityInfo>,
}

impl CapabilityMap {
    fn update_cache(&mut self) {
        self.capability_cache = self
            .inner
            .iter()
            .map(
                |(&CapabilityId { name, version }, &CapabilityMeta { length, .. })| {
                    CapabilityInfo {
                        name,
                        version,
                        length,
                    }
                },
            )
            .collect();
    }

    fn register_capability(
        &mut self,
        id: CapabilityId,
        length: usize,
        protocol_server: Arc<dyn CapabilityServer>,
    ) {
        self.inner.insert(
            id,
            CapabilityMeta {
                length,
                protocol_server,
            },
        );

        self.update_cache()
    }

    fn delete_capability(&mut self, cap: CapabilityId) {
        self.inner.remove(&cap);

        self.update_cache()
    }

    fn get_capabilities(&self) -> &[CapabilityInfo] {
        &self.capability_cache
    }

    const fn get_inner(&self) -> &BTreeMap<CapabilityId, CapabilityMeta> {
        &self.inner
    }
}

/// This is an asynchronous RLPx server implementation.
///
/// `Server` is the RLPx server handle that supports adding and removing peers and
/// supports registration for capability servers.
///
/// This implementation is based on the concept of structured concurrency.
/// Internal state is managed by a multitude of workers that run in separate runtime tasks
/// spawned on the running executor during the server creation and addition of new peers.
/// All continuously running workers are inside the task scope owned by the server struct.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Server {
    #[allow(unused)]
    tasks: Arc<TaskGroup>,

    streams: Arc<Mutex<PeerStreams>>,

    node_filter: Arc<Mutex<dyn NodeFilter>>,

    protocols: Arc<RwLock<CapabilityMap>>,

    #[derivative(Debug = "ignore")]
    secret_key: Arc<SigningKey>,
    protocol_version: ProtocolVersion,
    client_version: String,
    port: u16,
}

/// Builder for ergonomically creating a new `Server`.
#[derive(Debug)]
pub struct ServerBuilder {
    task_group: Option<Arc<TaskGroup>>,
    listen_options: Option<ListenOptions>,
    client_version: String,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            task_group: None,
            listen_options: None,
            client_version: format!("rust-devp2p/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn with_task_group(&mut self, task_group: Arc<TaskGroup>) -> &mut Self {
        self.task_group = Some(task_group);
        self
    }

    pub fn with_listen_options(&mut self, options: ListenOptions) -> &mut Self {
        self.listen_options = Some(options);
        self
    }

    pub fn with_client_version(&mut self, version: String) -> &mut Self {
        self.client_version = version;
        self
    }

    /// Create a new RLPx node
    pub async fn build(&self, secret_key: SigningKey) -> Result<Arc<Server>, io::Error> {
        Server::new(
            secret_key,
            self.client_version.clone(),
            self.task_group.clone(),
            self.listen_options.clone(),
        )
        .await
    }
}

pub struct CapabilityFilter {
    pub name: CapabilityName,
    pub versions: BTreeSet<usize>,
}

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct ListenOptions {
    #[derivative(Debug = "ignore")]
    pub discovery_tasks: Vec<Arc<AsyncMutex<dyn Discovery>>>,
    pub max_peers: usize,
    pub addr: SocketAddr,
}

impl Server {
    async fn new(
        secret_key: SigningKey,
        client_version: String,
        task_group: Option<Arc<TaskGroup>>,
        listen_options: Option<ListenOptions>,
    ) -> Result<Arc<Self>, io::Error> {
        let tasks = task_group.unwrap_or_default();

        let secret_key = Arc::new(secret_key);

        let protocol_version = ProtocolVersion::V5;

        let port = listen_options
            .as_ref()
            .map_or(0, |options| options.addr.port());

        let streams = Arc::new(Mutex::new(PeerStreams::default()));
        let node_filter = Arc::new(Mutex::new(MemoryNodeFilter::new(Arc::new(
            listen_options
                .as_ref()
                .map_or(0.into(), |options| options.max_peers.into()),
        ))));

        let protocols = Arc::new(RwLock::new(Default::default()));

        if let Some(options) = &listen_options {
            let tcp_incoming = TcpListener::bind(options.addr).await?;
            tasks.spawn(handle_incoming(
                Arc::downgrade(&tasks),
                streams.clone(),
                node_filter.clone(),
                tcp_incoming,
                PeerStreamHandshakeData {
                    port,
                    protocol_version,
                    secret_key: secret_key.clone(),
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
            protocol_version,
            client_version,
            port,
        });

        // TODO: Use semaphore
        if let Some(options) = listen_options {
            let num = options.discovery_tasks.len();
            for discovery in options.discovery_tasks {
                if num > 0 {
                    tokio::time::delay_for(
                        Duration::from_secs(DISCOVERY_CONNECT_TIMEOUT_SECS) / num as u32,
                    )
                    .await;
                }
                tasks.spawn({
                    let server = Arc::downgrade(&server);
                    let tasks = Arc::downgrade(&tasks);
                    async move {
                        loop {
                            if let Some(server) = server.upgrade() {
                                let streams_len = server.streams.lock().mapping.len();
                                let max_peers = server.node_filter.lock().max_peers();

                                if streams_len < max_peers {
                                    trace!("Discovering peers as our peer count is too low: {} < {}", streams_len, max_peers);
                                    match tokio::time::timeout(
                                        Duration::from_secs(DISCOVERY_TIMEOUT_SECS),
                                        {
                                            let discovery = discovery.clone();
                                            async move {
                                                discovery.lock().await.get_new_peer().await
                                            }
                                        },
                                    )
                                    .await
                                    .unwrap_or_else(|_| {
                                        Err(anyhow!("timed out"))
                                    }) {
                                        Ok((addr, remote_id)) => {
                                            debug!("Discovered peer: {:?}", remote_id);
                                            if let Some(tasks) = tasks.upgrade() {
                                                tasks.spawn(async move {
                                                    if tokio::time::timeout(Duration::from_secs(DISCOVERY_CONNECT_TIMEOUT_SECS), server.add_peer_inner(addr, remote_id, true)).await.is_err() {
                                                        debug!("Timed out adding peer {}", remote_id);
                                                    }
                                                });
                                            }
                                        }
                                        Err(e) => warn!("Failed to get new peer: {}", e)
                                    }
                                    tokio::time::delay_for(Duration::from_millis(2000)).await;
                                } else {
                                    trace!("Skipping discovery as current number of peers is too high: {} >= {}", streams_len, max_peers);
                                    tokio::time::delay_for(Duration::from_secs(2)).await;
                                }
                            } else {
                                return;
                            }
                        }
                    }.instrument(span!(Level::DEBUG, "discovery", "#{}", num.to_string()))
                });
            }
        }

        Ok(server)
    }

    /// Add a new peer to this RLPx node. Returns `true` if it was added successfully (did not exist before, accepted by node filter).
    pub fn add_peer(
        &self,
        node_record: NodeRecord,
    ) -> impl Future<Output = io::Result<bool>> + Send + 'static {
        self.add_peer_inner(node_record.addr, node_record.id, false)
    }

    fn add_peer_inner(
        &self,
        addr: SocketAddr,
        remote_id: PeerId,
        check_peer: bool,
    ) -> impl Future<Output = io::Result<bool>> + Send + 'static {
        let tasks = self.tasks.clone();
        let streams = self.streams.clone();
        let node_filter = self.node_filter.clone();

        let capabilities = self.protocols.clone();
        let capability_set = capabilities.read().get_capabilities().to_vec();

        let secret_key = self.secret_key.clone();
        let protocol_version = self.protocol_version;
        let client_version = self.client_version.clone();
        let port = self.port;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let connection_id = Uuid::new_v4();

        // Start reaper task that will terminate this connection if connection future gets dropped.
        tasks.spawn({
            let cid = connection_id;
            let streams = streams.clone();
            async move {
                if rx.await.is_err() {
                    let mut s = streams.lock();
                    if let Entry::Occupied(entry) = s.mapping.entry(remote_id) {
                        // If this is the same connection attempt, then remove.
                        if let PeerState::Connecting { connection_id } = entry.get() {
                            if *connection_id == cid {
                                trace!("Reaping failed outbound connection: {}/{}", remote_id, cid);

                                entry.remove();
                            }
                        }
                    }
                }
            }
        });

        async move {
            trace!("Received request to add peer {}", remote_id);
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
                        if check_peer && !node_filter.allow(connection_num, remote_id) {
                            trace!("rejecting peer {}", remote_id);
                        } else {
                            info!("connecting to peer {}", remote_id);

                            vacant.insert(PeerState::Connecting { connection_id });
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
                            debug!("New peer connected: {}", remote_id);

                            *peer_state.get_mut() = PeerState::Connected(setup_peer_state(
                                streams,
                                capabilities,
                                remote_id,
                                peer,
                            ));

                            let _ = tx.send(());
                            return Ok(true);
                        }
                        Err(e) => {
                            debug!("peer disconnected with error {}", e);
                            peer_state.remove();
                            return Err(e);
                        }
                    }
                }
            }

            Ok(false)
        }
        .instrument(span!(Level::DEBUG, "add peer",))
    }

    /// Add a note to the peer
    #[must_use]
    pub fn note_peer(&self, remote_id: PeerId, key: impl Display, value: impl Display) -> bool {
        if let Some(PeerState::Connected(state)) = self.streams.lock().mapping.get_mut(&remote_id) {
            state.notes.insert(key.to_string(), value.to_string());

            return true;
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
        cap_filter: Option<&CapabilityFilter>,
        note_filter: Option<&(String, String)>,
    ) -> HashMap<PeerId, (PeerSender, BTreeMap<CapabilityName, usize>)> {
        let peers = self.streams.lock();

        let peer_num = peers.mapping.len();

        peers
            .mapping
            .iter()
            .filter_map(|(id, peer)| {
                match peer {
                    PeerState::Connecting { .. } => {
                        // Peer is connecting, not yet live
                        return None;
                    }
                    PeerState::Connected(handle) => {
                        // Check if peer supports capability
                        if let Some(cap_filter) = &cap_filter {
                            if cap_filter.versions.is_empty() {
                                // No cap version filter
                                for cap in &handle.capabilities {
                                    if cap.name == cap_filter.name {
                                        return Some((id, handle));
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
                                return Some((id, handle));
                            }
                        } else {
                            // No cap filter
                            return Some((id, handle));
                        }
                    }
                };
                None
            })
            .filter(|(_, peer)| {
                if let Some((key, value)) = &note_filter {
                    if let Some(v) = peer.notes.get(key) {
                        return v == value;
                    }

                    return false;
                }

                true
            })
            // TODO: what if user holds sender past peer drop?
            .map(|(remote_id, state)| {
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

impl CapabilityRegistrar for Arc<Server> {
    type ServerHandle = ServerHandleImpl;

    fn register(
        &self,
        info: CapabilityInfo,
        capability_server: Arc<dyn CapabilityServer>,
    ) -> Self::ServerHandle {
        let mut protocols = self.protocols.write();
        protocols.register_capability(info.into(), info.length, capability_server);
        let pool = Arc::downgrade(self);
        ServerHandleImpl {
            pool,
            capability: info.into(),
        }
    }
}
