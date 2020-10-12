//! RLPx protocol implementation in Rust

use crate::{disc::*, node_filter::*, peer::*, types::*};
use anyhow::anyhow;
use derivative::Derivative;
use futures::sink::SinkExt;
use k256::ecdsa::SigningKey;
use parking_lot::Mutex;
use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::{Debug, Display},
    future::Future,
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};
use task_group::TaskGroup;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::StreamExt,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        Mutex as AsyncMutex,
    },
};
use tracing::*;
use uuid::Uuid;

const GRACE_PERIOD_SECS: u64 = 2;
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_TIMEOUT_SECS: u64 = 5;
const DISCOVERY_CONNECT_TIMEOUT_SECS: u64 = 5;

#[derive(Clone, Copy)]
enum DisconnectInitiator {
    Local,
    LocalForceful,
    Remote,
}

struct DisconnectSignal {
    initiator: DisconnectInitiator,
    reason: DisconnectReason,
}

#[derive(Debug)]
struct ConnectedPeerState {
    disconnector: UnboundedSender<DisconnectSignal>,
    tasks: TaskGroup,
    capabilities: BTreeSet<CapabilityId>,
    notes: HashMap<String, String>,
}

#[derive(Debug)]
enum PeerState {
    Connecting { connection_id: Uuid },
    Connected(ConnectedPeerState),
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

#[derive(Derivative)]
#[derivative(Clone)]
struct PeerStreamHandshakeData<C> {
    port: u16,
    protocol_version: ProtocolVersion,
    secret_key: Arc<SigningKey>,
    client_version: String,
    capabilities: Arc<CapabilitySet>,
    #[derivative(Clone(bound = ""))]
    capability_server: Arc<C>,
}

async fn handle_incoming<C>(
    task_group: Weak<TaskGroup>,
    streams: Arc<Mutex<PeerStreams>>,
    node_filter: Arc<Mutex<dyn NodeFilter>>,
    mut tcp_incoming: TcpListener,
    handshake_data: PeerStreamHandshakeData<C>,
) where
    C: CapabilityServer,
{
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
fn setup_peer_state<C, Io>(
    streams: Weak<Mutex<PeerStreams>>,
    capability_server: Arc<C>,
    remote_id: PeerId,
    peer: PeerStream<Io>,
) -> ConnectedPeerState
where
    C: CapabilityServer,
    Io: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static,
{
    let capability_set = peer
        .capabilities()
        .iter()
        .copied()
        .map(From::from)
        .collect::<BTreeSet<_>>();
    let (mut sink, mut stream) = futures::StreamExt::split(peer);
    let (peer_disconnect_tx, mut peer_disconnect_rx) = unbounded_channel();
    let tasks = TaskGroup::default();

    capability_server.on_peer_connect(remote_id, capability_set.clone());

    // Ingress router
    tasks.spawn({
        let capability_server = capability_server.clone();
        let peer_disconnect_tx = peer_disconnect_tx.clone();
        async move {
            let disconnect_signal = {
                async move {
                    while let Some(message) = stream.next().await {
                        match message {
                            Err(e) => {
                                debug!("Peer incoming error: {}", e);
                                break;
                            }
                            Ok(InboundMessage::Subprotocol {
                                capability,
                                message_id,
                                payload,
                            }) => {
                                // Actually handle the message
                                capability_server
                                    .on_peer_event(
                                        remote_id,
                                        InboundEvent::Message {
                                            capability_name: capability.name,
                                            message: Message {
                                                id: message_id,
                                                data: payload,
                                            },
                                        },
                                    )
                                    .await
                            }
                            Ok(InboundMessage::Disconnect(reason)) => {
                                // Peer has requested disconnection.
                                return DisconnectSignal {
                                    initiator: DisconnectInitiator::Remote,
                                    reason,
                                };
                            }
                            Ok(_) => {}
                        }
                    }

                    // Ingress stream is closed, force disconnect the peer.
                    DisconnectSignal {
                        initiator: DisconnectInitiator::Remote,
                        reason: DisconnectReason::DisconnectRequested,
                    }
                }
            }
            .await;

            let _ = peer_disconnect_tx.send(disconnect_signal);
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
            loop {
                let mut disconnecting = None;
                let mut egress = None;
                tokio::select! {
                    msg = capability_server.next(remote_id) => {
                        match msg {
                            OutboundEvent::Message {
                                capability_name, message
                            } => {
                                egress = Some(EgressMessage::Subprotocol(SubprotocolMessage {
                                    cap_name: capability_name, message
                                }));
                            }
                            OutboundEvent::Disconnect {
                                reason
                            } => {
                                disconnecting = Some(DisconnectSignal {
                                    initiator: DisconnectInitiator::Local, reason
                                });
                            }
                        };
                    },
                    Some(DisconnectSignal { initiator, reason }) = peer_disconnect_rx.next() => {
                        if let DisconnectInitiator::Local = initiator {
                            egress = Some(EgressMessage::Disconnect { reason });
                        }
                        disconnecting = Some(DisconnectSignal { initiator, reason })
                    },
                    else => {
                        break;
                    }
                };

                if let Some(message) = egress {
                    trace!("Sending message: {:?}", message);

                    // Send egress message, force disconnect on error.
                    if let Err(e) = sink.send(message).await {
                        debug!("peer disconnected with error {:?}", e);
                        disconnecting.get_or_insert(DisconnectSignal {
                            initiator: DisconnectInitiator::LocalForceful,
                            reason: DisconnectReason::TcpSubsystemError,
                        });
                    }
                }

                if let Some(DisconnectSignal { initiator, reason }) = disconnecting {
                    if let DisconnectInitiator::Local = initiator {
                        // We have sent disconnect message, wait for grace period.
                        tokio::time::delay_for(Duration::from_secs(GRACE_PERIOD_SECS)).await;
                    }
                    capability_server
                        .on_peer_event(
                            remote_id,
                            InboundEvent::Disconnect {
                                reason: Some(reason),
                            },
                        )
                        .await;
                    break;
                }
            }

            // We are done, drop the peer state.
            if let Some(streams) = streams.upgrade() {
                streams.lock().disconnect_peer(remote_id);
            }
        }
        .instrument(span!(
            Level::DEBUG,
            "egress router",
            "peer={}",
            remote_id.to_string(),
        ))
    });
    ConnectedPeerState {
        disconnector: peer_disconnect_tx,
        tasks,
        capabilities: capability_set,
        notes: Default::default(),
    }
}

/// Establishes the connection with peer and adds them to internal state.
async fn handle_incoming_request<C, Io>(
    streams: Arc<Mutex<PeerStreams>>,
    node_filter: Arc<Mutex<dyn NodeFilter>>,
    stream: Io,
    handshake_data: PeerStreamHandshakeData<C>,
) where
    C: CapabilityServer,
    Io: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static,
{
    let PeerStreamHandshakeData {
        secret_key,
        protocol_version,
        client_version,
        capabilities,
        capability_server,
        port,
    } = handshake_data;
    // Do handshake and convert incoming connection into stream.
    let peer_res = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        PeerStream::incoming(
            stream,
            secret_key,
            protocol_version,
            client_version,
            capabilities.get_capabilities().to_vec(),
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
                            Arc::downgrade(&streams),
                            capability_server,
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

#[derive(Debug, Default)]
struct CapabilitySet {
    inner: BTreeMap<CapabilityId, CapabilityLength>,

    capability_cache: Vec<CapabilityInfo>,
}

impl CapabilitySet {
    fn get_capabilities(&self) -> &[CapabilityInfo] {
        &self.capability_cache
    }
}

impl From<BTreeMap<CapabilityId, CapabilityLength>> for CapabilitySet {
    fn from(inner: BTreeMap<CapabilityId, CapabilityLength>) -> Self {
        let capability_cache = inner
            .iter()
            .map(
                |(&CapabilityId { name, version }, &length)| CapabilityInfo {
                    name,
                    version,
                    length,
                },
            )
            .collect();

        Self {
            inner,
            capability_cache,
        }
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
pub struct Server<C: CapabilityServer> {
    #[allow(unused)]
    tasks: Arc<TaskGroup>,

    streams: Arc<Mutex<PeerStreams>>,

    node_filter: Arc<Mutex<dyn NodeFilter>>,

    capabilities: Arc<CapabilitySet>,
    capability_server: Arc<C>,

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

    pub fn with_task_group(mut self, task_group: Arc<TaskGroup>) -> Self {
        self.task_group = Some(task_group);
        self
    }

    pub fn with_listen_options(mut self, options: ListenOptions) -> Self {
        self.listen_options = Some(options);
        self
    }

    pub fn with_client_version(mut self, version: String) -> Self {
        self.client_version = version;
        self
    }

    /// Create a new RLPx node
    pub async fn build<C: CapabilityServer>(
        self,
        capability_mask: BTreeMap<CapabilityId, CapabilityLength>,
        capability_server: Arc<C>,
        secret_key: SigningKey,
    ) -> Result<Arc<Server<C>>, io::Error> {
        Server::new(
            secret_key,
            self.client_version,
            self.task_group,
            capability_mask.into(),
            capability_server,
            self.listen_options,
        )
        .await
    }
}

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct ListenOptions {
    #[derivative(Debug = "ignore")]
    pub discovery_tasks: Vec<Arc<AsyncMutex<dyn Discovery>>>,
    pub max_peers: usize,
    pub addr: SocketAddr,
}

impl<C: CapabilityServer> Server<C> {
    async fn new(
        secret_key: SigningKey,
        client_version: String,
        task_group: Option<Arc<TaskGroup>>,
        capabilities: CapabilitySet,
        capability_server: Arc<C>,
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

        let capabilities = Arc::new(capabilities);

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
                    capabilities: capabilities.clone(),
                    capability_server: capability_server.clone(),
                },
            ));
        }

        let server = Arc::new(Self {
            tasks: tasks.clone(),
            streams,
            node_filter,
            capabilities,
            capability_server,
            secret_key,
            protocol_version,
            client_version,
            port,
        });

        // TODO: Use semaphore
        if let Some(options) = listen_options {
            for (num, discovery) in options.discovery_tasks.into_iter().enumerate() {
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

        let capabilities = self.capabilities.clone();
        let capability_set = capabilities.get_capabilities().to_vec();
        let capability_server = self.capability_server.clone();

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
                                Arc::downgrade(&streams),
                                capability_server,
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

    /// Gradefully disconnect an already connected peer or force disconnect a peer that is about to be connected.
    #[must_use]
    pub fn disconnect_peer(&self, remote_id: PeerId, reason: DisconnectReason) -> bool {
        let mut s = self.streams.lock();
        if let Some(peer) = s.mapping.get_mut(&remote_id) {
            if let PeerState::Connected(state) = peer {
                let _ = state.disconnector.send(DisconnectSignal {
                    initiator: DisconnectInitiator::Local,
                    reason,
                });
            } else {
                s.disconnect_peer(remote_id);
            }
            return true;
        }

        false
    }

    /// Force disconnect a peer if it is already connected or about
    /// to be connected.
    #[must_use]
    pub fn drop_peer(&self, remote_id: PeerId) -> bool {
        self.streams.lock().disconnect_peer(remote_id)
    }

    /// Active peers
    #[must_use]
    pub fn active_peers(&self) -> HashSet<PeerId> {
        self.streams.lock().mapping.keys().copied().collect()
    }

    #[must_use]
    pub fn connected_peers(&self) -> HashSet<PeerId> {
        self.streams
            .lock()
            .mapping
            .iter()
            .filter_map(|(id, state)| {
                if matches!(state, PeerState::Connected(..)) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }
}
