//! `RLPx` protocol implementation in Rust

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::if_not_else,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::used_underscore_binding,
    clippy::wildcard_imports
)]

pub mod ecies;
mod errors;
mod mac;
mod peer;
mod util;

pub use peer::{CapabilityInfo, CapabilityName, PeerStream};

use bytes::Bytes;
use ethereum_types::H512;
use futures::{future::abortable, stream::SplitStream, Sink, SinkExt};
use libsecp256k1::SecretKey;
use log::*;
use parking_lot::Mutex;
use std::{
    collections::{hash_map::Entry, BTreeSet, HashMap, HashSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt, StreamMap},
};

/// Sending message for `RLPx`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLPxSendMessage {
    pub peer: H512,
    pub capability_name: CapabilityName,
    pub id: usize,
    pub data: Bytes,
}

/// Receiving message for `RLPx`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RLPxReceiveMessage {
    Connected {
        node: H512,
        capabilities: Vec<CapabilityInfo>,
    },
    Disconnected {
        node: H512,
    },
    Normal {
        node: H512,
        capability: CapabilityInfo,
        id: usize,
        data: Bytes,
    },
}

struct StreamHandle {
    sender: tokio::sync::mpsc::Sender<(CapabilityName, usize, Bytes)>,
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

pub type CancellationToken = tokio::sync::watch::Receiver<()>;

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
                let capabilities = peer.capabilities().into();
                let (sink, stream) = futures::StreamExt::split(peer);
                let (peer_sender_tx, peer_sender_rx) = tokio::sync::mpsc::channel(1);

                assert!(streams.insert(remote_id, stream.into()).is_none());
                *peer_state = PeerState::Connected(StreamHandle {
                    sender: peer_sender_tx,
                });

                (remote_id, capabilities, peer_sender_rx, sink)
            };
            let _ = newly_connected.send((remote_id, capabilities)).await;

            while let Some(msg) = peer_sender_rx.recv().await {
                if let Err(e) = sink.send(msg).await {
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

// Routes all outgoing message requests to appropriate peers.
async fn outgoing_router<S>(mut outgoing_messages: S, streams: Arc<Mutex<PeerStreams<TcpStream>>>)
where
    S: Stream<Item = RLPxSendMessage> + Send + Unpin,
{
    while let Some(RLPxSendMessage {
        peer,
        capability_name,
        id,
        data,
    }) = outgoing_messages.next().await
    {
        let message = (capability_name, id, data);

        let peer_sender = {
            let this = streams.lock();
            match this.mapping.get(&peer) {
                Some(PeerState::Connected(handle)) => Some(handle.sender.clone()),
                Some(PeerState::Connecting) => {
                    warn!("Skipping message for a connecting peer: {:?}", message);
                    None
                }
                None => {
                    warn!("Skipping message for disconnected peer: {:?}", message);
                    None
                }
            }
        };

        if let Some(mut peer_sender) = peer_sender {
            let _ = peer_sender.send(message.clone()).await;
        }
    }
}

pub type NodeFilter = Box<dyn Fn(usize, H512) -> bool + Send + 'static>;

/// A `RLPx` stream and sink
pub struct RLPxStream {
    #[allow(unused)]
    tasks: Arc<TaskGroup>,

    streams: Arc<Mutex<PeerStreams<TcpStream>>>,

    node_filter: Arc<Mutex<NodeFilter>>,

    newly_connected_tx: tokio::sync::mpsc::Sender<(H512, Vec<CapabilityInfo>)>,
    newly_connected: tokio::sync::mpsc::Receiver<(H512, Vec<CapabilityInfo>)>,
    newly_disconnected: tokio::sync::mpsc::Receiver<H512>,
    sink: tokio::sync::mpsc::Sender<RLPxSendMessage>,
    disconnect_cmd_tx: tokio::sync::mpsc::UnboundedSender<(H512, Option<DisconnectCb>)>,

    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: u16,
}

pub struct CapabilityFilter {
    pub name: String,
    pub versions: BTreeSet<usize>,
}

pub struct PeerFilter {
    pub is_connected: Option<bool>,
    pub capability: Option<CapabilityFilter>,
}

#[derive(Default, Debug)]
pub struct TaskGroup(Arc<Mutex<Vec<futures::future::AbortHandle>>>);

impl TaskGroup {
    pub fn spawn<T>(&self, future: T)
    where
        T: Future<Output = ()> + Send + 'static,
    {
        let mut group = self.0.lock();
        let (t, handle) = abortable(future);
        group.push(handle);
        tokio::spawn(t);
    }
}

impl Drop for TaskGroup {
    fn drop(&mut self) {
        for handle in &*self.0.lock() {
            handle.abort();
        }
    }
}

// This is a Tokio-based RLPx server implementation.
//
// RLPxStream is the server handle that supports adding and removing peers and
// it also provides Stream and Sink interfaces.
//
// This implementation is based on the concept of structured concurrency.
// Internal state is managed by a multitude of workers that run in separate runtime tasks
// spawned on the running executor during the server creation and addition of new peers.
// All continuously running workers are logically owned by the server struct. This contract
// is enforced by the cancellation token whose state is periodically checked by all workers.

impl RLPxStream {
    /// Create a new `RLPx` stream
    pub async fn new(
        secret_key: SecretKey,
        protocol_version: usize,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        listen: Option<SocketAddr>,
    ) -> Result<Self, io::Error> {
        let tasks = Arc::new(TaskGroup::default());
        let (newly_connected_tx, newly_connected) = tokio::sync::mpsc::channel(1);
        let (newly_disconnected_tx, newly_disconnected) = tokio::sync::mpsc::channel(1);

        let port = listen.map_or(0, |addr| addr.port());

        let streams = Arc::new(Mutex::new(PeerStreams::default()));
        let node_filter = Arc::new(Mutex::new(Box::new(|_, _| true) as NodeFilter));

        let (disconnect_cmd_tx, disconnect_requests) =
            tokio::sync::mpsc::unbounded_channel::<(_, Option<DisconnectCb>)>();

        tasks.spawn(disconnecter_task(
            disconnect_requests,
            streams.clone(),
            newly_disconnected_tx.clone(),
        ));

        if let Some(addr) = listen {
            let tcp_incoming = TcpListener::bind(addr).await?;
            tasks.spawn(handle_incoming(
                Arc::downgrade(&tasks),
                tcp_incoming,
                PeerStreamHandshakeData {
                    port,
                    protocol_version,
                    secret_key,
                    client_version: client_version.clone(),
                    capabilities: capabilities.clone(),
                },
                streams.clone(),
                newly_connected_tx.clone(),
                disconnect_cmd_tx.clone(),
            ));
        }

        let (sink, outgoing_messages) = tokio::sync::mpsc::channel(1);
        tokio::spawn(outgoing_router(outgoing_messages, streams.clone()));

        Ok(Self {
            tasks,
            streams,
            node_filter,
            secret_key,
            protocol_version,
            client_version,
            capabilities,
            sink,
            newly_connected,
            newly_connected_tx,
            newly_disconnected,
            disconnect_cmd_tx,
            port,
        })
    }

    /// Add a new peer to this `RLPx` stream. Returns `true` if it did not exist before.
    pub async fn add_peer(&self, addr: SocketAddr, remote_id: H512) -> io::Result<bool> {
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

        tokio::spawn(async move {
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
                        if (node_filter)(connection_num, remote_id) {
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
                                let capabilities = peer.capabilities().into();
                                let (mut sink, stream) = futures::StreamExt::split(peer);
                                let (peer_sender_tx, mut peer_sender_rx) =
                                    tokio::sync::mpsc::channel(1);

                                // Outgoing router -> PeerStream connector
                                if let Some(tasks) = tasks_handle.upgrade() {
                                    tasks.spawn(async move {
                                        while let Some(msg) = peer_sender_rx.recv().await {
                                            if let Err(e) = sink.send(msg).await {
                                                debug!("peer disconnected with error {:?}", e);
                                                let _ = disconnect_cmd_tx
                                                    .clone()
                                                    .send((remote_id, None));
                                                return;
                                            }
                                        }
                                    })
                                }
                                assert!(streams.insert(remote_id, stream.into()).is_none());
                                *peer_state.get_mut() = PeerState::Connected(StreamHandle {
                                    sender: peer_sender_tx,
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
        })
        .await
        .unwrap()
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub async fn disconnect_peer(&self, remote_id: H512) -> bool {
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
        if !disconnecter_alive {
            return false;
        }

        disconnection_res.await.unwrap_or(false)
    }

    /// Set the node filter.
    pub fn set_node_filter<F: Fn(usize, H512) -> bool + Send + 'static>(&self, node_filter: F) {
        *self.node_filter.lock() = Box::new(node_filter);
    }

    /// Active peers
    #[must_use]
    pub fn active_peers(&self) -> HashSet<H512> {
        self.streams.lock().mapping.keys().copied().collect()
    }

    /// Get peer by capability
    pub async fn get_peers(&self, _limit: usize, _filter: PeerFilter) -> HashSet<H512> {
        let _peers = self.streams.lock();

        // peers.iter().filter(|peer| )

        todo!()
    }
}

impl Stream for RLPxStream {
    type Item = RLPxReceiveMessage;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Poll::Ready(Some(connected)) = this.newly_connected.poll_recv(cx) {
            Poll::Ready(Some(RLPxReceiveMessage::Connected {
                node: connected.0,
                capabilities: connected.1,
            }))
        } else if let Poll::Ready(Some(node)) = this.newly_disconnected.poll_recv(cx) {
            Poll::Ready(Some(RLPxReceiveMessage::Disconnected { node }))
        } else {
            let mut streams = this.streams.lock();
            if let Poll::Ready(Some((node, res))) = Pin::new(&mut streams.streams).poll_next(cx) {
                match res {
                    PeerStreamUpdate::Data((capability, id, data)) => {
                        debug!("received RLPx data {:?}", data);
                        return Poll::Ready(Some(Self::Item::Normal {
                            node,
                            capability,
                            id,
                            data,
                        }));
                    }
                    PeerStreamUpdate::Error(e) => {
                        debug!("Peer {} disconnected with error: {}", node, e);
                    }
                    PeerStreamUpdate::Finished => {
                        debug!("Peer {} disconnected without error", node);
                    }
                }

                let _ = this.disconnect_cmd_tx.send((node, None));
                cx.waker().wake_by_ref();
            }

            Poll::Pending
        }
    }
}

impl Sink<RLPxSendMessage> for RLPxStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().sink.poll_ready(cx).map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "server does not accept messages")
        })
    }

    fn start_send(self: Pin<&mut Self>, item: RLPxSendMessage) -> Result<(), Self::Error> {
        self.get_mut()
            .sink
            .try_send(item)
            .expect("readiness should have been checked with poll_ready; qed");
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
