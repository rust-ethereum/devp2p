//! `RLPx` protocol implementation in Rust

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub mod ecies;
mod errors;
mod mac;
mod peer;
mod util;

pub use peer::{CapabilityInfo, PeerStream};

use bigint::H512;
use futures::{stream::SplitStream, Sink, SinkExt};
use log::*;
use secp256k1::key::SecretKey;
use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt, StreamMap},
    sync::Mutex,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Sending node type specifying either all, any or a particular peer
pub enum RLPxNode {
    Any,
    All,
    Peer(H512),
}

/// Sending message for `RLPx`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLPxSendMessage {
    pub node: RLPxNode,
    pub capability_name: &'static str,
    pub id: usize,
    pub data: Vec<u8>,
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
        data: Vec<u8>,
    },
}

struct StreamHandle {
    sender: tokio::sync::mpsc::Sender<(&'static str, usize, Vec<u8>)>,
}

enum PeerState {
    Connecting,
    Connected(StreamHandle),
}

impl PeerState {
    fn is_connected(&self) -> bool {
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
    Data((CapabilityInfo, usize, Vec<u8>)),
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

/// A `RLPx` stream and sink
pub struct RLPxStream {
    #[allow(unused)]
    dropper: tokio::sync::watch::Sender<()>,
    drop_handle: tokio::sync::watch::Receiver<()>,

    streams: Arc<Mutex<PeerStreams<TcpStream>>>,

    newly_connected_tx: tokio::sync::mpsc::Sender<(H512, Vec<CapabilityInfo>)>,
    newly_connected: tokio::sync::mpsc::Receiver<(H512, Vec<CapabilityInfo>)>,
    newly_disconnected: tokio::sync::mpsc::Receiver<H512>,
    sink: tokio::sync::mpsc::Sender<RLPxSendMessage>,
    disconnect_cmd_tx:
        tokio::sync::mpsc::UnboundedSender<(H512, Option<tokio::sync::oneshot::Sender<bool>>)>,

    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: u16,
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
        let (dropper, mut drop_handle) = tokio::sync::watch::channel(());
        drop_handle.recv().await;
        let (newly_connected_tx, newly_connected) = tokio::sync::mpsc::channel(1);
        let (newly_disconnected_tx, newly_disconnected) = tokio::sync::mpsc::channel(1);

        let port = listen.map_or(0, |addr| addr.port());

        let streams = Arc::new(Mutex::new(PeerStreams::default()));

        // Disconnect command listener
        let (disconnect_cmd_tx, mut disconnect_cmd) = tokio::sync::mpsc::unbounded_channel::<(
            _,
            Option<tokio::sync::oneshot::Sender<bool>>,
        )>();
        tokio::spawn({
            let mut drop_handle = drop_handle.clone();
            let streams = streams.clone();
            let mut newly_disconnected_tx = newly_disconnected_tx;
            async move {
                loop {
                    tokio::select! {
                        _ = drop_handle.recv() => {
                            return;
                        }
                        res = disconnect_cmd.next() => {
                            if let Some((remote_id, cb_chan)) = res {
                                debug!("disconnecting peer {}", remote_id);

                                let mut s = streams.lock().await;
                                let PeerStreams { streams, mapping } = &mut *s;

                                // If this was a known peer, remove it.
                                let peer_dropped = if mapping.remove(&remote_id).is_some() {
                                    // If the connection was successfully established, drop it.
                                    streams.remove(&remote_id).unwrap();
                                    true
                                } else {
                                    false
                                };
                                let _ = newly_disconnected_tx.send(remote_id).await;
                                if let Some(cb_chan) = cb_chan {
                                    let _ = cb_chan.send(peer_dropped);
                                }
                            } else {
                                return;
                            }
                        }
                    }
                }
            }
        });

        // Incoming connection handler
        if let Some(addr) = listen {
            let mut tcp_incoming = TcpListener::bind(addr).await?;
            let streams = streams.clone();
            let client_version = client_version.clone();
            let capabilities = capabilities.clone();
            let newly_connected = newly_connected_tx.clone();
            let drop_handle = drop_handle.clone();
            let mut general_drop_handle = drop_handle.clone();
            let disconnect_cmd_tx = disconnect_cmd_tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = general_drop_handle.recv() => {
                            return;
                        }
                        res = tcp_incoming.accept() => {
                            match res {
                                Err(e) => {
                                    error!("failed to accept peer: {:?}, shutting down", e);
                                    return;
                                }
                                Ok((stream, _remote_addr)) => {
                                    let client_version = client_version.clone();
                                    let capabilities = capabilities.clone();
                                    let mut newly_connected = newly_connected.clone();
                                    let streams = streams.clone();
                                    let disconnect_cmd_tx = disconnect_cmd_tx.clone();
                                    let drop_handle = drop_handle.clone();
                                    tokio::spawn(async move {
                                        // Do handshake and convert incoming connection into stream.
                                        let peer_res = PeerStream::incoming(
                                            stream,
                                            secret_key,
                                            protocol_version,
                                            client_version.clone(),
                                            capabilities.clone(),
                                            port,
                                        )
                                        .await;
                                        match peer_res {
                                            Ok(peer) => {
                                                let remote_id = peer.remote_id();
                                                let mut s = streams.lock().await;
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
                                                let (mut sink, stream) = futures::StreamExt::split(peer);
                                                let mut drop_handle = drop_handle.clone();
                                                let (peer_sender_tx, mut peer_sender_rx) = tokio::sync::mpsc::channel(1);

                                                // Outgoing router -> PeerStream connector
                                                tokio::spawn(async move {
                                                    loop {
                                                        tokio::select! {
                                                            _ = drop_handle.recv() => {
                                                                return;
                                                            }
                                                            res = peer_sender_rx.recv() => {
                                                                if let Some(msg) = res {
                                                                    if let Err(e) = sink.send(msg).await {
                                                                        debug!("peer disconnected with error {:?}", e);
                                                                        let _ = disconnect_cmd_tx.send((remote_id, None));
                                                                    }
                                                                } else {
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                                assert!(streams.insert(remote_id.clone(), stream.into()).is_none());
                                                *peer_state = PeerState::Connected(StreamHandle { sender: peer_sender_tx });
                                                drop(s);
                                                let _ = newly_connected
                                                    .send((remote_id, capabilities))
                                                    .await;
                                            }
                                            Err(e) => {
                                                error!("peer disconnected with error {}", e);
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            });
        }

        // Outgoing message router
        let (sink, mut outgoing_messages) = tokio::sync::mpsc::channel(1);
        tokio::spawn({
            let mut drop_handle = drop_handle.clone();
            let streams = streams.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = drop_handle.recv() => {
                            return;
                        }
                        res = outgoing_messages.next() => {
                            if let Some(RLPxSendMessage {
                                node,
                                capability_name,
                                id,
                                data,
                            }) = res
                            {
                                let this = streams.lock().await;
                                // So here we select the peers that will receive our message.
                                let peer = match node {
                                    RLPxNode::Peer(peer_id) => Some(peer_id),
                                    RLPxNode::All => None,
                                    RLPxNode::Any => this.mapping.keys().next().copied(),
                                };

                                let message = (capability_name, id, data);

                                // Send to one peer if it's selected.
                                let selected_peers = if let Some(peer_id) = peer {
                                    match this.mapping.get(&peer_id) {
                                        Some(PeerState::Connected(handle)) => {
                                            vec![handle.sender.clone()]
                                        }
                                        Some(PeerState::Connecting) => {
                                            warn!(
                                                "Skipping message for a connecting peer: {:?}",
                                                message
                                            );
                                            vec![]
                                        }
                                        None => {
                                            warn!(
                                                "Skipping message for disconnected peer: {:?}",
                                                message
                                            );
                                            vec![]
                                        }
                                    }
                                } else {
                                    // Send to everybody otherwise.
                                    this.mapping.values().filter_map(|v| if let PeerState::Connected(handle) = v { Some(handle.sender.clone()) } else { None }).collect::<Vec<_>>()
                                };

                                drop(this);
                                for mut peer in selected_peers {
                                    let _ = peer.send(message.clone()).await;
                                }
                            } else {
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            dropper,
            drop_handle,
            streams,
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
        let mut drop_handle = self.drop_handle.clone();

        let streams = self.streams.clone();
        let disconnect_cmd_tx = self.disconnect_cmd_tx.clone();
        let mut newly_connected = self.newly_connected_tx.clone();

        let secret_key = self.secret_key;
        let protocol_version = self.protocol_version;
        let client_version = self.client_version.clone();
        let capabilities = self.capabilities.clone();
        let port = self.port;

        tokio::spawn(async move {
            // NOTE: we assume that successful handshake means that remote id provided above is correct
            match streams.lock().await.mapping.entry(remote_id) {
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
                    return Ok(false);
                }
                Entry::Vacant(vacant) => {
                    info!("connecting to peer {}", remote_id);
                    vacant.insert(PeerState::Connecting);
                }
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
            }.await;
            let mut s = streams.lock().await;
            let PeerStreams {
                streams,
                mapping,
            } = &mut *s;

            // Adopt the new connection if the peer has not been dropped or superseded by incoming connection.
            if let Entry::Occupied(mut peer_state) = mapping.entry(remote_id) {
                if !peer_state.get().is_connected() {
                    return match peer_res {
                        Ok(peer) => {
                            assert_eq!(peer.remote_id(), remote_id);
                            debug!("new peer connected: {}", remote_id);
                            let capabilities = peer.capabilities().into();
                            let (mut sink, stream) = futures::StreamExt::split(peer);
                            let (peer_sender_tx, mut peer_sender_rx) =
                                tokio::sync::mpsc::channel(1);

                            // Outgoing router -> PeerStream connector
                            tokio::spawn(async move {
                                loop {
                                    tokio::select! {
                                        _ = drop_handle.recv() => {
                                            return;
                                        }
                                        res = peer_sender_rx.recv() => {
                                            if let Some(msg) = res {
                                                if let Err(e) = sink.send(msg).await {
                                                    debug!("peer disconnected with error {:?}", e);
                                                    let _ = disconnect_cmd_tx.clone().send((remote_id, None));
                                                    return;
                                                }
                                            } else {
                                                return;
                                            }
                                        }
                                    }
                                }
                            });
                            assert!(streams.insert(remote_id.clone(), stream.into()).is_none());
                            *peer_state.get_mut() =
                                PeerState::Connected(StreamHandle {
                                    sender: peer_sender_tx,
                                });
                            drop(s);
                            let _ = newly_connected.send((remote_id, capabilities)).await;
                            Ok(true)
                        }
                        Err(e) => {
                            error!("peer disconnected with error {}", e);
                            peer_state.remove();
                            Err(e)
                        }
                    }
                }
            }

            Ok(false)
        })
        .await
        .unwrap()
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub async fn disconnect_peer(&self, remote_id: H512) -> bool {
        let (cb_tx, res) = tokio::sync::oneshot::channel();
        if self
            .disconnect_cmd_tx
            .send((remote_id, Some(cb_tx)))
            .is_err()
        {
            return false;
        }

        res.await.unwrap_or(false)
    }

    /// Active peers
    pub async fn active_peers(&self) -> Vec<H512> {
        self.streams.lock().await.mapping.keys().copied().collect()
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
        } else if let Ok(mut streams) = this.streams.try_lock() {
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
        } else {
            Poll::Pending
        }
    }
}

impl Sink<RLPxSendMessage> for RLPxStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .sink
            .poll_ready(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))
    }

    fn start_send(self: Pin<&mut Self>, item: RLPxSendMessage) -> Result<(), Self::Error> {
        let _ = self.get_mut().sink.try_send(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
