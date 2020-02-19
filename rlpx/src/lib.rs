//! `RLPx` protocol implementation in Rust

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
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
use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use log::*;
use rand::{thread_rng, Rng};
use secp256k1::key::SecretKey;
use std::{io, net::SocketAddr};
use tokio_core::{
    net::{Incoming, TcpListener},
    reactor::Handle,
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

/// A `RLPx` stream and sink
pub struct RLPxStream {
    streams: Vec<PeerStream>,
    futures: Vec<(H512, Box<dyn Future<Item = PeerStream, Error = io::Error>>)>,
    incoming_futures: Vec<Box<dyn Future<Item = PeerStream, Error = io::Error>>>,
    newly_connected: Vec<(H512, Vec<CapabilityInfo>)>,
    newly_disconnected: Vec<H512>,
    active_peers: Vec<H512>,
    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: u16,
    tcp_incoming: Option<Incoming>,
    handle: Handle,
}

impl RLPxStream {
    /// Create a new `RLPx` stream
    pub fn new(
        handle: &Handle,
        secret_key: SecretKey,
        protocol_version: usize,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        listen: Option<SocketAddr>,
    ) -> Result<Self, io::Error> {
        Ok(Self {
            streams: Vec::new(),
            futures: Vec::new(),
            secret_key,
            protocol_version,
            client_version,
            capabilities,
            handle: handle.clone(),
            active_peers: Vec::new(),
            newly_connected: Vec::new(),
            newly_disconnected: Vec::new(),
            port: listen.map_or(0, |addr| addr.port()),
            tcp_incoming: match listen {
                Some(addr) => Some(TcpListener::bind(&addr, handle)?.incoming()),
                None => None,
            },
            incoming_futures: Vec::new(),
        })
    }

    /// Append a new peer to this `RLPx` stream if it does not exist
    pub fn add_peer(&mut self, addr: &SocketAddr, remote_id: H512) {
        if !self.active_peers.contains(&remote_id) {
            info!("connecting to peer {}", remote_id);
            let future = PeerStream::connect(
                addr,
                &self.handle,
                self.secret_key,
                remote_id,
                self.protocol_version,
                self.client_version.clone(),
                self.capabilities.clone(),
                self.port,
            );
            self.futures.push((remote_id, future));
            self.active_peers.push(remote_id);
        }
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub fn disconnect_peer(&mut self, remote_id: H512) {
        let futures = &mut self.futures;
        let streams = &mut self.streams;
        let newly_disconnected = &mut self.newly_disconnected;

        retain_mut(streams, |peer| {
            if peer.remote_id() == remote_id {
                newly_disconnected.push(remote_id);
                false
            } else {
                true
            }
        });

        retain_mut(futures, |&mut (peer_id, _)| peer_id != remote_id);
    }

    /// Poll over new peers to resolve them to TCP streams
    fn poll_new_peers(&mut self) -> Poll<(), io::Error> {
        let futures = &mut self.futures;
        let incoming_futures = &mut self.incoming_futures;
        let streams = &mut self.streams;
        let active_peers = &mut self.active_peers;
        let newly_connected = &mut self.newly_connected;

        let mut all_ready = true;

        retain_mut(futures, |(remote_id, future)| match future.poll() {
            Ok(Async::NotReady) => {
                all_ready = false;
                true
            }
            Ok(Async::Ready(peer)) => {
                debug!("new peer connected");
                newly_connected.push((*remote_id, peer.capabilities().into()));
                streams.push(peer);
                false
            }
            Err(e) => {
                error!("peer disconnected with error {}", e);
                active_peers.retain(|peer_id| *peer_id != *remote_id);
                false
            }
        });

        debug!("streams {} futures {}", streams.len(), futures.len());

        if let Some(tcp_incoming) = self.tcp_incoming.as_mut() {
            while let Async::Ready(Some((stream, _))) = tcp_incoming.poll()? {
                incoming_futures.push(PeerStream::incoming(
                    stream,
                    self.secret_key,
                    self.protocol_version,
                    self.client_version.clone(),
                    self.capabilities.clone(),
                    self.port,
                ));
            }
        }

        retain_mut(incoming_futures, |future| match future.poll() {
            Ok(Async::NotReady) => {
                all_ready = false;
                true
            }
            Ok(Async::Ready(peer)) => {
                debug!("new peer connected");
                newly_connected.push((peer.remote_id(), peer.capabilities().into()));
                streams.push(peer);
                false
            }
            Err(e) => {
                error!("peer disconnected with error {}", e);
                false
            }
        });

        if all_ready {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }

    /// Active peers
    pub fn active_peers(&self) -> &[H512] {
        self.active_peers.as_ref()
    }
}

fn retain_mut<T, F>(vec: &mut Vec<T>, mut f: F)
where
    F: FnMut(&mut T) -> bool,
{
    let len = vec.len();
    let mut del = 0;
    {
        let v = &mut **vec;

        for i in 0..len {
            if !f(&mut v[i]) {
                del += 1;
            } else if del > 0 {
                v.swap(i - del, i);
            }
        }
    }
    if del > 0 {
        vec.truncate(len - del);
    }
}

impl Stream for RLPxStream {
    type Item = RLPxReceiveMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.poll_new_peers()?;

        if !self.newly_connected.is_empty() {
            let connected = self.newly_connected.pop().unwrap();
            return Ok(Async::Ready(Some(RLPxReceiveMessage::Connected {
                node: connected.0,
                capabilities: connected.1,
            })));
        }
        if !self.newly_disconnected.is_empty() {
            return Ok(Async::Ready(Some(RLPxReceiveMessage::Disconnected {
                node: self.newly_disconnected.pop().unwrap(),
            })));
        }

        let mut ret: Option<Self::Item> = None;

        {
            let streams = &mut self.streams;
            let active_peers = &mut self.active_peers;
            let newly_disconnected = &mut self.newly_disconnected;

            retain_mut(streams, |peer| {
                if ret.is_some() {
                    return true;
                }

                let id = peer.remote_id();
                match peer.poll() {
                    Ok(Async::NotReady) => true,
                    Ok(Async::Ready(None)) => {
                        debug!("peer disconnected no error");
                        newly_disconnected.push(id);
                        false
                    }
                    Ok(Async::Ready(Some((cap, message_id, data)))) => {
                        debug!("received RLPx data {:?}", data);
                        ret = Some(RLPxReceiveMessage::Normal {
                            node: id,
                            capability: cap,
                            id: message_id,
                            data,
                        });
                        true
                    }
                    Err(e) => {
                        debug!("peer disconnected with error {:?}", e);
                        active_peers.retain(|peer_id| *peer_id != id);
                        newly_disconnected.push(id);
                        false
                    }
                }
            });
        }

        if ret.is_some() {
            Ok(Async::Ready(ret))
        } else {
            if !self.newly_connected.is_empty() {
                let connected = self.newly_connected.pop().unwrap();
                return Ok(Async::Ready(Some(RLPxReceiveMessage::Connected {
                    node: connected.0,
                    capabilities: connected.1,
                })));
            }
            if !self.newly_disconnected.is_empty() {
                return Ok(Async::Ready(Some(RLPxReceiveMessage::Disconnected {
                    node: self.newly_disconnected.pop().unwrap(),
                })));
            }
            Ok(Async::NotReady)
        }
    }
}

impl Sink for RLPxStream {
    type SinkItem = RLPxSendMessage;
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        message: RLPxSendMessage,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.poll_new_peers()?;

        let streams = &mut self.streams;
        let active_peers = &mut self.active_peers;
        let newly_disconnected = &mut self.newly_disconnected;

        let mut any_ready = false;
        if message.node == RLPxNode::Any {
            thread_rng().shuffle(streams);
        }

        debug!("sending RLPx data: {:?}", message.data);

        retain_mut(streams, |peer| {
            let id = peer.remote_id();

            if match message.node {
                RLPxNode::Peer(peer_id) => peer_id == id,
                RLPxNode::All => true,
                RLPxNode::Any => !any_ready,
            } {
                let remote_id = peer.remote_id();
                match peer.start_send((message.capability_name, message.id, message.data.clone())) {
                    Ok(AsyncSink::Ready) => {
                        any_ready = true;
                        true
                    }
                    Ok(AsyncSink::NotReady(_)) => true,
                    Err(e) => {
                        debug!("peer disconnected with error {:?}", e);
                        active_peers.retain(|peer_id| *peer_id != remote_id);
                        newly_disconnected.push(remote_id);
                        false
                    }
                }
            } else {
                true
            }
        });

        if any_ready {
            Ok(AsyncSink::Ready)
        } else {
            Ok(AsyncSink::NotReady(message))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let streams = &mut self.streams;
        let active_peers = &mut self.active_peers;
        let newly_disconnected = &mut self.newly_disconnected;

        let mut all_ready = true;

        retain_mut(streams, |peer| {
            let remote_id = peer.remote_id();
            match peer.poll_complete() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => {
                    all_ready = false;
                    true
                }
                Err(e) => {
                    debug!("peer disconnected with error: {:?}", e);
                    active_peers.retain(|peer_id| *peer_id != remote_id);
                    newly_disconnected.push(remote_id);
                    false
                }
            }
        });

        if all_ready {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}
