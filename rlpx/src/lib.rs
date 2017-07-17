//! RLPx protocol implementation in Rust

extern crate secp256k1;
extern crate rand;

extern crate sha3;
extern crate sha2;
extern crate byteorder;
extern crate crypto;
extern crate etcommon_bigint as bigint;
extern crate etcommon_crypto as hash;
extern crate etcommon_rlp as rlp;
extern crate etcommon_util;
extern crate bytes;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;

mod util;
pub mod ecies;
mod peer;
mod mac;
mod errors;

pub use peer::{PeerStream, CapabilityInfo};

use bigint::H512;
use util::pk2id;
use hash::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};
use futures::future;
use futures::{Poll, Async, StartSend, AsyncSink, Future, Stream, Sink};
use std::io;
use std::net::SocketAddr;
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Sending node type specifying either all, any or a particular peer
pub enum Node {
    Any,
    All,
    Peer(H512),
}

/// A RLPx stream and sink
pub struct RLPxStream {
    streams: Vec<PeerStream>,
    futures: Vec<(H512, Box<Future<Item = PeerStream, Error = io::Error>>)>,
    active_peers: Vec<H512>,
    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: u16,
    handle: Handle,
}

impl RLPxStream {
    /// Create a new RLPx stream
    pub fn new(handle: &Handle, secret_key: SecretKey, protocol_version: usize,
               client_version: String, capabilities: Vec<CapabilityInfo>,
               port: u16) -> RLPxStream {
        RLPxStream {
            streams: Vec::new(),
            futures: Vec::new(),
            secret_key, protocol_version, client_version,
            capabilities, port,
            handle: handle.clone(),
            active_peers: Vec::new(),
        }
    }

    /// Append a new peer to this RLPx stream if it does not exist
    pub fn add_peer(
        &mut self, addr: &SocketAddr, remote_id: H512
    ) {
        if !self.active_peers.contains(&remote_id) {
            let future = PeerStream::connect(addr, &self.handle, self.secret_key.clone(),
                                             remote_id, self.protocol_version,
                                             self.client_version.clone(),
                                             self.capabilities.clone(), self.port);
            self.futures.push((remote_id, future));
            self.active_peers.push(remote_id);
        }
    }

    /// Poll over new peers to resolve them to TCP streams
    pub fn poll_new_peers(&mut self) -> Poll<(), io::Error> {
        let ref mut futures = self.futures;
        let ref mut streams = self.streams;
        let ref mut active_peers = self.active_peers;

        let mut all_ready = true;

        retain_mut(futures, |&mut (remote_id, ref mut future)| {
            match future.poll() {
                Ok(Async::NotReady) => {
                    all_ready = false;
                    true
                },
                Ok(Async::Ready(peer)) => {
                    streams.push(peer);
                    false
                },
                Err(e) => {
                    active_peers.retain(|peer_id| {
                        *peer_id != remote_id
                    });
                    false
                },
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
    where F: FnMut(&mut T) -> bool
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
    type Item = (H512, CapabilityInfo, usize, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.poll_new_peers()?;

        let ref mut streams = self.streams;
        let ref mut active_peers = self.active_peers;

        let mut ret: Option<Self::Item> = None;
        retain_mut(streams, |ref mut peer| {
            if ret.is_some() {
                return true;
            }

            let id = peer.remote_id();
            match peer.poll() {
                Ok(Async::NotReady) => true,
                Ok(Async::Ready(None)) => false,
                Ok(Async::Ready(Some((cap, message_id, data)))) => {
                    ret = Some((id, cap, message_id, data));
                    true
                },
                Err(e) => {
                    active_peers.retain(|peer_id| {
                        *peer_id != id
                    });
                    false
                },
            }
        });

        if ret.is_some() {
            Ok(Async::Ready(ret))
        } else {
            Ok(Async::NotReady)
        }
    }
}

impl Sink for RLPxStream {
    type SinkItem = (Node, CapabilityInfo, usize, Vec<u8>);
    type SinkError = io::Error;

    fn start_send(&mut self, (node, cap, message_id, data): (Node, CapabilityInfo, usize, Vec<u8>)) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.poll_new_peers()?;

        let ref mut streams = self.streams;
        let ref mut active_peers = self.active_peers;

        let mut any_ready = false;

        retain_mut(streams, |ref mut peer| {
            let id = peer.remote_id();

            if match node {
                Node::Peer(peer_id) => peer_id == id,
                Node::All => true,
                Node::Any => !any_ready,
            } {
                let remote_id = peer.remote_id();
                match peer.start_send((cap.clone(), message_id, data.clone())) {
                    Ok(AsyncSink::Ready) => {
                        any_ready = true;
                        true
                    },
                    Ok(AsyncSink::NotReady(_)) => true,
                    Err(e) => {
                        active_peers.retain(|peer_id| {
                            *peer_id != remote_id
                        });
                        false
                    },
                }
            } else {
                true
            }
        });

        if any_ready {
            Ok(AsyncSink::Ready)
        } else {
            Ok(AsyncSink::NotReady((node, cap, message_id, data)))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let ref mut streams = self.streams;
        let ref mut active_peers = self.active_peers;

        let mut all_ready = true;

        retain_mut(streams, |ref mut peer| {
            let remote_id = peer.remote_id();
            match peer.poll_complete() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => {
                    all_ready = false;
                    true
                },
                Err(e) => {
                    active_peers.retain(|peer_id| {
                        *peer_id != remote_id
                    });
                    false
                },
            }
        });

        if all_ready {
            Ok(Async::Ready(()))
        } else {
            Ok(Async::NotReady)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
