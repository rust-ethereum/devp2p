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
pub mod peer;
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

pub struct RLPxStream {
    streams: Vec<PeerStream>,
    secret_key: SecretKey,
    protocol_version: usize,
    client_version: String,
    capabilities: Vec<CapabilityInfo>,
    port: usize,
}

impl RLPxStream {
    pub fn new(secret_key: SecretKey, protocol_version: usize,
               client_version: String, capabilities: Vec<CapabilityInfo>,
               port: usize) -> RLPxStream {
        RLPxStream {
            streams: Vec::new(),
            secret_key, protocol_version, client_version,
            capabilities, port
        }
    }

    pub fn add_peer(
        mut self, addr: &SocketAddr, handle: &Handle, remote_id: H512
    ) -> Box<Future<Item = RLPxStream, Error = io::Error>> {
        let fu = PeerStream::connect(addr, handle, self.secret_key.clone(),
                            remote_id, self.protocol_version,
                            self.client_version.clone(),
                            self.capabilities.clone(), self.port)
            .then(move |peer_result| {
                match peer_result {
                    Ok(peer) => {
                        self.streams.push(peer);
                        future::ok(self)
                    },
                    Err(_) => {
                        future::ok(self)
                    },
                }
            });

        Box::new(fu)
    }
}

impl Stream for RLPxStream {
    type Item = (CapabilityInfo, usize, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        'outer: loop {
            let mut full_iter = true;
            let mut start_index = 0;

            'inner: for i in start_index..self.streams.len() {
                match self.streams[i].poll() {
                    Ok(Async::NotReady) => (),
                    Ok(Async::Ready(None)) => {
                        self.streams.swap_remove(i);
                        full_iter = false;
                        start_index = i;
                        break 'inner;
                    },
                    Ok(Async::Ready(Some(val))) =>
                        return Ok(Async::Ready(Some(val))),
                    Err(e) => {
                        self.streams.swap_remove(i);
                        full_iter = false;
                        start_index = i;
                        break 'inner;
                    },
                }
            }

            if full_iter {
                break 'outer;
            }
        }
        Ok(Async::NotReady)
    }
}

impl Sink for RLPxStream {
    type SinkItem = (CapabilityInfo, usize, Vec<u8>);
    type SinkError = io::Error;

    fn start_send(&mut self, (cap, id, data): (CapabilityInfo, usize, Vec<u8>)) -> StartSend<Self::SinkItem, Self::SinkError> {
        let mut any_ready = false;

        'outer: loop {
            let mut full_iter = true;
            let mut start_index = 0;

            'inner: for i in 0..self.streams.len() {
                match self.streams[i].start_send((cap.clone(), id, data.clone())) {
                    Ok(AsyncSink::Ready) => {
                        any_ready = true;
                    },
                    Ok(AsyncSink::NotReady(_)) => (),
                    Err(e) => {
                        self.streams.swap_remove(i);
                        full_iter = false;
                        start_index = i;
                        break 'inner;
                    }
                }
            }

            if full_iter {
                break 'outer;
            }
        }

        if any_ready {
            Ok(AsyncSink::Ready)
        } else {
            Ok(AsyncSink::NotReady((cap, id, data)))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let mut all_ready = true;

        'outer: loop {
            let mut full_iter = true;
            let mut start_index = 0;

            'inner: for i in 0..self.streams.len() {
                match self.streams[i].poll_complete() {
                    Ok(Async::Ready(())) => (),
                    Ok(Async::NotReady) => {
                        all_ready = false;
                    },
                    Err(e) => {
                        self.streams.swap_remove(i);
                        full_iter = false;
                        start_index = i;
                        break 'inner;
                    }
                }
            }

            if full_iter {
                break 'outer;
            }
        }

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
