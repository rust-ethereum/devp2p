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

pub struct RLPxStream {
    streams: Vec<PeerStream>,
    futures: Vec<Box<Future<Item = PeerStream, Error = io::Error>>>,
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
            futures: Vec::new(),
            secret_key, protocol_version, client_version,
            capabilities, port,
        }
    }

    pub fn add_peer(
        &mut self, addr: &SocketAddr, handle: &Handle, remote_id: H512
    ) {
        let future = PeerStream::connect(addr, handle, self.secret_key.clone(),
                                         remote_id, self.protocol_version,
                                         self.client_version.clone(),
                                         self.capabilities.clone(), self.port);
        self.futures.push(future);
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
    type Item = (CapabilityInfo, usize, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let ref mut futures = self.futures;
        let ref mut streams = self.streams;

        retain_mut(futures, |ref mut future| {
            match future.poll() {
                Ok(Async::NotReady) => true,
                Ok(Async::Ready(peer)) => {
                    streams.push(peer);
                    false
                },
                Err(e) => false,
            }
        });

        let mut ret: Option<Self::Item> = None;
        retain_mut(streams, |ref mut peer| {
            if ret.is_some() {
                return true;
            }

            match peer.poll() {
                Ok(Async::NotReady) => true,
                Ok(Async::Ready(None)) => false,
                Ok(Async::Ready(Some(val))) => {
                    ret = Some(val);
                    true
                },
                Err(e) => false,
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
    type SinkItem = (CapabilityInfo, usize, Vec<u8>);
    type SinkError = io::Error;

    fn start_send(&mut self, (cap, id, data): (CapabilityInfo, usize, Vec<u8>)) -> StartSend<Self::SinkItem, Self::SinkError> {
        let ref mut futures = self.futures;
        let ref mut streams = self.streams;

        retain_mut(futures, |ref mut future| {
            match future.poll() {
                Ok(Async::NotReady) => true,
                Ok(Async::Ready(peer)) => {
                    streams.push(peer);
                    false
                },
                Err(e) => false,
            }
        });

        let mut any_ready = false;

        retain_mut(streams, |ref mut peer| {
            match peer.start_send((cap.clone(), id, data.clone())) {
                Ok(AsyncSink::Ready) => {
                    any_ready = true;
                    true
                },
                Ok(AsyncSink::NotReady(_)) => true,
                Err(e) => false,
            }
        });

        if any_ready {
            Ok(AsyncSink::Ready)
        } else {
            Ok(AsyncSink::NotReady((cap, id, data)))
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        let ref mut streams = self.streams;

        let mut all_ready = true;

        retain_mut(streams, |ref mut peer| {
            match peer.poll_complete() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => {
                    all_ready = false;
                    true
                },
                Err(e) => false,
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
