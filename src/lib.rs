//! Ethereum DevP2P protocol implementation

pub extern crate dpt;
pub extern crate rlpx;

#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate secp256k1;
extern crate etcommon_bigint as bigint;

use dpt::{DPTNode, DPTStream, DPTMessage};
use rlpx::{RLPxSendMessage, RLPxReceiveMessage, CapabilityInfo, RLPxStream};
use tokio_core::reactor::{Handle, Timeout};
use std::time::Duration;
use std::net::SocketAddr;
use std::io;
use secp256k1::key::SecretKey;
use futures::{StartSend, Async, Poll, Stream, Sink, Future, future};
use bigint::H512;

/// An Ethereum DevP2P stream that handles peers management
pub struct DevP2PStream {
    dpt: DPTStream,
    rlpx: RLPxStream,
    ping_interval: Duration,
    ping_timeout_interval: Duration,
    ping_timeout: Timeout,
    optimal_peers_len: usize,
    handle: Handle,
}

impl DevP2PStream {
    /// Create a new DevP2P stream
    pub fn new(addr: &SocketAddr,
               handle: &Handle, secret_key: SecretKey,
               protocol_version: usize, client_version: String,
               capabilities: Vec<CapabilityInfo>,
               bootstrap_nodes: Vec<DPTNode>,
               ping_interval: Duration, ping_timeout_interval: Duration,
               optimal_peers_len: usize) -> Result<Self, io::Error> {
        let port = addr.port();

        let dpt = DPTStream::new(addr, handle, secret_key.clone(),
                                 bootstrap_nodes, port)?;
        let rlpx = RLPxStream::new(handle, secret_key.clone(),
                                   protocol_version, client_version,
                                   capabilities, port);
        let ping_timeout = Timeout::new(ping_interval, handle)?;

        Ok(DevP2PStream {
            dpt, rlpx, ping_interval, ping_timeout,
            ping_timeout_interval,
            optimal_peers_len, handle: handle.clone()
        })
    }

    fn poll_dpt_receive_peers(&mut self) -> Poll<(), io::Error> {
        loop {
            let node = match self.dpt.poll() {
                Ok(Async::Ready(Some(node))) => node,
                Ok(_) => return Ok(Async::Ready(())),
                Err(e) => return Err(e),
            };
            self.rlpx.add_peer(&SocketAddr::new(node.address, node.tcp_port), node.id);
        }
    }

    fn poll_dpt_request_new_peers(&mut self) -> Poll<(), io::Error> {
        if self.rlpx.active_peers().len() < self.optimal_peers_len {
            self.dpt.start_send(DPTMessage::RequestNewPeer)?;
            self.dpt.poll_complete()?;
        }

        Ok(Async::Ready(()))
    }

    fn poll_dpt_ping(&mut self) -> Poll<(), io::Error> {
        let mut result = self.ping_timeout.poll()?;

        loop {
            match result {
                Async::NotReady => return Ok(Async::Ready(())),
                Async::Ready(()) => {
                    self.dpt.start_send(DPTMessage::Ping(Timeout::new(
                        self.ping_timeout_interval, &self.handle)?))?;
                    self.dpt.poll_complete()?;
                    self.ping_timeout = Timeout::new(self.ping_interval, &self.handle)?;

                    result = self.ping_timeout.poll()?;
                },
            }
        }

        Ok(Async::Ready(()))
    }
}

impl Stream for DevP2PStream {
    type Item = RLPxReceiveMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.poll_dpt_receive_peers()?;
        let result = self.rlpx.poll()?;
        self.poll_dpt_request_new_peers()?;
        self.poll_dpt_ping()?;
        Ok(result)
    }
}

impl Sink for DevP2PStream {
    type SinkItem = RLPxSendMessage;
    type SinkError = io::Error;

    fn start_send(&mut self, val: RLPxSendMessage) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.poll_dpt_receive_peers()?;
        let result = self.rlpx.start_send(val)?;
        self.poll_dpt_request_new_peers()?;
        self.poll_dpt_ping()?;
        Ok(result)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        try_ready!(self.dpt.poll_complete());
        try_ready!(self.rlpx.poll_complete());
        Ok(Async::Ready(()))
    }
}
