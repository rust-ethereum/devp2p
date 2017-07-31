use dpt::{DPTNode, DPTStream, DPTMessage};
use rlpx::{RLPxSendMessage, RLPxReceiveMessage, CapabilityInfo, RLPxStream};
use tokio_core::reactor::{Handle, Timeout};
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};
use std::cmp::min;
use std::io;
use secp256k1::key::SecretKey;
use futures::{StartSend, Async, Poll, Stream, Sink, Future, future};
use bigint::H512;
use rand::{thread_rng, Rng};

/// Config for DevP2P
pub struct DevP2PConfig {
    pub ping_interval: Duration,
    pub ping_timeout_interval: Duration,
    pub optimal_peers_len: usize,
    pub optimal_peers_interval: Duration,
    pub reconnect_dividend: usize,
}

/// An Ethereum DevP2P stream that handles peers management
pub struct DevP2PStream {
    dpt: DPTStream,
    rlpx: RLPxStream,

    ping_timeout: Timeout,
    optimal_peers_timeout: Timeout,
    handle: Handle,

    config: DevP2PConfig,
}

impl DevP2PStream {
    /// Create a new DevP2P stream
    pub fn new(addr: &SocketAddr, public_addr: &IpAddr,
               handle: &Handle, secret_key: SecretKey,
               protocol_version: usize, client_version: String,
               capabilities: Vec<CapabilityInfo>,
               bootstrap_nodes: Vec<DPTNode>,
               config: DevP2PConfig,
    ) -> Result<Self, io::Error> {
        let port = addr.port();

        let mut rlpx = RLPxStream::new(handle, secret_key.clone(),
                                       protocol_version, client_version,
                                       capabilities, port);

        let dpt = DPTStream::new(addr, handle, secret_key.clone(),
                                 bootstrap_nodes, public_addr, port)?;

        let ping_timeout = Timeout::new(config.ping_interval, handle)?;
        let optimal_peers_timeout = Timeout::new(config.optimal_peers_interval, handle)?;

        Ok(DevP2PStream {
            dpt, rlpx, ping_timeout,
            optimal_peers_timeout,
            config,
            handle: handle.clone()
        })
    }

    /// Force disconnecting a peer if it is already connected or about
    /// to be connected. Useful for removing peers on a different hard
    /// fork network
    pub fn disconnect_peer(&mut self, remote_id: H512) {
        self.rlpx.disconnect_peer(remote_id);
        self.dpt.disconnect_peer(remote_id);
    }

    /// Active peers
    pub fn active_peers(&mut self) -> &[H512] {
        self.rlpx.active_peers()
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
        let mut result = self.optimal_peers_timeout.poll()?;

        loop {
            match result {
                Async::NotReady => return Ok(Async::Ready(())),
                Async::Ready(()) => {
                    if self.rlpx.active_peers().len() < self.config.optimal_peers_len {
                        error!("not enough peers (only {}), requesting new ...", self.rlpx.active_peers().len());
                        self.dpt.start_send(DPTMessage::RequestNewPeer)?;
                        self.dpt.poll_complete()?;

                        debug!("reconnect to old connected peers ...");
                        let mut connected: Vec<DPTNode> = self.dpt.connected_peers().into();
                        thread_rng().shuffle(&mut connected);
                        for i in 0..min(self.config.optimal_peers_len - self.rlpx.active_peers().len(),
                                        connected.len() / self.config.reconnect_dividend) {
                            self.rlpx.add_peer(&SocketAddr::new(connected[i].address,
                                                                connected[i].tcp_port),
                                               connected[i].id);
                        }
                    }

                    self.optimal_peers_timeout = Timeout::new(self.config.optimal_peers_interval,
                                                              &self.handle)?;

                    result = self.optimal_peers_timeout.poll()?;
                }
            }
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
                        self.config.ping_timeout_interval, &self.handle)?))?;
                    self.dpt.poll_complete()?;
                    self.ping_timeout = Timeout::new(self.config.ping_interval, &self.handle)?;

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
