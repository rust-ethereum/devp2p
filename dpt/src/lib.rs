//! Ethereum DPT protocol implementation

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::cognitive_complexity,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

mod message;
mod proto;
mod util;

use bigint::{H256, H512};
use futures::{Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use log::*;
use message::*;
use proto::{DPTCodec, DPTCodecMessage};
use rand::{thread_rng, Rng};
use rlp::UntrustedRlp;
use secp256k1::{
    key::{PublicKey, SecretKey},
    SECP256K1,
};
use std::{
    convert::TryFrom,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};
use tokio_core::{
    net::{UdpFramed, UdpSocket},
    reactor::{Handle, Timeout},
};
use url::{Host, Url};
use util::pk2id;

/// DPT message for requesting new peers or ping with timeout
pub enum DPTMessage {
    RequestNewPeer,
    Ping(Timeout),
}

/// DPT stream for sending DPT messages or receiving new peers
pub struct DPTStream {
    stream: UdpFramed<DPTCodec>,
    id: H512,
    connected: Vec<DPTNode>,
    pingponged: Vec<DPTNode>,
    bootstrapped: bool,
    timeout: Option<(Timeout, Vec<H512>)>,
    incoming: Vec<DPTNode>,
    address: IpAddr,
    udp_port: u16,
    tcp_port: u16,
}

/// DPT node used by a DPT stream
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DPTNode {
    pub address: IpAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub id: H512,
}

#[derive(Debug, Clone)]
pub enum DPTNodeParseError {
    UrlError,
    HexError,
}

impl DPTNode {
    /// The TCP socket address of this node
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.tcp_port)
    }

    /// The UDP socket address of this node
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.udp_port)
    }

    pub fn from_url(url: &Url) -> Result<Self, DPTNodeParseError> {
        let address = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
            Some(Host::Domain(ip)) => IpAddr::V4(Ipv4Addr::from_str(ip).unwrap()),
            _ => return Err(DPTNodeParseError::UrlError),
        };
        let port = match url.port() {
            Some(port) => port,
            _ => return Err(DPTNodeParseError::UrlError),
        };
        let id = match H512::from_str(url.username()) {
            Ok(id) => id,
            _ => return Err(DPTNodeParseError::HexError),
        };

        Ok(Self {
            address,
            id,
            tcp_port: port,
            udp_port: port,
        })
    }
}

impl DPTStream {
    /// Create a new DPT stream
    pub fn new(
        addr: SocketAddr,
        handle: &Handle,
        secret_key: SecretKey,
        bootstrap_nodes: Vec<DPTNode>,
        public_address: IpAddr,
        tcp_port: u16,
    ) -> Result<Self, io::Error> {
        let id = pk2id(&match PublicKey::from_secret_key(&SECP256K1, &secret_key) {
            Ok(val) => val,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "converting pub key failed",
                ))
            }
        });
        debug!("self id: {:x}", id);
        Ok(Self {
            stream: UdpSocket::bind(&addr, handle)?.framed(DPTCodec::new(secret_key)),
            id,
            connected: bootstrap_nodes.clone(),
            incoming: bootstrap_nodes,
            pingponged: Vec::new(),
            bootstrapped: false,
            timeout: None,
            address: public_address,
            udp_port: addr.port(),
            tcp_port,
        })
    }

    /// Get all connected peers
    pub fn connected_peers(&self) -> &[DPTNode] {
        &self.pingponged
    }

    /// Disconnect from a node
    pub fn disconnect_peer(&mut self, remote_id: H512) {
        self.connected.retain(|node| node.id != remote_id);
        self.pingponged.retain(|node| node.id != remote_id);
    }

    /// Get the peer by its id
    pub fn get_peer(&self, remote_id: H512) -> Option<DPTNode> {
        self.connected
            .iter()
            .find(|connected_peer| connected_peer.id == remote_id)
            .copied()
    }

    fn default_expire() -> u64 {
        u64::try_from(time::now_utc().to_timespec().sec)
            .expect("this would predate the protocol inception")
            + 60
    }

    fn send_ping(&mut self, addr: SocketAddr, to: DPTNode) -> Poll<(), io::Error> {
        let typ = 0x01_u8;
        let message = PingMessage {
            from: Endpoint {
                address: self.address,
                udp_port: self.udp_port,
                tcp_port: self.tcp_port,
            },
            to: Endpoint {
                address: to.address,
                udp_port: to.udp_port,
                tcp_port: to.tcp_port,
            },
            expire: Self::default_expire(),
        };
        let data = rlp::encode(&message).to_vec();

        self.stream
            .start_send(DPTCodecMessage { typ, data, addr })?;
        self.stream.poll_complete()?;

        Ok(Async::Ready(()))
    }

    fn send_pong(&mut self, addr: SocketAddr, echo: H256, to: Endpoint) -> Poll<(), io::Error> {
        let typ = 0x02_u8;
        let message = PongMessage {
            echo,
            to,
            expire: Self::default_expire(),
        };
        let data = rlp::encode(&message).to_vec();

        debug!("sending pong ...");
        self.stream
            .start_send(DPTCodecMessage { typ, data, addr })?;
        self.stream.poll_complete()?;

        Ok(Async::Ready(()))
    }

    fn send_find_neighbours(&mut self, addr: SocketAddr) -> Poll<(), io::Error> {
        let typ = 0x03_u8;
        let message = FindNeighboursMessage {
            id: self.id,
            expire: Self::default_expire(),
        };
        let data = rlp::encode(&message).to_vec();

        self.stream
            .start_send(DPTCodecMessage { typ, data, addr })?;
        self.stream.poll_complete()?;

        Ok(Async::Ready(()))
    }

    fn send_neighbours(&mut self, addr: SocketAddr) -> Poll<(), io::Error> {
        let typ = 0x04_u8;
        // Return at most 3 nodes at a time.
        let mut nodes = Vec::new();
        for i in 0..self.connected.len() {
            if nodes.len() >= 3 {
                break;
            }

            let address = self.connected[i].address;
            let udp_port = self.connected[i].udp_port;
            let tcp_port = self.connected[i].tcp_port;
            let id = self.connected[i].id;

            nodes.push(Neighbour {
                address,
                udp_port,
                tcp_port,
                id,
            });
        }
        let message = NeighboursMessage {
            nodes,
            expire: Self::default_expire(),
        };
        let data = rlp::encode(&message).to_vec();

        self.stream
            .start_send(DPTCodecMessage { typ, data, addr })?;
        self.stream.poll_complete()?;

        Ok(Async::Ready(()))
    }
}

impl Stream for DPTStream {
    type Item = DPTNode;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.bootstrapped {
            for node in self.connected.clone() {
                self.send_ping(node.udp_addr(), node)?;
            }
            self.bootstrapped = true;
        }

        let mut timeoutted = false;
        if self.timeout.is_some() {
            let (timeout, hs) = self.timeout.as_mut().unwrap();
            timeoutted = match timeout.poll() {
                Ok(Async::Ready(())) => true,
                Ok(Async::NotReady) => false,
                Err(e) => return Err(e),
            };

            if timeoutted {
                debug!("{} endpoints timeoutted", hs.len());
                for h in hs {
                    self.connected.retain(|v| v.id != *h);
                }
            }
        }
        if timeoutted {
            self.timeout = None;
        }

        loop {
            let (message, remote_id, hash) = match self.stream.poll()? {
                Async::Ready(Some(Some(val))) => val,
                Async::Ready(Some(None)) => continue,
                Async::NotReady => {
                    if !self.incoming.is_empty() {
                        return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                    }

                    return Ok(Async::NotReady);
                }
                Async::Ready(None) => return Ok(Async::Ready(None)),
            };

            match message.typ {
                0x01 /* ping */ => {
                    debug!("got ping message");
                    let ping_message: PingMessage = match UntrustedRlp::new(&message.data).as_val() {
                    Ok(val) => val,
                        Err(_) => continue,
                    };

                    self.send_pong(message.addr, hash, ping_message.to)?;

                    let v = self.connected.iter().find(|v| v.id == remote_id).cloned();
                    if let Some(v) = v {
                        if !self.pingponged.contains(&v) {
                            self.pingponged.push(v);
                        }
                    }
                },
                0x02 /* pong */ => {
                    debug!("got pong message");
                    if UntrustedRlp::new(&message.data).as_val::<PongMessage>().is_err() {
                        continue
                    }

                    if self.timeout.is_some() {
                        self.timeout.as_mut().unwrap().1.retain(|v| {
                            *v != remote_id
                        });
                    }

                    let v = self.connected.iter().find(|v| v.id == remote_id).cloned();
                    if let Some(v) = v {
                        if !self.pingponged.contains(&v) {
                            debug!("pushing pingponged: {:?}", v);
                            self.pingponged.push(v);
                        }
                    }
                },
                0x03 /* find neighbours */ => {
                    debug!("got find neighbours message");
                    self.send_neighbours(message.addr)?;
                },
                0x04 /* neighbours */ => {
                    debug!("got neighbours message");
                    let incoming_message: NeighboursMessage =
                        match UntrustedRlp::new(&message.data).as_val() {
                            Ok(val) => val,
                            Err(_) => continue,
                        };
                    debug!("neighbouts message len {}", incoming_message.nodes.len());
                    for node in incoming_message.nodes {
                        let node = DPTNode {
                            address: node.address,
                            udp_port: node.udp_port,
                            tcp_port: node.tcp_port,
                            id: node.id,
                    };
                        if !self.connected.contains(&node) {
                            self.send_ping(node.udp_addr(), node.clone())?;

                            debug!("pushing new node {:?}", node);
                            self.connected.push(node.clone());
                            self.incoming.push(node.clone());
                            debug!("connected {}", self.connected.len());
                        }
                    }
                },
                _ => { }
            }

            if !self.incoming.is_empty() {
                return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
            }
        }
    }
}

impl Sink for DPTStream {
    type SinkItem = DPTMessage;
    type SinkError = io::Error;

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }

    fn start_send(&mut self, message: DPTMessage) -> StartSend<Self::SinkItem, Self::SinkError> {
        match message {
            DPTMessage::RequestNewPeer => {
                debug!("randomly selecting one peer from {}", self.pingponged.len());
                thread_rng().shuffle(&mut self.pingponged);

                if self.pingponged.is_empty() {
                    debug!("no peers available to find node");
                    for node in self.connected.clone() {
                        self.send_ping(node.udp_addr(), node)?;
                    }
                    return Ok(AsyncSink::Ready);
                }

                let addr = self.pingponged[0].udp_addr();
                self.send_find_neighbours(addr)?;

                Ok(AsyncSink::Ready)
            }

            DPTMessage::Ping(timeout) => {
                let mut timeoutting = Vec::new();
                for node in self.connected.clone() {
                    self.send_ping(node.udp_addr(), node.clone())?;
                    timeoutting.push(node.id);
                }

                self.timeout = Some((timeout, timeoutting));

                Ok(AsyncSink::Ready)
            }
        }
    }
}
