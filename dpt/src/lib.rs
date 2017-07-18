//! Ethereum DPT protocol implementation

extern crate etcommon_bigint as bigint;
extern crate etcommon_crypto as hash;
extern crate etcommon_rlp as rlp;
extern crate sha3;
extern crate secp256k1;
#[macro_use]
extern crate log;
#[macro_use]
extern crate futures;
extern crate tokio_io;
extern crate tokio_core;
extern crate time;
extern crate rand;
extern crate url;

mod proto;
mod message;
mod util;

use message::*;
use proto::{DPTCodec, DPTCodecMessage};
use futures::future;
use futures::{Poll, Async, StartSend, AsyncSink, Future, Stream, Sink};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};
use tokio_core::reactor::{Timeout, Handle};
use tokio_core::net::{UdpSocket, UdpFramed};
use std::net::{IpAddr, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::io;
use std::str::FromStr;
use bigint::{H256, H512};
use rlp::UntrustedRlp;
use hash::SECP256K1;
use secp256k1::key::{PublicKey, SecretKey};
use util::pk2id;
use rand::{Rng, thread_rng};
use url::{Host, Url};

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
    timeout: Option<(Timeout, Vec<H512>)>,
    incoming: Vec<DPTNode>,
    address: IpAddr,
    udp_port: u16,
    tcp_port: u16,
}

#[derive(Debug, Clone)]
/// DPT node used by a DPT stream
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
    pub fn tcp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.tcp_port)
    }

    /// The UDP socket address of this node
    pub fn udp_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.udp_port)
    }

    pub fn from_url(url: &Url) -> Result<DPTNode, DPTNodeParseError> {
        let address = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
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

        Ok(DPTNode {
            address, id,
            tcp_port: port,
            udp_port: port,
        })
    }
}

impl DPTStream {
    /// Create a new DPT stream
    pub fn new(addr: &SocketAddr, handle: &Handle,
               secret_key: SecretKey,
               bootstrap_nodes: Vec<DPTNode>,
               tcp_port: u16) -> Result<Self, io::Error> {
        let id = pk2id(&match PublicKey::from_secret_key(&SECP256K1, &secret_key) {
            Ok(val) => val,
            Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "converting pub key failed")),
        });
        Ok(Self {
            stream: UdpSocket::bind(addr, handle)?.framed(DPTCodec::new(secret_key)),
            id, connected: bootstrap_nodes, incoming: Vec::new(),
            timeout: None,
            address: addr.ip(), udp_port: addr.port(), tcp_port
        })
    }

    /// Disconnect from a node
    pub fn disconnect_peer(&mut self, remote_id: H512) {
        self.connected.retain(|node| {
            node.id != remote_id
        });
    }

    /// Get the peer by its id
    pub fn get_peer(&self, remote_id: H512) -> Option<DPTNode> {
        for i in 0..self.connected.len() {
            if self.connected[i].id == remote_id {
                return Some(self.connected[i].clone());
            }
        }
        return None;
    }
}

impl Stream for DPTStream {
    type Item = DPTNode;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let mut timeoutted = false;
        if self.timeout.is_some() {
            let &mut (ref mut timeout, ref hs) = self.timeout.as_mut().unwrap();
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

        let (message, remote_id, hash) = match try!(self.stream.poll()) {
            Async::Ready(Some(Some(val))) => val,
            Async::Ready(Some(None)) | Async::NotReady => {
                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else if self.connected.len() == 0 {
                    return Err(io::Error::new(io::ErrorKind::Other, "no reachable DPT endpoint"));
                } else {
                    return Ok(Async::NotReady);
                }
            },
            Async::Ready(None) => return Ok(Async::Ready(None)),
        };

        match message.typ {
            0x01 /* ping */ => {
                debug!("got ping message");
                let incoming_message: PingMessage = match UntrustedRlp::new(&message.data).as_val() {
                    Ok(val) => val,
                    Err(_) =>
                        if self.incoming.len() > 0 {
                            return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                        } else {
                            return Ok(Async::NotReady);
                        },
                };
                let typ = 0x02u8;
                let echo = hash;
                let to = incoming_message.from;
                let outgoing_message = PongMessage {
                    echo, to, timestamp: time::now_utc().to_timespec().sec as u64,
                };
                let data = rlp::encode(&outgoing_message).to_vec();

                // If sending pong is not available, drop.
                self.stream.start_send(DPTCodecMessage {
                    typ, data, addr: message.addr
                });

                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else {
                    return Ok(Async::NotReady);
                }
            },
            0x02 /* pong */ => {
                debug!("got pong message");
                let incoming_message: PongMessage = match UntrustedRlp::new(&message.data).as_val() {
                    Ok(val) => val,
                    Err(_) =>
                        if self.incoming.len() > 0 {
                            return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                        } else {
                            return Ok(Async::NotReady);
                        },
                };
                if self.timeout.is_some() {
                    self.timeout.as_mut().unwrap().1.retain(|v| {
                        *v != remote_id
                    });
                }

                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else {
                    return Ok(Async::NotReady);
                }
            },
            0x03 /* find neighbours */ => {
                debug!("got find neighbours message");
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
                        address, udp_port, tcp_port, id,
                    });
                }
                let typ = 0x04u8;
                let outgoing_message = NeighboursMessage {
                    nodes, timestamp: time::now_utc().to_timespec().sec as u64,
                };
                let data = rlp::encode(&outgoing_message).to_vec();

                self.stream.start_send(DPTCodecMessage {
                    typ, data, addr: message.addr
                });

                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else {
                    return Ok(Async::NotReady);
                }
            },
            0x04 /* neighbours */ => {
                debug!("got neighbours message");
                let incoming_message: NeighboursMessage = match UntrustedRlp::new(&message.data).as_val() {
                    Ok(val) => val,
                    Err(_) => {
                        debug!("neighbours parsing error");
                        if self.incoming.len() > 0 {
                            return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                        } else {
                            return Ok(Async::NotReady);
                        }
                    }
                };
                debug!("neighbouts message len {}", incoming_message.nodes.len());
                for i in 0..incoming_message.nodes.len() {
                    if self.connected.iter()
                        .all(|node| node.id != incoming_message.nodes[i].id)
                    {
                        let ip = incoming_message.nodes[i].address;
                        let tcp_port = incoming_message.nodes[i].tcp_port;
                        let udp_port = incoming_message.nodes[i].udp_port;
                        let remote_id = incoming_message.nodes[i].id;
                        let addr = SocketAddr::new(ip, udp_port);
                        let node = DPTNode {
                            address: ip,
                            udp_port, tcp_port,
                            id: remote_id
                        };
                        debug!("pushing new node {:?}", node);
                        self.connected.push(node.clone());
                        self.incoming.push(node);
                        debug!("connected {}", self.connected.len());
                    } else {
                        // debug!("already connected {:x}", incoming_message.nodes[i].id);
                    }
                }
                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else {
                    return Ok(Async::NotReady);
                }
            },
            _ => {
                if self.incoming.len() > 0 {
                    return Ok(Async::Ready(Some(self.incoming.pop().unwrap())));
                } else {
                    return Ok(Async::NotReady);
                }
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
                let mut any_sent = false;
                let typ = 0x03u8;
                let message = FindNeighboursMessage {
                    id: self.id,
                    timestamp: time::now_utc().to_timespec().sec as u64,
                };
                let data = rlp::encode(&message).to_vec();

                let ref mut connected = self.connected;
                let ref mut stream = self.stream;
                thread_rng().shuffle(connected);

                retain_mut(connected, |node| {
                    match stream.start_send(DPTCodecMessage {
                        addr: node.udp_addr(), typ, data: data.clone()
                    }) {
                        Ok(AsyncSink::Ready) => {
                            any_sent = true;
                            true
                        },
                        Ok(AsyncSink::NotReady(_)) => true,
                        Err(_) => false,
                    }
                });
                if any_sent {
                    return Ok(AsyncSink::Ready);
                } else {
                    return Ok(AsyncSink::NotReady(DPTMessage::RequestNewPeer));
                }
            },

            DPTMessage::Ping(timeout) => {
                let mut any_sent = false;
                let mut timeouting = Vec::new();
                let from_endpoint = Endpoint {
                    address: self.address.clone(),
                    udp_port: self.udp_port,
                    tcp_port: self.tcp_port,
                };
                let ref mut connected = self.connected;
                let ref mut stream = self.stream;
                retain_mut(connected, |node| {
                    let typ = 0x01u8;
                    let (address, tcp_port, udp_port, remote_id) =
                        (node.address, node.tcp_port, node.udp_port, node.id);
                    let message = PingMessage {
                        version: H256::from(0x3),
                        from: from_endpoint.clone(),
                        to: Endpoint {
                            address, udp_port, tcp_port
                        },
                        timestamp: time::now_utc().to_timespec().sec as u64,
                    };
                    let data = rlp::encode(&message).to_vec();
                    match stream.start_send(DPTCodecMessage {
                        addr: node.udp_addr(), typ, data
                    }) {
                        Ok(AsyncSink::Ready) => {
                            any_sent = true;
                            timeouting.push(remote_id);
                            true
                        },
                        Ok(AsyncSink::NotReady(_)) => true,
                        Err(_) => false,
                    }
                });
                if any_sent {
                    self.timeout = Some((timeout, timeouting));
                    return Ok(AsyncSink::Ready);
                } else {
                    return Ok(AsyncSink::NotReady(DPTMessage::Ping(timeout)));
                }
            }

        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
