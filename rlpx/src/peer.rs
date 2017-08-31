use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::H512;
use std::io;
use std::net::SocketAddr;
use ecies::ECIESStream;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};
use secp256k1::{self, SECP256K1};
use secp256k1::key::{PublicKey, SecretKey};
use util::pk2id;
use futures::future;
use futures::{Poll, Async, StartSend, AsyncSink, Future, Stream, Sink};
use rlp;

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
/// Capability information
pub struct CapabilityInfo {
    pub name: &'static str,
    pub version: usize,
    pub length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMessage {
    pub name: String,
    pub version: usize,
}

impl Encodable for CapabilityMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for CapabilityMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<CapabilityMessage>,
    pub port: u16,
    pub id: H512,
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);
        s.append(&self.id);
    }
}

impl Decodable for HelloMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}

/// Peer stream of a RLPx
pub struct PeerStream {
    stream: ECIESStream,
    protocol_version: usize,
    client_version: String,
    shared_capabilities: Vec<CapabilityInfo>,
    port: u16,
    id: H512,
    remote_id: H512,
}

impl PeerStream {
    /// Remote public id of this peer
    pub fn remote_id(&self) -> H512 {
        self.remote_id
    }

    /// Get all capabilities of this peer stream
    pub fn capabilities(&self) -> &[CapabilityInfo] {
        &self.shared_capabilities
    }

    /// Connect to a peer over TCP
    pub fn connect(
        addr: &SocketAddr, handle: &Handle,
        secret_key: SecretKey, remote_id: H512,
        protocol_version: usize, client_version: String,
        capabilities: Vec<CapabilityInfo>, port: u16
    ) -> Box<Future<Item = PeerStream, Error = io::Error>> {
        Box::new(
            ECIESStream::connect(addr, handle, secret_key.clone(), remote_id)
                .and_then(move |socket| {
                    PeerStream::new(socket, secret_key, protocol_version,
                                    client_version, capabilities, port)
                }))
    }

    /// Incoming peer stream over TCP
    pub fn incoming(
        stream: TcpStream, secret_key: SecretKey,
        protocol_version: usize, client_version: String,
        capabilities: Vec<CapabilityInfo>, port: u16
    ) -> Box<Future<Item = PeerStream, Error = io::Error>> {
        Box::new(
            ECIESStream::incoming(stream, secret_key.clone())
                .and_then(move |socket| {
                    PeerStream::new(socket, secret_key, protocol_version,
                                    client_version, capabilities, port)
                }))
    }

    /// Create a new peer stream
    pub fn new(
        ecies_stream: ECIESStream, secret_key: SecretKey,
        protocol_version: usize, client_version: String,
        capabilities: Vec<CapabilityInfo>, port: u16
    ) -> Box<Future<Item = PeerStream, Error = io::Error>> {
        let public_key = match PublicKey::from_secret_key(&SECP256K1, &secret_key) {
            Ok(key) => key,
            Err(_) => return Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, "SECP256K1 public key error")))
                as Box<Future<Item = PeerStream, Error = io::Error>>,
        };
        let id = pk2id(&public_key);
        let nonhello_capabilities = capabilities.clone();
        let nonhello_client_version = client_version.clone();

        debug!("connecting to rlpx peer {:x}", id);

        let stream = future::ok(ecies_stream)
            .and_then(move |socket| {
                debug!("sending hello message ...");
                let hello = rlp::encode(&HelloMessage {
                    port, id, protocol_version, client_version,
                    capabilities: {
                        let mut caps = Vec::new();
                        for cap in capabilities {
                            caps.push(CapabilityMessage {
                                name: cap.name.to_string(),
                                version: cap.version
                            });
                        }
                        caps
                    }
                }).to_vec();
                let message_id: Vec<u8> = rlp::encode(&0usize).to_vec();
                assert!(message_id.len() == 1);
                let mut ret: Vec<u8> = Vec::new();
                ret.push(message_id[0]);
                for d in &hello {
                    ret.push(*d);
                }
                socket.send(ret)
            })
            .and_then(|transport| transport.into_future().map_err(|(e, _)| {
                debug!("transport error: {:?}", e);
                e
            }))
            .and_then(move |(hello, transport)| {
                debug!("receiving hello message ...");
                if hello.is_none() {
                    debug!("hello failed because of no value");
                    return Err(io::Error::new(io::ErrorKind::Other, "hello failed (no value)"));
                }
                let hello = hello.unwrap();

                let message_id_rlp = UntrustedRlp::new(&hello[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();
                match message_id {
                    Ok(message_id) => {
                        if message_id != 0 {
                            error!("hello failed because message id is not 0 but {}", message_id);
                            return Err(io::Error::new(io::ErrorKind::Other,
                                                      "hello failed (message id)"));
                        }
                    },
                    Err(_) => {
                        debug!("hello failed because message id cannot be parsed");
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "hello failed (message id parsing)"));
                    }
                }

                let rlp: Result<HelloMessage, rlp::DecoderError> =
                    UntrustedRlp::new(&hello[1..]).as_val();
                match rlp {
                    Ok(val) => {
                        debug!("hello message: {:?}", val);
                        let mut shared_capabilities: Vec<CapabilityInfo> = Vec::new();

                        for cap_info in nonhello_capabilities {
                            if val.capabilities.iter().find(
                                |v| v.name == cap_info.name && v.version == cap_info.version)
                                .is_some()
                            {
                                shared_capabilities.push(cap_info.clone());
                            }
                        }

                        let mut shared_caps_original = shared_capabilities.clone();

                        for cap_info in shared_caps_original {
                            shared_capabilities.retain(|v| {
                                if v.name != cap_info.name { true }
                                else if v.version < cap_info.version { false }
                                else { true }
                            });
                        }

                        shared_capabilities.sort_by_key(|v| v.name.clone());

                        Ok(PeerStream {
                            remote_id: transport.remote_id(),
                            stream: transport,
                            client_version: nonhello_client_version,
                            protocol_version, port, id,
                            shared_capabilities,
                        })
                    },
                    Err(_) => {
                        debug!("hello failed because message rlp parsing failed");
                        Err(io::Error::new(io::ErrorKind::Other, "hello failed (rlp error)"))
                    }
                }
            });

        Box::new(stream)
    }

    fn handle_reserved_message(
        &mut self, message_id: usize, data: Vec<u8>
    ) -> Result<(), io::Error> {
        match message_id {
            0x01 /* disconnect */ => {
                let reason: Result<usize, rlp::DecoderError> = UntrustedRlp::new(&data).val_at(0);
                debug!("received disconnect message, reason: {:?}", reason);
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "explicit disconnect"));
            },
            0x02 /* ping */ => {
                debug!("received ping message data {:?}", data);
                let mut payload: Vec<u8> = rlp::encode(&0x03usize /* pong */).to_vec();
                payload.append(&mut rlp::EMPTY_LIST_RLP.to_vec());
                debug!("sending pong message payload {:?}", payload);
                self.stream.start_send(payload)?;
                self.stream.poll_complete()?;
            },
            0x03 /* pong */ => {
                debug!("received pong message");
            },
            _ => {
                debug!("received unknown reserved message");
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "unhandled reserved message"))
            },
        }
        Ok(())
    }
}

impl Stream for PeerStream {
    type Item = (CapabilityInfo, usize, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.stream.poll()) {
            Some(val) => {
                debug!("received peer message: {:?}", val);
                let message_id_rlp = UntrustedRlp::new(&val[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();

                let (cap, id) = match message_id {
                    Ok(message_id) => {
                        if message_id < 0x10 {
                            self.handle_reserved_message(message_id, (&val[1..]).into())?;
                            return Ok(Async::NotReady);
                        }

                        let mut message_id = message_id - 0x10;
                        let mut index = 0;
                        for cap in &self.shared_capabilities {
                            if message_id > cap.length {
                                message_id = message_id - cap.length;
                                index = index + 1;
                            }
                        }
                        if index >= self.shared_capabilities.len() {
                            return Err(io::Error::new(io::ErrorKind::Other,
                                                      "message id parsing failed (too big)"));
                        }
                        (self.shared_capabilities[index].clone(), message_id)
                    },
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "message id parsing failed (invalid)"));
                    }
                };

                Ok(Async::Ready(Some((cap, id, (&val[1..]).into()))))
            },
            None => Ok(Async::Ready(None)),
        }
    }
}

impl Sink for PeerStream {
    type SinkItem = (&'static str, usize, Vec<u8>);
    type SinkError = io::Error;

    fn start_send(&mut self, (cap_name, id, data): (&'static str, usize, Vec<u8>)) -> StartSend<Self::SinkItem, Self::SinkError> {
        let cap = self.shared_capabilities.iter().find(|cap| {
            cap.name == cap_name
        });

        if cap.is_none() {
            debug!("giving up sending cap {} of id {} to 0x{:x} because remote does not support.",
                   cap_name, id, self.remote_id());
            return Ok(AsyncSink::Ready);
        }

        let cap = *cap.unwrap();

        if id >= cap.length {
            debug!("giving up sending cap {} of id {} to 0x{:x} because it is too big.",
                   cap_name, id, self.remote_id());
            return Ok(AsyncSink::Ready);
        }

        let mut message_id = 0x10;
        for scap in &self.shared_capabilities {
            if scap != &cap {
                message_id = message_id + scap.length;
            } else {
                break;
            }
        }
        message_id = message_id + id;
        let first = rlp::encode(&message_id);
        assert!(first.len() == 1);

        let mut ret: Vec<u8> = Vec::new();
        ret.push(first[0]);
        for d in &data {
            ret.push(*d);
        }

        match self.stream.start_send(ret)? {
            AsyncSink::Ready => Ok(AsyncSink::Ready),
            AsyncSink::NotReady(_) => Ok(AsyncSink::NotReady((cap_name, id, data))),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }
}
