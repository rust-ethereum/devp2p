use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::H512;
use std::io;
use std::net::SocketAddr;
use ecies::ECIESStream;
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};
use secp256k1::key::{PublicKey, SecretKey};
use hash::SECP256K1;
use util::pk2id;
use futures::future;
use futures::{Poll, Async, StartSend, AsyncSink, Future, Stream, Sink};
use rlp;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityInfo {
    pub name: String,
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
    pub port: usize,
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

pub struct PeerStream {
    stream: ECIESStream,
    protocol_version: usize,
    client_version: String,
    shared_capabilities: Vec<CapabilityInfo>,
    port: usize,
    id: H512,
}

impl PeerStream {
    pub fn connect(
        addr: &SocketAddr, handle: &Handle,
        secret_key: SecretKey, remote_id: H512,
        protocol_version: usize, client_version: String,
        capabilities: Vec<CapabilityInfo>, port: usize
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

        let stream = ECIESStream::connect(addr, handle, secret_key.clone(), remote_id)
            .and_then(move |socket| {
                let hello = rlp::encode(&HelloMessage {
                    port, id, protocol_version, client_version,
                    capabilities: {
                        let mut caps = Vec::new();
                        for cap in capabilities {
                            caps.push(CapabilityMessage {
                                name: cap.name,
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
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(move |(hello, transport)| {
                if hello.is_none() {
                    return Err(io::Error::new(io::ErrorKind::Other, "hello failed (no value)"));
                }
                let hello = hello.unwrap();

                let message_id_rlp = UntrustedRlp::new(&hello[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();
                match message_id {
                    Ok(message_id) => {
                        if message_id != 0 {
                            return Err(io::Error::new(io::ErrorKind::Other,
                                                      "hello failed (message id)"));
                        }
                    },
                    Err(_) => {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                                  "hello failed (message id parsing)"));
                    }
                }

                let rlp: Result<HelloMessage, rlp::DecoderError> =
                    UntrustedRlp::new(&hello[1..]).as_val();
                match rlp {
                    Ok(val) => {
                        println!("hello message: {:?}", val);
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
                            stream: transport,
                            client_version: nonhello_client_version,
                            protocol_version, port, id,
                            shared_capabilities
                        })
                    },
                    Err(_) => Err(io::Error::new(io::ErrorKind::Other, "hello failed (rlp error)"))
                }
            });

        Box::new(stream)
    }
}

impl Stream for PeerStream {
    type Item = (CapabilityInfo, usize, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match try_ready!(self.stream.poll()) {
            Some(val) => {
                let message_id_rlp = UntrustedRlp::new(&val[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();

                let (cap, id) = match message_id {
                    Ok(message_id) => {
                        if message_id < 0x10 {
                            println!("got reserved message: {}, {:?}", message_id, &val[1..]);
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
    type SinkItem = (CapabilityInfo, usize, Vec<u8>);
    type SinkError = io::Error;

    fn start_send(&mut self, (cap, id, data): (CapabilityInfo, usize, Vec<u8>)) -> StartSend<Self::SinkItem, Self::SinkError> {
        if !self.shared_capabilities.contains(&cap) {
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
            AsyncSink::NotReady(_) => Ok(AsyncSink::NotReady((cap, id, data))),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }
}
