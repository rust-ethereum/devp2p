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
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl Encodable for Capability {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for Capability {
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
    pub capabilities: Vec<Capability>,
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
    shared_capabilities: Vec<Capability>,
    port: usize,
    id: H512,
}

impl PeerStream {
    pub fn connect(
        addr: &SocketAddr, handle: &Handle,
        secret_key: SecretKey, remote_id: H512,
        protocol_version: usize, client_version: String,
        capabilities: Vec<Capability>, port: usize
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
            .and_then(move |socket| socket.send(rlp::encode(&HelloMessage {
                port, id, protocol_version, client_version, capabilities
            }).to_vec()))
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(move |(hello, transport)| {
                if hello.is_none() {
                    return Err(io::Error::new(io::ErrorKind::Other, "hello failed"));
                }

                let hello = hello.unwrap();
                if hello[0] != 0 && hello[0] != 128 {
                    Err(io::Error::new(io::ErrorKind::Other, "hello failed"))
                } else {
                    let rlp: Result<HelloMessage, rlp::DecoderError> =
                        UntrustedRlp::new(&hello[1..]).as_val();
                    match rlp {
                        Ok(val) => {
                            println!("hello message: {:?}", val);
                            let mut shared_capabilities: Vec<Capability> = Vec::new();
                            for cap in nonhello_capabilities {
                                if val.capabilities.contains(&cap) {
                                    shared_capabilities.push(cap.clone())
                                }
                            }
                            Ok(PeerStream {
                                stream: transport,
                                client_version: nonhello_client_version,
                                protocol_version, port, id,
                                shared_capabilities
                            })
                        },
                        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "hello failed"))
                    }
                }
            });

        Box::new(stream)
    }
}
