use super::algorithm::ECIES;
use crate::errors::ECIESError;
use bigint::H512;
use bytes::BytesMut;
use futures::{future, try_ready, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream};
use log::*;
use secp256k1::key::SecretKey;
use std::{io, net::SocketAddr};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_core::{net::TcpStream, reactor::Handle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Current ECIES state of a connection
pub enum ECIESState {
    Auth,
    Ack,
    Header,
    Body,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw values for an ECIES protocol
pub enum ECIESValue {
    Auth,
    Ack,
    Header(usize),
    Body(Vec<u8>),
    AuthReceive(H512),
}

/// Tokio codec for ECIES
pub struct ECIESCodec {
    ecies: ECIES,
    state: ECIESState,
}

impl ECIESCodec {
    /// Create a new server codec using the given secret key
    pub fn new_server(secret_key: SecretKey) -> Result<Self, ECIESError> {
        Ok(Self {
            ecies: ECIES::new_server(secret_key)?,
            state: ECIESState::Auth,
        })
    }

    /// Create a new client codec using the given secret key and the server's public id
    pub fn new_client(secret_key: SecretKey, remote_id: H512) -> Result<Self, ECIESError> {
        Ok(Self {
            ecies: ECIES::new_client(secret_key, remote_id)?,
            state: ECIESState::Auth,
        })
    }
}

impl Decoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<ECIESValue>, io::Error> {
        match self.state {
            ECIESState::Auth => {
                if buf.len() < ECIES::auth_len() {
                    return Ok(None);
                }

                let data = buf.split_to(ECIES::auth_len());
                self.ecies.parse_auth(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::AuthReceive(self.ecies.remote_id())))
            }
            ECIESState::Ack => {
                if buf.len() < ECIES::ack_len() {
                    return Ok(None);
                }

                let data = buf.split_to(ECIES::ack_len());
                self.ecies.parse_ack(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Ack))
            }
            ECIESState::Header => {
                if buf.len() < ECIES::header_len() {
                    return Ok(None);
                }

                let data = buf.split_to(ECIES::header_len());
                let size = self.ecies.parse_header(&data)?;

                self.state = ECIESState::Body;
                Ok(Some(ECIESValue::Header(size)))
            }
            ECIESState::Body => {
                if buf.len() < self.ecies.body_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.body_len());
                let ret = self.ecies.parse_body(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Body(ret)))
            }
        }
    }
}

impl Encoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn encode(&mut self, msg: ECIESValue, buf: &mut BytesMut) -> Result<(), io::Error> {
        match msg {
            ECIESValue::AuthReceive(_) => panic!(),
            ECIESValue::Auth => {
                let data = self.ecies.create_auth()?;
                self.state = ECIESState::Ack;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
            ECIESValue::Ack => {
                let data = self.ecies.create_ack()?;
                self.state = ECIESState::Header;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
            ECIESValue::Header(size) => {
                let data = self.ecies.create_header(size);
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
            ECIESValue::Body(val) => {
                let data = self.ecies.create_body(val.as_ref());
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
        }
    }
}

/// ECIES stream over TCP exchanging raw bytes
pub struct ECIESStream {
    stream: Framed<TcpStream, ECIESCodec>,
    polled_header: bool,
    sending_body: Option<Vec<u8>>,
    remote_id: H512,
}

impl ECIESStream {
    /// Connect to an ECIES server
    #[must_use]
    pub fn connect(
        addr: &SocketAddr,
        handle: &Handle,
        secret_key: SecretKey,
        remote_id: H512,
    ) -> Box<dyn Future<Item = Self, Error = io::Error>> {
        let ecies = match ECIESCodec::new_client(secret_key, remote_id) {
            Ok(val) => val,
            Err(_) => {
                return Box::new(future::err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid handshake",
                ))) as Box<dyn Future<Item = _, Error = _>>
            }
        };

        debug!("connecting to ecies stream ...");
        let stream = TcpStream::connect(addr, handle)
            .and_then(|socket| {
                debug!("sending ecies auth ...");
                ecies.framed(socket).send(ECIESValue::Auth)
            })
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(move |(ack, transport)| {
                debug!("receiving ecies ack ...");
                if ack == Some(ECIESValue::Ack) {
                    Ok(Self {
                        stream: transport,
                        polled_header: false,
                        sending_body: None,
                        remote_id,
                    })
                } else {
                    error!("expected ack, got {:?} instead", ack);
                    Err(io::Error::new(io::ErrorKind::Other, "invalid handshake"))
                }
            });

        Box::new(stream)
    }

    /// Listen on a just connected ECIES clinet
    pub fn incoming(
        stream: TcpStream,
        secret_key: SecretKey,
    ) -> Box<dyn Future<Item = Self, Error = io::Error>> {
        let ecies = match ECIESCodec::new_server(secret_key) {
            Ok(val) => val,
            Err(_) => {
                return Box::new(future::err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid handshake",
                ))) as Box<dyn Future<Item = _, Error = _>>
            }
        };

        debug!("incoming ecies stream ...");
        let stream = ecies
            .framed(stream)
            .into_future()
            .map_err(|(e, _)| e)
            .and_then(move |(ack, transport)| {
                debug!("receiving ecies auth");
                match ack {
                    Some(ECIESValue::AuthReceive(remote_id)) => Ok((remote_id, transport)),
                    ack => {
                        error!("expected auth, got {:?} instead", ack);
                        Err(io::Error::new(io::ErrorKind::Other, "invalid handshake"))
                    }
                }
            })
            .and_then(|(remote_id, socket)| {
                debug!("sending ecies ack ...");
                socket
                    .send(ECIESValue::Ack)
                    .and_then(move |socket| Ok((remote_id, socket)))
            })
            .and_then(|(remote_id, socket)| {
                Ok(Self {
                    stream: socket,
                    polled_header: false,
                    sending_body: None,
                    remote_id,
                })
            });

        Box::new(stream)
    }

    /// Get the remote id
    pub const fn remote_id(&self) -> H512 {
        self.remote_id
    }
}

impl Stream for ECIESStream {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.polled_header {
            match try_ready!(self.stream.poll()) {
                Some(ECIESValue::Header(_)) => (),
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "ECIES stream protocol error",
                    ))
                }
                None => return Ok(Async::Ready(None)),
            };
            self.polled_header = true;
        }
        let body = match try_ready!(self.stream.poll()) {
            Some(ECIESValue::Body(val)) => val,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "ECIES stream protocol error",
                ))
            }
            None => return Ok(Async::Ready(None)),
        };
        self.polled_header = false;
        Ok(Async::Ready(Some(body)))
    }
}

impl Sink for ECIESStream {
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Vec<u8>) -> StartSend<Self::SinkItem, Self::SinkError> {
        if self.sending_body.is_some() {
            let sending_body = self.sending_body.take().unwrap();
            match self.stream.start_send(ECIESValue::Body(sending_body))? {
                AsyncSink::Ready => (), // Cache cleared, able to deal with the current item.
                AsyncSink::NotReady(ECIESValue::Body(sending_body)) => {
                    self.sending_body = Some(sending_body);
                    return Ok(AsyncSink::NotReady(item));
                }
                _ => panic!(),
            }
        }

        match self.stream.start_send(ECIESValue::Header(item.len()))? {
            AsyncSink::Ready => (),
            AsyncSink::NotReady(_) => return Ok(AsyncSink::NotReady(item)),
        }

        match self.stream.start_send(ECIESValue::Body(item))? {
            AsyncSink::Ready => (),
            AsyncSink::NotReady(ECIESValue::Body(item)) => {
                self.sending_body = Some(item);
            }
            _ => panic!(),
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        if self.sending_body.is_some() {
            let sending_body = self.sending_body.take().unwrap();
            match self.stream.start_send(ECIESValue::Body(sending_body))? {
                AsyncSink::Ready => (),
                AsyncSink::NotReady(ECIESValue::Body(sending_body)) => {
                    self.sending_body = Some(sending_body);
                    return Ok(Async::NotReady);
                }
                _ => panic!(),
            }
        }

        self.stream.poll_complete()
    }
}
