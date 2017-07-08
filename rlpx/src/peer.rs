use futures::future;
use futures::{Future, Stream, Sink};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};
use tokio_core::reactor::Core;
use tokio_proto::{TcpClient, TcpServer};
use tokio_proto::pipeline::{ClientProto, ServerProto};
use bytes::{BytesMut, BufMut};
use ecies::ECIES;
use errors::ECIESError;
use secp256k1::key::SecretKey;
use bigint::H512;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ECIESState {
    Auth, Ack, Header, Body
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ECIESValue {
    Auth, Ack, Header(usize), Body(Vec<u8>)
}

pub struct ECIESCodec {
    ecies: ECIES,
    state: ECIESState,
}

impl Decoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<ECIESValue>, io::Error> {
        match self.state {
            ECIESState::Auth => {
                if buf.len() < self.ecies.auth_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.auth_len());
                self.ecies.parse_auth(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Auth))
            },
            ECIESState::Ack => {
                if buf.len() < self.ecies.ack_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.ack_len());
                self.ecies.parse_ack(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Ack))
            },
            ECIESState::Header => {
                if buf.len() < self.ecies.header_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.header_len());
                let size = self.ecies.parse_header(&data)?;

                self.state = ECIESState::Body;
                Ok(Some(ECIESValue::Header(size)))
            },
            ECIESState::Body => {
                if buf.len() < self.ecies.body_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.body_len());
                let ret = self.ecies.parse_body(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Body(ret)))
            },
        }
    }
}

impl Encoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn encode(&mut self, msg: ECIESValue, buf: &mut BytesMut) -> Result<(), io::Error> {
        match msg {
            ECIESValue::Auth => {
                let data = self.ecies.create_auth()?;
                self.state = ECIESState::Ack;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Ack => {
                let data = self.ecies.create_ack()?;
                self.state = ECIESState::Header;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Header(size) => {
                let data = self.ecies.create_header(size);
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Body(val) => {
                let data = self.ecies.create_body(val.as_ref());
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
        }
    }
}

pub struct ECIESClientProto {
    secret_key: SecretKey,
    remote_id: H512,
}

pub struct ECIESServerProto {
    secret_key: SecretKey,
}

impl<T: AsyncRead + AsyncWrite + 'static> ClientProto<T> for ECIESClientProto {
    type Request = ECIESValue;
    type Response = ECIESValue;
    type Transport = Framed<T, ECIESCodec>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ecies = match ECIES::new_client(self.secret_key.clone(), self.remote_id) {
            Ok(val) => val,
            Err(e) => return Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, "invalid handshake")))
                as Self::BindTransport,
        };
        let transport = io.framed(ECIESCodec { ecies, state: ECIESState::Auth });

        let handshake = transport.send(ECIESValue::Auth)
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(|(ack, transport)| {
                if ack == Some(ECIESValue::Ack) {
                    Ok(transport)
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "invalid handshake"))
                }
            });

        Box::new(handshake)
    }
}

impl<T: AsyncRead + AsyncWrite + 'static> ServerProto<T> for ECIESServerProto {
    type Request = ECIESValue;
    type Response = ECIESValue;
    type Transport = Framed<T, ECIESCodec>;
    type BindTransport = Box<Future<Item = Self::Transport, Error = io::Error>>;

    fn bind_transport(&self, io: T) -> Self::BindTransport {
        let ecies = match ECIES::new_server(self.secret_key.clone()) {
            Ok(val) => val,
            Err(e) => return Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, "invalid handshake")))
                as Self::BindTransport,
        };
        let transport = io.framed(ECIESCodec { ecies, state: ECIESState::Auth });

        let handshake = transport.into_future()
            .map_err(|(e, _)| e)
            .and_then(|(auth, transport)| {
                if auth == Some(ECIESValue::Auth) {
                    Box::new(transport.send(ECIESValue::Ack)) as Self::BindTransport
                } else {
                    Box::new(
                        future::err(io::Error::new(io::ErrorKind::Other, "invalid handshake")))
                        as Self::BindTransport
                }
            });

        Box::new(handshake)
    }
}

// pub struct Peer {
//     client_id: String,
//     capabilities: Vec<Capability>,
//     address: SocketAddr,

//     id: H512,
//     remote_id: H512,

//     socket: TcpStream,
// }
