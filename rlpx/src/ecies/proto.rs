use super::algorithm::ECIES;
use crate::errors::ECIESError;
use bigint::H512;
use bytes::BytesMut;
use futures::{ready, Sink, SinkExt};
use log::*;
use pin_project_lite::pin_project;
use secp256k1::key::SecretKey;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{net::TcpStream, stream::*};
use tokio_util::codec::*;

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

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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

    fn encode(&mut self, item: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            ECIESValue::AuthReceive(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AuthReceive is not expected",
            )),
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

pin_project! {
    /// `ECIES` stream over TCP exchanging raw bytes
    pub struct ECIESStream {
        #[pin]
        stream: Framed<TcpStream, ECIESCodec>,
        polled_header: bool,
        remote_id: H512,
    }
}

impl ECIESStream {
    /// Connect to an `ECIES` server
    pub async fn connect(
        addr: SocketAddr,
        secret_key: SecretKey,
        remote_id: H512,
    ) -> Result<Self, io::Error> {
        let ecies = ECIESCodec::new_client(secret_key, remote_id)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid handshake"))?;

        debug!("connecting to ecies stream ...");
        let socket = TcpStream::connect(addr).await?;
        debug!("sending ecies auth ...");

        let mut transport = ecies.framed(socket);
        transport.send(ECIESValue::Auth).await?;

        let ack = transport.try_next().await?;

        debug!("receiving ecies ack ...");
        if ack == Some(ECIESValue::Ack) {
            Ok(Self {
                stream: transport,
                polled_header: false,
                remote_id,
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid handshake: expected ack, got {:?} instead", ack),
            ))
        }
    }

    /// Listen on a just connected ECIES client
    pub async fn incoming(stream: TcpStream, secret_key: SecretKey) -> Result<Self, io::Error> {
        let ecies = ECIESCodec::new_server(secret_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid handshake"))?;

        debug!("incoming ecies stream ...");
        let mut transport = ecies.framed(stream);
        let ack = transport.try_next().await?;

        debug!("receiving ecies auth");
        let remote_id = match ack {
            Some(ECIESValue::AuthReceive(remote_id)) => remote_id,
            other => {
                error!("expected auth, got {:?} instead", other);
                return Err(io::Error::new(io::ErrorKind::Other, "invalid handshake"));
            }
        };

        debug!("sending ecies ack ...");
        transport.send(ECIESValue::Ack).await?;

        Ok(Self {
            stream: transport,
            polled_header: false,
            remote_id,
        })
    }

    /// Get the remote id
    pub const fn remote_id(&self) -> H512 {
        self.remote_id
    }
}

impl Stream for ECIESStream {
    type Item = Result<Vec<u8>, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.polled_header {
            match ready!(self.as_mut().project().stream.poll_next(cx)) {
                Some(Ok(ECIESValue::Header(_))) => (),
                Some(_) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "ECIES stream protocol error",
                    ))))
                }
                None => return Poll::Ready(None),
            };
            self.polled_header = true;
        }
        let body = match ready!(self.as_mut().project().stream.poll_next(cx)) {
            Some(Ok(ECIESValue::Body(val))) => val,
            Some(_) => {
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "ECIES stream protocol error",
                ))))
            }
            None => return Poll::Ready(None),
        };
        self.polled_header = false;
        Poll::Ready(Some(Ok(body)))
    }
}

impl Sink<Vec<u8>> for ECIESStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.as_mut()
            .project()
            .stream
            .start_send(ECIESValue::Header(item.len()))?;
        self.as_mut()
            .project()
            .stream
            .start_send(ECIESValue::Body(item))?;

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_close(cx)
    }
}
