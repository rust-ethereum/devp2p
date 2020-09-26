use super::algorithm::ECIES;
use crate::errors::ECIESError;
use bytes::{Bytes, BytesMut};
use ethereum_types::H512;
use futures::{ready, Sink, SinkExt};
use k256::ecdsa::SigningKey;
use std::{
    fmt::Debug,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    stream::*,
};
use tokio_util::codec::*;
use tracing::*;

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
#[derive(Debug)]
pub struct ECIESCodec {
    ecies: ECIES,
    state: ECIESState,
}

impl ECIESCodec {
    /// Create a new server codec using the given secret key
    pub fn new_server(secret_key: Arc<SigningKey>) -> Result<Self, ECIESError> {
        Ok(Self {
            ecies: ECIES::new_server(secret_key)?,
            state: ECIESState::Auth,
        })
    }

    /// Create a new client codec using the given secret key and the server's public id
    pub fn new_client(secret_key: Arc<SigningKey>, remote_id: H512) -> Result<Self, ECIESError> {
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
                trace!("parsing auth");
                if buf.len() < ECIES::auth_len() {
                    return Ok(None);
                }

                let data = buf.split_to(ECIES::auth_len());
                self.ecies.parse_auth(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::AuthReceive(self.ecies.remote_id())))
            }
            ECIESState::Ack => {
                trace!("parsing ack with len {}", buf.len());
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

impl Encoder<ECIESValue> for ECIESCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ECIESValue, buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            ECIESValue::AuthReceive(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AuthReceive is not expected",
            )),
            ECIESValue::Auth => {
                let data = self.ecies.create_auth()?;
                self.state = ECIESState::Ack;
                buf.extend_from_slice(&data);
                Ok(())
            }
            ECIESValue::Ack => {
                let data = self.ecies.create_ack()?;
                self.state = ECIESState::Header;
                buf.extend_from_slice(&data);
                Ok(())
            }
            ECIESValue::Header(size) => {
                let data = self.ecies.create_header(size);
                buf.extend_from_slice(&data);
                Ok(())
            }
            ECIESValue::Body(val) => {
                let data = self.ecies.create_body(val.as_ref());
                buf.extend_from_slice(&data);
                Ok(())
            }
        }
    }
}

/// `ECIES` stream over TCP exchanging raw bytes
#[derive(Debug)]
pub struct ECIESStream<Io> {
    stream: Framed<Io, ECIESCodec>,
    polled_header: bool,
    remote_id: H512,
}

impl<Io> ECIESStream<Io>
where
    Io: AsyncRead + AsyncWrite + Debug + Send + Unpin,
{
    /// Connect to an `ECIES` server
    pub async fn connect(
        transport: Io,
        secret_key: Arc<SigningKey>,
        remote_id: H512,
    ) -> Result<Self, io::Error> {
        let ecies = ECIESCodec::new_client(secret_key, remote_id)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid handshake"))?;

        let mut transport = ecies.framed(transport);

        debug!("sending ecies auth ...");
        transport.send(ECIESValue::Auth).await?;

        debug!("waiting for ecies ack ...");
        let ack = transport.try_next().await?;

        debug!("parsing ecies ack ...");
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
    pub async fn incoming(transport: Io, secret_key: Arc<SigningKey>) -> Result<Self, io::Error> {
        let ecies = ECIESCodec::new_server(secret_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid handshake"))?;

        debug!("incoming ecies stream ...");
        let mut transport = ecies.framed(transport);
        let ack = transport.try_next().await?;

        debug!("receiving ecies auth");
        let remote_id = match ack {
            Some(ECIESValue::AuthReceive(remote_id)) => remote_id,
            other => {
                debug!("expected auth, got {:?} instead", other);
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
    pub fn remote_id(&self) -> H512 {
        self.remote_id
    }
}

impl<Io> Stream for ECIESStream<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if !this.polled_header {
            match ready!(Pin::new(&mut this.stream).poll_next(cx)) {
                Some(Ok(ECIESValue::Header(_))) => (),
                Some(_) => {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "ECIES stream protocol error",
                    ))))
                }
                None => return Poll::Ready(None),
            };
            this.polled_header = true;
        }
        let body = match ready!(Pin::new(&mut this.stream).poll_next(cx)) {
            Some(Ok(ECIESValue::Body(val))) => val,
            Some(_) => {
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "ECIES stream protocol error",
                ))))
            }
            None => return Poll::Ready(None),
        };
        this.polled_header = false;
        Poll::Ready(Some(Ok(body.into())))
    }
}

impl<Io> Sink<Vec<u8>> for ECIESStream<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).start_send(ECIESValue::Header(item.len()))?;
        Pin::new(&mut this.stream).start_send(ECIESValue::Body(item))?;

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
