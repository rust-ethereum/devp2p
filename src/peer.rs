use crate::{ecies::ECIESStream, types::*, util::pk2id};
use bytes::Bytes;
use enum_primitive_derive::Primitive;
use futures::{ready, Sink, SinkExt};
use libsecp256k1::{PublicKey, SecretKey};
use log::*;
use num_traits::*;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    stream::{Stream, StreamExt},
};

const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// `RLPx` protocol version.
#[derive(Copy, Clone, Debug, Primitive)]
pub enum ProtocolVersion {
    V4 = 4,
    V5 = 5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMessage {
    pub name: CapabilityName,
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
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
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
    pub id: PeerId,
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
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}

struct Snappy {
    encoder: snap::raw::Encoder,
    decoder: snap::raw::Decoder,
}

/// `RLPx` transport peer stream
#[allow(unused)]
pub struct PeerStream<Io> {
    stream: ECIESStream<Io>,
    client_version: String,
    shared_capabilities: Vec<CapabilityInfo>,
    port: u16,
    id: PeerId,
    remote_id: PeerId,

    snappy: Option<Snappy>,

    pending_pong: bool,
}

impl<Io> PeerStream<Io>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin,
{
    /// Remote public id of this peer
    pub fn remote_id(&self) -> PeerId {
        self.remote_id
    }

    /// Get all capabilities of this peer stream
    pub fn capabilities(&self) -> &[CapabilityInfo] {
        &self.shared_capabilities
    }

    /// Connect to a peer over TCP
    pub async fn connect(
        transport: Io,
        secret_key: SecretKey,
        remote_id: PeerId,
        protocol_version: ProtocolVersion,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        Ok(Self::new(
            ECIESStream::connect(transport, secret_key, remote_id).await?,
            secret_key,
            protocol_version,
            client_version,
            capabilities,
            port,
        )
        .await?)
    }

    /// Incoming peer stream over TCP
    pub async fn incoming(
        transport: Io,
        secret_key: SecretKey,
        protocol_version: ProtocolVersion,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        Ok(Self::new(
            ECIESStream::incoming(transport, secret_key).await?,
            secret_key,
            protocol_version,
            client_version,
            capabilities,
            port,
        )
        .await?)
    }

    /// Create a new peer stream
    pub async fn new(
        mut transport: ECIESStream<Io>,
        secret_key: SecretKey,
        protocol_version: ProtocolVersion,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        let public_key = PublicKey::from_secret_key(&secret_key);
        let id = pk2id(&public_key);
        let nonhello_capabilities = capabilities.clone();
        let nonhello_client_version = client_version.clone();

        debug!("connecting to rlpx peer {:x}", id);

        debug!("sending hello message ...");
        let hello = rlp::encode(&HelloMessage {
            port,
            id,
            protocol_version: protocol_version.to_usize().unwrap(),
            client_version,
            capabilities: {
                let mut caps = Vec::new();
                for cap in capabilities {
                    caps.push(CapabilityMessage {
                        name: cap.name,
                        version: cap.version,
                    });
                }
                caps
            },
        })
        .to_vec();
        let message_id: Vec<u8> = rlp::encode(&0_usize).to_vec();
        assert!(message_id.len() == 1);
        let mut ret: Vec<u8> = Vec::new();
        ret.push(message_id[0]);
        for d in &hello {
            ret.push(*d);
        }
        transport.send(ret).await?;

        let hello = transport.try_next().await?;

        debug!("receiving hello message ...");
        let hello = hello.ok_or_else(|| {
            debug!("hello failed because of no value");
            io::Error::new(io::ErrorKind::Other, "hello failed (no value)")
        })?;

        let message_id_rlp = Rlp::new(&hello[0..1]);
        let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();
        match message_id {
            Ok(message_id) => {
                if message_id != 0 {
                    error!(
                        "hello failed because message id is not 0 but {}: {:x?}",
                        message_id,
                        &hello[1..]
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "hello failed (message id)",
                    ));
                }
            }
            Err(e) => {
                debug!("hello failed because message id cannot be parsed");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("hello failed (message id parsing: {})", e),
                ));
            }
        }

        let rlp: Result<HelloMessage, rlp::DecoderError> = Rlp::new(&hello[1..]).as_val();
        match rlp {
            Ok(val) => {
                debug!("hello message: {:?}", val);
                let mut shared_capabilities: Vec<CapabilityInfo> = Vec::new();

                for cap_info in nonhello_capabilities {
                    let cap_match = val
                        .capabilities
                        .iter()
                        .any(|v| v.name == cap_info.name && v.version == cap_info.version);

                    if cap_match {
                        shared_capabilities.push(cap_info);
                    }
                }

                let shared_caps_original = shared_capabilities.clone();

                for cap_info in shared_caps_original {
                    shared_capabilities
                        .retain(|v| v.name != cap_info.name || v.version >= cap_info.version);
                }

                shared_capabilities.sort_by_key(|v| v.name);

                let snappy = match protocol_version {
                    ProtocolVersion::V4 => None,
                    ProtocolVersion::V5 => Some(Snappy {
                        encoder: snap::raw::Encoder::new(),
                        decoder: snap::raw::Decoder::new(),
                    }),
                };

                Ok(Self {
                    remote_id: transport.remote_id(),
                    stream: transport,
                    client_version: nonhello_client_version,
                    port,
                    id,
                    shared_capabilities,
                    snappy,
                    pending_pong: false,
                })
            }
            Err(e) => {
                debug!("hello failed because message rlp parsing failed");
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("hello failed (rlp error: {})", e),
                ))
            }
        }
    }
}

impl<Io> Stream for PeerStream<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<(CapabilityInfo, usize, Bytes), io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut s = self.get_mut();
        if s.pending_pong && Pin::new(&mut s.stream).poll_ready(cx)?.is_ready() {
            let mut payload: Vec<u8> = rlp::encode(&0x03_usize /* pong */).to_vec();
            payload.append(&mut rlp::EMPTY_LIST_RLP.to_vec());
            debug!("sending pong message payload {:?}", payload);

            Pin::new(&mut s.stream).start_send(payload)?;
            let _ = Pin::new(&mut s.stream).poll_flush(cx)?;
        }

        match ready!(Pin::new(&mut s.stream).poll_next(cx)) {
            Some(Ok(val)) => {
                debug!("received peer message: {:?}", val);
                let message_id_rlp = Rlp::new(&val[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();

                let (cap, id, data) = match message_id {
                    Ok(message_id) => {
                        let data = if let Some(snappy) = &mut s.snappy {
                            let input = &val[1..];
                            let payload_len = snap::raw::decompress_len(input)?;
                            if payload_len > MAX_PAYLOAD_SIZE {
                                return Poll::Ready(Some(Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "payload size ({}) exceeds limit ({} bytes)",
                                        payload_len, MAX_PAYLOAD_SIZE
                                    ),
                                ))));
                            }
                            snappy.decoder.decompress_vec(input)?.into()
                        } else {
                            Bytes::copy_from_slice(&val[1..])
                        };

                        if message_id < 0x10 {
                            let data = &val[1..];
                            match message_id {
                                0x01 /* disconnect */ => {
                                    let reason: Result<usize, rlp::DecoderError> = Rlp::new(&*data).val_at(0);
                                    debug!("received disconnect message, reason: {:?}", reason);
                                    return Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::Other,
                                                                               "explicit disconnect"))));
                                },
                                0x02 /* ping */ => {
                                    debug!("received ping message data {:?}", data);
                                    s.pending_pong = true;
                                    cx.waker().wake_by_ref();
                                    return Poll::Pending
                                },
                                0x03 /* pong */ => {
                                    debug!("received pong message");
                                },
                                _ => {
                                    debug!("received unknown reserved message");
                                    return Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::Other,
                                                                               "unhandled reserved message"))))
                                },
                            }
                            return Poll::Pending;
                        }

                        let mut message_id = message_id - 0x10;
                        let mut index = 0;
                        for cap in &s.shared_capabilities {
                            if message_id > cap.length {
                                message_id -= cap.length;
                                index += 1;
                            }
                        }
                        if index >= s.shared_capabilities.len() {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "message id parsing failed (too big)",
                            ))));
                        }
                        (s.shared_capabilities[index], message_id, data)
                    }
                    Err(e) => {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("message id parsing failed (invalid): {}", e),
                        ))));
                    }
                };

                Poll::Ready(Some(Ok((cap, id, data))))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

impl<Io> Sink<(CapabilityName, usize, Bytes)> for PeerStream<Io>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_ready(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        (cap_name, id, data): (CapabilityName, usize, Bytes),
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let cap = this
            .shared_capabilities
            .iter()
            .find(|cap| cap.name == cap_name);

        if cap.is_none() {
            debug!(
                "giving up sending cap {} of id {} to 0x{:x} because remote does not support.",
                cap_name.0,
                id,
                this.remote_id()
            );
            return Ok(());
        }

        let cap = *cap.unwrap();

        if id >= cap.length {
            debug!(
                "giving up sending cap {} of id {} to 0x{:x} because it is too big.",
                cap_name.0,
                id,
                this.remote_id()
            );
            return Ok(());
        }

        let mut message_id = 0x10;
        for scap in &this.shared_capabilities {
            if scap == &cap {
                break;
            }

            message_id += scap.length;
        }
        message_id += id;
        let first = rlp::encode(&message_id);
        assert!(first.len() == 1);

        let mut ret: Vec<u8> = Vec::new();
        ret.push(first[0]);
        if let Some(snappy) = &mut this.snappy {
            ret.append(&mut snappy.encoder.compress_vec(&*data).unwrap());
        } else {
            ret.extend_from_slice(&*data)
        }

        Pin::new(&mut this.stream).start_send(ret)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
