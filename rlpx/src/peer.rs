use crate::{ecies::ECIESStream, util::pk2id};
use bigint::H512;
use futures::{ready, Sink, SinkExt};
use log::*;
use pin_project_lite::pin_project;
use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use secp256k1::{
    key::{PublicKey, SecretKey},
    SECP256K1,
};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    net::TcpStream,
    stream::{Stream, StreamExt},
};

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

pin_project! {
    /// Peer stream of a RLPx
    pub struct PeerStream {
        #[pin]
        stream: ECIESStream,
        protocol_version: usize,
        client_version: String,
        shared_capabilities: Vec<CapabilityInfo>,
        port: u16,
        id: H512,
        remote_id: H512,

        pending_pong: bool,
    }
}
impl PeerStream {
    /// Remote public id of this peer
    pub const fn remote_id(&self) -> H512 {
        self.remote_id
    }

    /// Get all capabilities of this peer stream
    pub fn capabilities(&self) -> &[CapabilityInfo] {
        &self.shared_capabilities
    }

    /// Connect to a peer over TCP
    pub async fn connect(
        addr: SocketAddr,
        secret_key: SecretKey,
        remote_id: H512,
        protocol_version: usize,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        Ok(Self::new(
            ECIESStream::connect(addr, secret_key, remote_id).await?,
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
        stream: TcpStream,
        secret_key: SecretKey,
        protocol_version: usize,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        Ok(Self::new(
            ECIESStream::incoming(stream, secret_key).await?,
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
        mut socket: ECIESStream,
        secret_key: SecretKey,
        protocol_version: usize,
        client_version: String,
        capabilities: Vec<CapabilityInfo>,
        port: u16,
    ) -> Result<Self, io::Error> {
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "SECP256K1 public key error"))?;
        let id = pk2id(&public_key);
        let nonhello_capabilities = capabilities.clone();
        let nonhello_client_version = client_version.clone();

        debug!("connecting to rlpx peer {:x}", id);

        debug!("sending hello message ...");
        let hello = rlp::encode(&HelloMessage {
            port,
            id,
            protocol_version,
            client_version,
            capabilities: {
                let mut caps = Vec::new();
                for cap in capabilities {
                    caps.push(CapabilityMessage {
                        name: cap.name.to_string(),
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
        socket.send(ret).await?;

        let hello = socket.try_next().await?;
        let transport = socket;

        debug!("receiving hello message ...");
        let hello = hello.ok_or_else(|| {
            debug!("hello failed because of no value");
            io::Error::new(io::ErrorKind::Other, "hello failed (no value)")
        })?;

        let message_id_rlp = UntrustedRlp::new(&hello[0..1]);
        let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();
        match message_id {
            Ok(message_id) => {
                if message_id != 0 {
                    error!(
                        "hello failed because message id is not 0 but {}",
                        message_id
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

        let rlp: Result<HelloMessage, rlp::DecoderError> = UntrustedRlp::new(&hello[1..]).as_val();
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
                        shared_capabilities.push(cap_info.clone());
                    }
                }

                let shared_caps_original = shared_capabilities.clone();

                for cap_info in shared_caps_original {
                    shared_capabilities
                        .retain(|v| v.name != cap_info.name || v.version >= cap_info.version);
                }

                shared_capabilities.sort_by_key(|v| v.name);

                Ok(Self {
                    remote_id: transport.remote_id(),
                    stream: transport,
                    client_version: nonhello_client_version,
                    protocol_version,
                    port,
                    id,
                    shared_capabilities,
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

impl Stream for PeerStream {
    type Item = Result<(CapabilityInfo, usize, Vec<u8>), io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.pending_pong && self.as_mut().project().stream.poll_ready(cx)?.is_ready() {
            let mut payload: Vec<u8> = rlp::encode(&0x03_usize /* pong */).to_vec();
            payload.append(&mut rlp::EMPTY_LIST_RLP.to_vec());
            debug!("sending pong message payload {:?}", payload);

            self.as_mut().project().stream.start_send(payload)?;
            let _ = self.as_mut().project().stream.poll_flush(cx)?;
        }

        match ready!(self.as_mut().project().stream.poll_next(cx)) {
            Some(Ok(val)) => {
                debug!("received peer message: {:?}", val);
                let message_id_rlp = UntrustedRlp::new(&val[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();

                let (cap, id) = match message_id {
                    Ok(message_id) => {
                        if message_id < 0x10 {
                            let data = &val[1..];
                            match message_id {
                                0x01 /* disconnect */ => {
                                    let reason: Result<usize, rlp::DecoderError> = UntrustedRlp::new(data).val_at(0);
                                    debug!("received disconnect message, reason: {:?}", reason);
                                    return Poll::Ready(Some(Err(io::Error::new(io::ErrorKind::Other,
                                                                               "explicit disconnect"))));
                                },
                                0x02 /* ping */ => {
                                    debug!("received ping message data {:?}", data);
                                    self.pending_pong = true;
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
                        for cap in &self.shared_capabilities {
                            if message_id > cap.length {
                                message_id -= cap.length;
                                index += 1;
                            }
                        }
                        if index >= self.shared_capabilities.len() {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "message id parsing failed (too big)",
                            ))));
                        }
                        (self.shared_capabilities[index], message_id)
                    }
                    Err(e) => {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("message id parsing failed (invalid): {}", e),
                        ))));
                    }
                };

                Poll::Ready(Some(Ok((cap, id, (&val[1..]).into()))))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

impl Sink<(&'static str, usize, Vec<u8>)> for PeerStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_ready(cx)
    }

    fn start_send(
        self: Pin<&mut Self>,
        (cap_name, id, data): (&'static str, usize, Vec<u8>),
    ) -> Result<(), Self::Error> {
        let cap = self
            .shared_capabilities
            .iter()
            .find(|cap| cap.name == cap_name);

        if cap.is_none() {
            debug!(
                "giving up sending cap {} of id {} to 0x{:x} because remote does not support.",
                cap_name,
                id,
                self.remote_id()
            );
            return Ok(());
        }

        let cap = *cap.unwrap();

        if id >= cap.length {
            debug!(
                "giving up sending cap {} of id {} to 0x{:x} because it is too big.",
                cap_name,
                id,
                self.remote_id()
            );
            return Ok(());
        }

        let mut message_id = 0x10;
        for scap in &self.shared_capabilities {
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
        for d in &data {
            ret.push(*d);
        }

        self.project().stream.start_send(ret)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().stream.poll_close(cx)
    }
}
