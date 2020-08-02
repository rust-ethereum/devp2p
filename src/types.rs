pub use crate::util::Shutdown;
use arrayvec::ArrayString;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use ethereum_types::H512;
use rlp::{DecoderError, Rlp, RlpStream};
use std::{collections::BTreeSet, future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityName(pub ArrayString<[u8; 4]>);

impl rlp::Encodable for CapabilityName {
    fn rlp_append(&self, s: &mut RlpStream) {
        self.0.as_bytes().rlp_append(s);
    }
}

impl rlp::Decodable for CapabilityName {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self(
            ArrayString::from(
                std::str::from_utf8(rlp.data()?)
                    .map_err(|_| DecoderError::Custom("should be a UTF-8 string"))?,
            )
            .map_err(|_| DecoderError::RlpIsTooBig)?,
        ))
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
/// Capability information
pub struct CapabilityInfo {
    pub name: CapabilityName,
    pub version: usize,
    pub length: usize,
}

pub trait IngressPeerToken: Send + Sync + 'static {
    fn id(&self) -> PeerId;
    fn penalize(self);
}

pub type IngressHandlerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub type IngressHandler<Peer: IngressPeerToken> = Box<dyn Fn(Peer, BytesMut) -> IngressHandlerFuture + Send + 'static>;

pub type PeerId = H512;

pub enum PeerSendError {
    Shutdown,
    PeerGone,
}

/// Peer handle that freezes the peer in the pool.
#[async_trait]
pub trait PeerHandle: Send + Sync {
    fn capability_version(&self) -> u8;
    fn peer_id(&self) -> PeerId;
    async fn send_message(self, message: Bytes) -> Result<(), PeerSendError>;
}

/// DevP2P server handle that can be used by the owning protocol server to access peer pool.
#[async_trait]
pub trait ServerHandle: Send + Sync {
    type PeerHandle: PeerHandle;
    /// Get random peer that matches the specified capability version. Returns peer ID and actual capability version.
    async fn get_peer(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
    ) -> Result<Option<Self::PeerHandle>, Shutdown>;
    /// Number of peers that support the specified capability version.
    async fn num_peers(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
    ) -> Result<usize, Shutdown>;
}

#[async_trait]
pub trait ProtocolRegistrar: Send + Sync {
    type ServerHandle: ServerHandle;
    type IngressPeerToken: IngressPeerToken;

    /// Register support for the protocol. Takes the sink as incoming handler for the protocol. Returns personal handle to the peer pool.
    fn register_incoming_handler(
        &self,
        protocol: CapabilityName,
        handler: IngressHandler<Self::IngressPeerToken>,
    ) -> Self::ServerHandle;
}
