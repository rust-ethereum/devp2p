pub use crate::util::Shutdown;
use arrayvec::ArrayString;
use async_trait::async_trait;
use bytes::Bytes;
pub use ethereum_types::H512 as PeerId;
use rlp::{DecoderError, Rlp, RlpStream};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
};

/// Record that specifies information necessary to connect to RLPx node
pub struct NodeRecord {
    /// Node ID.
    pub id: PeerId,
    /// Address of RLPx TCP server.
    pub addr: SocketAddr,
}

impl FromStr for NodeRecord {
    type Err = Box<dyn std::error::Error + Send + Sync>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const PREFIX: &str = "enode://";

        let (prefix, data) = s.split_at(PREFIX.len());
        if prefix != PREFIX {
            return Err("Not an enode".into());
        }

        let mut parts = data.split("@");
        let id = parts
            .next()
            .ok_or_else(|| "Failed to read remote ID")?
            .parse()?;
        let addr = parts
            .next()
            .ok_or_else(|| "Failed to read address")?
            .parse()?;

        Ok(Self { id, addr })
    }
}

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

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId {
    pub name: CapabilityName,
    pub version: usize,
}

impl From<CapabilityInfo> for CapabilityId {
    fn from(CapabilityInfo { name, version, .. }: CapabilityInfo) -> Self {
        Self { name, version }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ReputationReport {
    Good,
    Bad,
    Kick,
    Ban,
}

/// Represents a peers that sent us a message.
pub struct IngressPeer {
    /// Peer ID
    pub id: PeerId,
    /// Capability of this inbound message
    pub capability: CapabilityId,
}

#[derive(Debug)]
pub enum HandleError {
    Rlp(rlp::DecoderError),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<rlp::DecoderError> for HandleError {
    fn from(err: rlp::DecoderError) -> Self {
        Self::Rlp(err)
    }
}

impl HandleError {
    pub fn to_reputation_report(&self) -> Option<ReputationReport> {
        Some(match self {
            Self::Rlp(_) => ReputationReport::Bad,
            Self::Other(_) => return None,
        })
    }
}

pub type IngressHandlerFuture = Pin<
    Box<
        dyn Future<Output = Result<(Option<(usize, Bytes)>, Option<ReputationReport>), HandleError>>
            + Send
            + 'static,
    >,
>;

pub type IngressHandler =
    Arc<dyn Fn(IngressPeer, usize, Bytes) -> IngressHandlerFuture + Send + Sync + 'static>;

pub type OnPeerConnect = Arc<dyn Fn() -> Option<Message> + Send + Sync + 'static>;

pub enum PeerSendError {
    Shutdown,
    PeerGone,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub id: usize,
    pub data: Bytes,
}

/// Represents a peer that we requested ourselves from the pool.
#[async_trait]
pub trait EgressPeerHandle: Send + Sync {
    fn capability_version(&self) -> usize;
    fn peer_id(&self) -> PeerId;
    async fn send_message(self, message: Message) -> Result<(), PeerSendError>;
}

/// DevP2P server handle that can be used by the owning protocol server to access peer pool.
#[async_trait]
pub trait ServerHandle: Send + Sync + 'static {
    type EgressPeerHandle: EgressPeerHandle;
    /// Get peers that match the specified capability version. Returns peer ID and actual capability version.
    async fn get_peers(
        &self,
        name: CapabilityName,
        versions: BTreeSet<usize>,
        note: Option<(String, String)>,
    ) -> Result<Vec<Self::EgressPeerHandle>, Shutdown>;
}

#[async_trait]
pub trait ProtocolRegistrar: Send + Sync {
    type ServerHandle: ServerHandle;

    /// Register support for the protocol. Takes the sink as incoming handler for the protocol. Returns personal handle to the peer pool.
    fn register_protocol_server(
        &self,
        capabilities: BTreeMap<CapabilityId, usize>,
        incoming_handler: IngressHandler,
        on_peer_connect: OnPeerConnect,
    ) -> Self::ServerHandle;
}
