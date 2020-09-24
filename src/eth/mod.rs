pub mod proto;

use self::proto::*;
use crate::{mux::*, types::*};
use arrayvec::ArrayString;
use async_trait::async_trait;
use bytes::Bytes;
use ethereum::{Block, Transaction};
use ethereum_forkid::ForkId;
use ethereum_types::*;
use maplit::btreemap;
use once_cell::sync::Lazy;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Debug,
};
use tracing::*;

pub type H256FastSet = HashSet<H256, plain_hasher::PlainHasher>;

static ETH_PROTOCOL_ID: Lazy<CapabilityName> =
    Lazy::new(|| CapabilityName(ArrayString::from("eth").unwrap()));
const ETH_PROTOCOL_VERSION: usize = 66;

#[allow(dead_code)]
pub enum Error {
    NoPeers,
    PeerGone,
    Shutdown,
}

impl From<Shutdown> for Error {
    fn from(_: Shutdown) -> Self {
        Self::Shutdown
    }
}

pub struct P2PResponse<Data> {
    pub report: Option<ReputationReport>,
    pub data: Option<Data>,
}

#[async_trait]
pub trait EthIngressHandler: Send + Sync + 'static {
    async fn handle_status(&self, status: Status) -> Option<ReputationReport>;
    async fn handle_new_block_hashes(&self, hashes: Vec<(H256, U256)>) -> Option<ReputationReport>;
    async fn handle_new_pooled_transaction_hashes(
        &self,
        hashes: H256FastSet,
    ) -> Option<ReputationReport>;
    async fn handle_new_block(
        &self,
        block: Block,
        total_difficulty: U256,
    ) -> Option<ReputationReport>;
    async fn handle_get_pooled_transactions(
        &self,
        hashes: H256FastSet,
    ) -> P2PResponse<Vec<Transaction>>;
}

#[async_trait]
pub trait EthProtocol: Send + Sync + 'static {
    async fn new_block_hashes(&self, hashes: Vec<(H256, U256)>) -> Result<(), Error>;
    async fn get_pooled_transactions(
        &self,
        hashes: HashSet<H256>,
    ) -> Result<Vec<Transaction>, Error>;
}

#[derive(Clone, Debug)]
pub struct StatusMeta {
    pub network_id: usize,
    pub total_difficulty: U256,
    pub best_hash: H256,
    pub genesis_hash: H256,
    pub fork_id: ForkId,
}

pub struct Server {
    pub status_fetcher: Box<dyn Fn() -> StatusMeta + Send + Sync>,
    pub ingress_handler: Box<dyn EthIngressHandler>,
}

#[async_trait]
impl MuxProtocol for Server {
    type RequestKind = proto::RequestMessageId;
    type ResponseKind = proto::ResponseMessageId;
    type GossipKind = proto::GossipMessageId;

    fn capabilities(&self) -> BTreeMap<CapabilityId, usize> {
        btreemap! { CapabilityId { name: *ETH_PROTOCOL_ID, version: ETH_PROTOCOL_VERSION } => 17 }
    }
    fn parse_message_id(
        &self,
        id: usize,
    ) -> Option<MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>> {
        Some(match id {
            0x00 => MessageKind::Gossip(Self::GossipKind::Status),
            0x01 => MessageKind::Gossip(Self::GossipKind::NewBlockHashes),
            0x02 => MessageKind::Gossip(Self::GossipKind::Transactions),
            0x03 => MessageKind::Request(Self::RequestKind::GetBlockHeaders),
            0x04 => MessageKind::Response(Self::ResponseKind::BlockHeaders),
            0x05 => MessageKind::Request(Self::RequestKind::GetBlockBodies),
            0x06 => MessageKind::Response(Self::ResponseKind::BlockBodies),
            0x07 => MessageKind::Gossip(Self::GossipKind::NewBlock),
            0x08 => MessageKind::Gossip(Self::GossipKind::NewPooledTransactionHashes),
            0x09 => MessageKind::Request(Self::RequestKind::GetPooledTransactions),
            0x0a => MessageKind::Response(Self::ResponseKind::PooledTransactions),
            0x0d => MessageKind::Request(Self::RequestKind::GetNodeData),
            0x0e => MessageKind::Response(Self::ResponseKind::NodeData),
            0x0f => MessageKind::Request(Self::RequestKind::GetReceipts),
            0x10 => MessageKind::Response(Self::ResponseKind::Receipts),
            _ => return None,
        })
    }
    fn to_message_id(
        &self,
        kind: MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>,
    ) -> usize {
        match kind {
            MessageKind::Gossip(Self::GossipKind::Status) => 0x00,
            MessageKind::Gossip(Self::GossipKind::NewBlockHashes) => 0x01,
            MessageKind::Gossip(Self::GossipKind::Transactions) => 0x02,
            MessageKind::Request(Self::RequestKind::GetBlockHeaders) => 0x03,
            MessageKind::Response(Self::ResponseKind::BlockHeaders) => 0x04,
            MessageKind::Request(Self::RequestKind::GetBlockBodies) => 0x05,
            MessageKind::Response(Self::ResponseKind::BlockBodies) => 0x06,
            MessageKind::Gossip(Self::GossipKind::NewBlock) => 0x07,
            MessageKind::Gossip(Self::GossipKind::NewPooledTransactionHashes) => 0x08,
            MessageKind::Request(Self::RequestKind::GetPooledTransactions) => 0x09,
            MessageKind::Response(Self::ResponseKind::PooledTransactions) => 0x0a,
            MessageKind::Request(Self::RequestKind::GetNodeData) => 0x0d,
            MessageKind::Response(Self::ResponseKind::NodeData) => 0x0e,
            MessageKind::Request(Self::RequestKind::GetReceipts) => 0x0f,
            MessageKind::Response(Self::ResponseKind::Receipts) => 0x10,
        }
    }
    fn on_peer_connect(&self) -> Option<Message> {
        let status = (self.status_fetcher)();
        Some(Message {
            id: self.to_message_id(MessageKind::Gossip(Self::GossipKind::Status)),
            data: rlp::encode(&Status {
                protocol_version: ETH_PROTOCOL_VERSION,
                network_id: status.network_id,
                total_difficulty: status.total_difficulty,
                genesis_hash: status.genesis_hash,
                best_hash: status.best_hash,
                fork_id: status.fork_id,
            })
            .into(),
        })
    }
    async fn handle_request(
        &self,
        id: Self::RequestKind,
        peer: IngressPeer,
        payload: Bytes,
    ) -> (Option<Vec<EncodableObject>>, Option<ReputationReport>) {
        trace!(
            "Received request {:?} from peer {} with payload {:02x?}",
            id,
            peer.id,
            payload
        );

        // TODO
        (None, None)
    }
    async fn handle_gossip(
        &self,
        id: Self::GossipKind,
        peer: IngressPeer,
        payload: Bytes,
    ) -> Option<ReputationReport> {
        trace!(
            "Received gossip message {:?} from peer {} with payload {:02x?}",
            id,
            peer.id,
            payload
        );

        match id {
            GossipMessageId::Status => match rlp::decode(&*payload) {
                Ok(status) => self.ingress_handler.handle_status(status).await,
                Err(e) => {
                    warn!("Failed to decode status message: {:?}", e);
                    Some(ReputationReport::Kick)
                }
            },
            _ => todo!(),
        }
    }
}
