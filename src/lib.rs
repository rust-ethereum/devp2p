//! Ethereum devp2p protocol implementation
//!
//! It is layered in the following way:
//! * `RLPxNode` which represents the whole pool of connected peers. It handles message routing and peer management.
//! * `MuxServer` which provides a request-response API to otherwise stateless P2P protocol.
//! * `EthIngressServer` which `MuxServer` calls into when new requests and gossip messages arrive.
//! * `MuxServer` itself implements `EthProtocol` which is a simple gateway to abstract Ethereum network.

#![allow(clippy::large_enum_variant)]

mod disc;
pub mod ecies;
mod errors;
mod mac;
mod mux;
mod node_filter;
mod peer;
mod rlpx;
mod types;
mod util;

pub use disc::*;
pub use mux::MuxServer;
pub use peer::PeerStream;
pub use rlpx::{
    DiscoveryOptions, ListenOptions, Server as RLPxNode, ServerBuilder as RLPxNodeBuilder,
};
pub use types::{
    CapabilityId, CapabilityInfo, CapabilityName, CapabilityRegistrar, CapabilityServer,
    HandleError, IngressPeer, Message, NodeRecord, PeerConnectOutcome, PeerId, ReputationReport,
};
