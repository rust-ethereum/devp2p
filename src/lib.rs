//! Ethereum devp2p protocol implementation
//!
//! It is layered in the following way:
//! * `RLPxNode` which represents the whole pool of connected peers. It handles message routing and peer management.
//! * `MuxServer` which provides a request-response API to otherwise stateless P2P protocol.
//! * `EthIngressServer` which `MuxServer` calls into when new requests and gossip messages arrive.
//! * `MuxServer` itself implements `EthProtocol` which is a simple gateway to abstract Ethereum network.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    unreachable_code,
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::filter_map,
    clippy::if_not_else,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::used_underscore_binding,
    clippy::wildcard_imports
)]

mod disc;
pub mod ecies;
mod errors;
mod eth;
mod mac;
mod mux;
mod node_filter;
mod peer;
mod rlpx;
mod types;
mod util;

pub use disc::*;
pub use eth::{proto as eth_proto, Server as EthServer};
pub use mux::MuxServer;
pub use peer::PeerStream;
pub use rlpx::{ListenOptions, Server as RLPxNode};
pub use types::{
    CapabilityId, CapabilityInfo, CapabilityName, Message, NodeRecord, ProtocolRegistrar,
};
