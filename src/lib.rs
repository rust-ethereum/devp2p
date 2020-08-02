//! Ethereum devp2p protocol implementation

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

pub mod ecies;
mod errors;
mod eth;
mod mac;
mod peer;
mod rlpx;
mod types;
mod util;

pub use eth::Server as EthServer;
pub use peer::PeerStream;
pub use rlpx::Server as RLPxNode;
pub use types::{CapabilityInfo, CapabilityName};
