//! Ethereum devp2p protocol implementation

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
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

mod eth;
mod raw;
pub mod rlpx;

pub use eth::Server as ETHServer;
pub use raw::Server as DevP2PServer;
