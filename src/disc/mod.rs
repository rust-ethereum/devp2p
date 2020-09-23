use crate::types::*;
use async_trait::async_trait;
use std::{io, net::SocketAddr};

#[async_trait]
pub trait Discovery: Send + Sync + 'static {
    async fn get_new_peer(&mut self) -> Result<(SocketAddr, PeerId), io::Error>;
}

#[cfg(feature = "discv5")]
pub mod discv5;
