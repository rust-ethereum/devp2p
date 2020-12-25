use crate::types::*;
use derive_more::From;
use futures::stream::BoxStream;
use std::{collections::HashMap, net::SocketAddr, task::Poll};
use tokio_stream::Stream;

#[cfg(feature = "discv4")]
mod discv4;

#[cfg(feature = "discv4")]
pub use self::discv4::{Discv4, Discv4Builder};

#[cfg(feature = "discv5")]
mod discv5;

#[cfg(feature = "discv5")]
pub use self::discv5::Discv5;

#[cfg(feature = "dnsdisc")]
mod dnsdisc;

#[cfg(feature = "dnsdisc")]
pub use self::dnsdisc::DnsDiscovery;

pub type Discovery = BoxStream<'static, anyhow::Result<NodeRecord>>;

#[derive(Clone, Debug, From)]
pub struct Bootnodes(pub HashMap<SocketAddr, PeerId>);

impl Stream for Bootnodes {
    type Item = anyhow::Result<NodeRecord>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some((&addr, &id)) = self.0.iter().next() {
            Poll::Ready(Some(Ok(NodeRecord { id, addr })))
        } else {
            Poll::Ready(None)
        }
    }
}
