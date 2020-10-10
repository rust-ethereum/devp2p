use super::Discovery;
use crate::{types::*, util::*};
use anyhow::anyhow;
use async_trait::async_trait;
use discv5::Discv5;
use std::net::SocketAddr;

#[async_trait]
impl Discovery for Discv5 {
    async fn get_new_peer(&mut self) -> anyhow::Result<(SocketAddr, PeerId)> {
        loop {
            for node in self
                .find_node(enr::NodeId::random())
                .await
                .map_err(|e| anyhow!("Discovery error: {}", e))?
            {
                if let Some(ip) = node.ip() {
                    if let Some(port) = node.tcp() {
                        if let enr::CombinedPublicKey::Secp256k1(pk) = node.public_key() {
                            return Ok(((ip, port).into(), pk2id(&pk)));
                        }
                    }
                }
            }
        }
    }
}
