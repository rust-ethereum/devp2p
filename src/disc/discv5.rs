use super::Discovery;
use crate::{types::*, util::*};
use async_trait::async_trait;
use discv5_crate::Discv5;
use std::net::SocketAddr;

#[async_trait]
impl Discovery for Discv5 {
    async fn get_new_peer(&mut self) -> StdResult<(SocketAddr, PeerId)> {
        loop {
            for node in self
                .find_node(enr01::NodeId::random())
                .await
                .map_err(|e| format!("Discovery error: {}", e))?
            {
                if let Some(ip) = node.ip() {
                    if let Some(port) = node.tcp() {
                        if let enr01::CombinedPublicKey::Secp256k1(pk) = node.public_key() {
                            return Ok((
                                (ip, port).into(),
                                pk2id(&k256::ecdsa::VerifyKey::new(&pk.serialize()).unwrap()),
                            ));
                        }
                    }
                }
            }
        }
    }
}
