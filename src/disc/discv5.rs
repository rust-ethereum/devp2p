use super::Discovery;
use crate::{types::*, util::*};
use async_trait::async_trait;
use discv5_crate::Discv5;
use std::{io, net::SocketAddr};

#[async_trait]
impl Discovery for Discv5 {
    async fn get_new_peer(&mut self) -> Result<(SocketAddr, PeerId), io::Error> {
        loop {
            for node in self.find_node(enr::NodeId::random()).await.map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Discovery error: {}", e))
            })? {
                if let Some(ip) = node.ip() {
                    if let Some(port) = node.tcp() {
                        if let enr::CombinedPublicKey::Secp256k1(pk) = node.public_key() {
                            return Ok((
                                (ip, port).into(),
                                // TODO: remove after version harmonization
                                pk2id(&libsecp256k1::PublicKey::parse(&pk.serialize()).unwrap()),
                            ));
                        }
                    }
                }
            }
        }
    }
}
