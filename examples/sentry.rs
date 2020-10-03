#![allow(dead_code)]

use arrayvec::ArrayString;
use devp2p::*;
use ethereum_types::*;
use hex_literal::hex;
use k256::ecdsa::SigningKey;
use maplit::*;
use rand::rngs::OsRng;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    convert::{identity, TryInto},
    sync::Arc,
};
use tracing::*;
use tracing_subscriber::EnvFilter;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

const CLIENT_VERSION: &str = "rust-devp2p/0.1.0";
const DNS_BOOTNODE: &str = "all.mainnet.ethdisco.net";

#[derive(Debug, RlpEncodable, RlpDecodable)]
struct StatusMessage {
    protocol_version: usize,
    network_id: usize,
    total_difficulty: U256,
    best_hash: H256,
    genesis_hash: H256,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let secret_key = SigningKey::random(&mut OsRng);

    let dns_resolver = dnsdisc::Resolver::new(Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .await
            .unwrap(),
    ));

    let discovery = DnsDiscovery::new(Arc::new(dns_resolver), DNS_BOOTNODE.to_string(), None);

    let client = RLPxNode::new(
        secret_key,
        CLIENT_VERSION.to_string(),
        Some(ListenOptions {
            discovery: Some(DiscoveryOptions {
                discovery: Arc::new(tokio::sync::Mutex::new(discovery)),
                tasks: 50_usize.try_into().unwrap(),
            }),
            max_peers: 50,
            addr: "0.0.0.0:30303".parse().unwrap(),
        }),
    )
    .await
    .unwrap();

    let status_message = StatusMessage {
        protocol_version: 63,
        network_id: 1,
        total_difficulty: 17608636743620256866935_u128.into(),
        best_hash: H256::from(hex!(
            "28042e7e4d35a3482bf5f0d862501868b04c1734f483ceae3bf1393561951829"
        )),
        genesis_hash: H256::from(hex!(
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        )),
    };

    let _handle = client.register_protocol_server(
        btreemap! { CapabilityId {
            name: CapabilityName(ArrayString::from("eth").unwrap()),
            version: 63
        } => 17 },
        Arc::new(|peer, id, data| {
            Box::pin(async move {
                if id == 0 {
                    match rlp::decode::<StatusMessage>(&data) {
                        Ok(v) => {
                            info!("Received status message from peer {}: {:?}", peer.id, v);
                        }
                        Err(e) => {
                            info!(
                                "Failed to decode peer {}'s status message: {}! Kicking peer.",
                                peer.id, e
                            );
                            return Ok((None, Some(ReputationReport::Kick)));
                        }
                    }
                }

                let out_id = match id {
                    3 => Some(4),
                    5 => Some(6),
                    _ => None,
                };

                Ok((
                    out_id.map(|id| (id, rlp::encode_list::<String, String>(&[]).into())),
                    None,
                ))
            })
        }),
        Arc::new(move || {
            Some(Message {
                id: 0,
                data: rlp::encode(&status_message).into(),
            })
        }),
    );

    loop {
        tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
        info!(
            "Current peers: {}",
            client.connected_peers(identity, None, None).len()
        );
    }
}
