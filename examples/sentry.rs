#![allow(dead_code)]

use arrayvec::ArrayString;
use async_trait::async_trait;
use devp2p::*;
use ethereum_types::*;
use futures::stream::BoxStream;
use hex_literal::hex;
use k256::ecdsa::SigningKey;
use maplit::btreemap;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use task_group::TaskGroup;
use tokio::{
    stream::StreamExt,
    sync::{
        mpsc::{channel, Sender},
        Mutex as AsyncMutex,
    },
};
use tracing::*;
use tracing_subscriber::EnvFilter;
use trust_dns_resolver::{config::*, TokioAsyncResolver};
use uuid::Uuid;

const DNS_BOOTNODE: &str = "all.mainnet.ethdisco.net";

fn eth() -> CapabilityName {
    CapabilityName(ArrayString::from("eth").unwrap())
}

#[derive(Debug, Default)]
struct TaskMetrics {
    count: AtomicUsize,
}

impl task_group::Metrics for TaskMetrics {
    fn task_started(&self, id: Uuid, name: String) {
        let c = self.count.fetch_add(1, Ordering::Relaxed);
        trace!("Current tasks: {}. Started task {}/{}", c + 1, name, id)
    }

    fn task_stopped(&self, id: Uuid, name: String) {
        let c = self.count.fetch_sub(1, Ordering::Relaxed);
        trace!("Current tasks: {}. Stopped task {}/{}", c - 1, name, id)
    }
}

#[derive(Debug, RlpEncodable, RlpDecodable)]
struct StatusMessage {
    protocol_version: usize,
    network_id: usize,
    total_difficulty: U256,
    best_hash: H256,
    genesis_hash: H256,
}

#[derive(Clone)]
struct Pipes {
    sender: Sender<OutboundEvent>,
    receiver: Arc<AsyncMutex<BoxStream<'static, OutboundEvent>>>,
}

#[derive(Default)]
struct CapabilityServerImpl {
    peer_pipes: Arc<RwLock<HashMap<PeerId, Pipes>>>,
}

impl CapabilityServerImpl {
    fn setup_pipes(&self, peer: PeerId, pipes: Pipes) {
        assert!(self.peer_pipes.write().insert(peer, pipes).is_none());
    }
    fn get_pipes(&self, peer: PeerId) -> Pipes {
        self.peer_pipes.read().get(&peer).unwrap().clone()
    }
    fn teardown(&self, peer: PeerId) {
        self.peer_pipes.write().remove(&peer);
    }
    fn connected_peers(&self) -> usize {
        self.peer_pipes.read().len()
    }
}

#[async_trait]
impl CapabilityServer for CapabilityServerImpl {
    #[instrument(skip(self))]
    fn on_peer_connect(&self, peer: PeerId, _: BTreeSet<CapabilityId>) {
        info!("Settting up peer state");
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

        let first_message = OutboundEvent::Message {
            capability_name: eth(),
            message: Message {
                id: 0,
                data: rlp::encode(&status_message).into(),
            },
        };

        let (sender, receiver) = channel(1);
        let receiver =
            Box::pin(tokio::stream::iter(std::iter::once(first_message)).chain(receiver));
        self.setup_pipes(
            peer,
            Pipes {
                sender,
                receiver: Arc::new(AsyncMutex::new(receiver)),
            },
        );
    }
    #[instrument(skip(self))]
    async fn on_peer_event(&self, peer: PeerId, event: InboundEvent) {
        match event {
            InboundEvent::Disconnect { .. } => {
                self.teardown(peer);
            }
            InboundEvent::Message { message, .. } => {
                info!(
                    "Received message with id {}, data {}",
                    message.id,
                    hex::encode(&message.data)
                );

                if message.id == 0 {
                    match rlp::decode::<StatusMessage>(&message.data) {
                        Ok(v) => {
                            info!("Decoded status message: {:?}", v);
                        }
                        Err(e) => {
                            info!("Failed to decode status message: {}! Kicking peer.", e);
                            let _ = self
                                .get_pipes(peer)
                                .sender
                                .send(OutboundEvent::Disconnect {
                                    reason: DisconnectReason::ProtocolBreach,
                                })
                                .await;

                            return;
                        }
                    }
                }

                let out_id = match message.id {
                    3 => Some(4),
                    5 => Some(6),
                    _ => None,
                };

                if let Some(id) = out_id {
                    let _ = self
                        .get_pipes(peer)
                        .sender
                        .send(OutboundEvent::Message {
                            capability_name: eth(),
                            message: Message {
                                id,
                                data: rlp::encode_list::<String, String>(&[]).into(),
                            },
                        })
                        .await;
                }
            }
        }
    }
    #[instrument(skip(self))]
    async fn next(&self, peer_id: PeerId) -> OutboundEvent {
        let outbound = self
            .get_pipes(peer_id)
            .receiver
            .lock()
            .await
            .next()
            .await
            .unwrap_or(OutboundEvent::Disconnect {
                reason: DisconnectReason::DisconnectRequested,
            });

        info!("Sending outbound event {:?}", outbound);

        outbound
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let secret_key = SigningKey::random(&mut OsRng);

    let task_metrics = Arc::new(TaskMetrics::default());
    let task_group = Arc::new(TaskGroup::new_with_metrics(task_metrics.clone()));

    let mut dns_resolver = dnsdisc::Resolver::new(Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .await
            .unwrap(),
    ));
    dns_resolver.with_task_group(task_group.clone());

    let discovery = DnsDiscovery::new(Arc::new(dns_resolver), DNS_BOOTNODE.to_string(), None);

    let discovery: Arc<AsyncMutex<dyn Discovery>> = Arc::new(AsyncMutex::new(discovery));

    let capability_server = Arc::new(CapabilityServerImpl::default());

    let swarm = Swarm::builder()
        .with_task_group(task_group.clone())
        .with_listen_options(ListenOptions {
            discovery_tasks: std::iter::repeat(discovery).take(1).collect(),
            max_peers: 50,
            addr: "0.0.0.0:30303".parse().unwrap(),
        })
        .build(
            btreemap! { CapabilityId {
                name: eth(),
                version: 63,
            } => 17 },
            capability_server,
            secret_key,
        )
        .await
        .unwrap();

    loop {
        tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
        info!("Peers: {}.", swarm.connected_peers());
    }
}
