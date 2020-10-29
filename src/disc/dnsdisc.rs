use super::Discovery;
use crate::{types::*, util::*};
use anyhow::anyhow;
use async_trait::async_trait;
use dnsdisc::{Backend, Resolver};
use k256::ecdsa::VerifyKey;
use std::{sync::Arc, time::Duration};
use task_group::TaskGroup;
use tokio::{stream::StreamExt, sync::mpsc::Receiver};
use tracing::*;

const MAX_SINGLE_RESOLUTION: u64 = 10;
const MAX_RESOLUTION_DURATION: u64 = 1800;

pub struct DnsDiscovery {
    #[allow(unused)]
    tasks: TaskGroup,
    receiver: Receiver<anyhow::Result<NodeRecord>>,
}

impl DnsDiscovery {
    #[must_use]
    pub fn new<B: Backend>(
        discovery: Arc<Resolver<B>>,
        domain: String,
        public_key: Option<VerifyKey>,
    ) -> Self {
        let tasks = TaskGroup::default();

        let (tx, receiver) = tokio::sync::mpsc::channel(1);
        tasks.spawn_with_name("DNS discovery pump", async move {
            loop {
                let mut query = discovery.query(domain.clone(), public_key);
                let restart_at =
                    std::time::Instant::now() + Duration::from_secs(MAX_RESOLUTION_DURATION);

                loop {
                    match tokio::time::timeout(
                        Duration::from_secs(MAX_SINGLE_RESOLUTION),
                        query.next(),
                    )
                    .await
                    {
                        Ok(Some(Err(e))) => {
                            if tx.send(Err(e)).await.is_err() {
                                return;
                            }
                            break;
                        }
                        Ok(Some(Ok(v))) => {
                            if let Some(addr) = v.tcp_socket() {
                                if tx
                                    .send(Ok(NodeRecord {
                                        addr,
                                        id: pk2id(&v.public_key()),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(_) => {}
                    }

                    if std::time::Instant::now() > restart_at {
                        trace!("Restarting DNS resolution");
                        break;
                    }
                }
            }
        });

        Self { tasks, receiver }
    }
}

#[async_trait]
impl Discovery for DnsDiscovery {
    async fn get_new_peer(&mut self) -> anyhow::Result<NodeRecord> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Discovery task is dead."))?
    }
}
