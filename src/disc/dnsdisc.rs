use crate::{types::*, util::*};
use dnsdisc::{Backend, Resolver};
use secp256k1::{PublicKey, SecretKey};
use std::{pin::Pin, sync::Arc, time::Duration};
use task_group::TaskGroup;
use tokio::sync::mpsc::{channel, Receiver};
use tokio_stream::{Stream, StreamExt};
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
        discovery: Arc<Resolver<B, SecretKey>>,
        domain: String,
        public_key: Option<PublicKey>,
    ) -> Self {
        let tasks = TaskGroup::default();

        let (tx, receiver) = channel(1);
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

impl Stream for DnsDiscovery {
    type Item = anyhow::Result<NodeRecord>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_recv(cx)
    }
}
