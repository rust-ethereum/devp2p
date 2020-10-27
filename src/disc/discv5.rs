use std::sync::Arc;

use super::Discovery;
use crate::{types::*, util::*};
use anyhow::anyhow;
use async_trait::async_trait;
use futures::stream::BoxStream;
use futures_intrusive::channel::UnbufferedChannel;
use task_group::TaskGroup;
use tokio::{select, stream::StreamExt, sync::mpsc::channel};
use tracing::*;

pub struct Discv5 {
    #[allow(unused)]
    tasks: TaskGroup,
    errors: Arc<UnbufferedChannel<anyhow::Error>>,
    receiver: BoxStream<'static, NodeRecord>,
}

impl Discv5 {
    pub fn new(mut disc: discv5::Discv5, cache: usize) -> Self {
        let tasks = TaskGroup::default();

        let errors = Arc::new(UnbufferedChannel::new());
        let (mut tx, receiver) = channel(cache);

        tasks.spawn_with_name("discv5 pump", {
            let errors = errors.clone();
            async move {
                async {
                    loop {
                        match disc.find_node(enr::NodeId::random()).await {
                            Err(e) => {
                                if errors
                                    .send(anyhow!("Discovery error: {}", e))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            Ok(nodes) => {
                                for node in nodes {
                                    if let Some(ip) = node.ip() {
                                        if let Some(port) = node.tcp() {
                                            if let enr::CombinedPublicKey::Secp256k1(pk) =
                                                node.public_key()
                                            {
                                                if tx
                                                    .send(NodeRecord {
                                                        addr: (ip, port).into(),
                                                        id: pk2id(&pk),
                                                    })
                                                    .await
                                                    .is_err()
                                                {
                                                    return;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                .await;

                debug!("Discovery receivers dropped, shutting down");
            }
        });

        Self {
            tasks,
            errors,
            receiver: Box::pin(receiver.fuse()),
        }
    }
}

#[async_trait]
impl Discovery for Discv5 {
    async fn get_new_peer(&mut self) -> anyhow::Result<NodeRecord> {
        let err_fut = self.errors.receive();
        let node_fut = self.receiver.next();

        select! {
            error = err_fut => {
                Err(error.ok_or_else(|| anyhow!("Discovery task is dead."))?)
            }
            node = node_fut => {
                Ok(node
                    .ok_or_else(|| anyhow!("Discovery task is dead."))?)
            }
        }
    }
}
