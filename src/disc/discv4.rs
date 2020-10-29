use super::Discovery;
use crate::types::*;
use anyhow::anyhow;
use async_trait::async_trait;
use discv4::Node;
use std::sync::Arc;
use task_group::TaskGroup;
use tokio::sync::mpsc::{channel, Receiver};

pub struct Discv4 {
    #[allow(unused)]
    tasks: TaskGroup,
    receiver: Receiver<NodeRecord>,
}

impl Discv4 {
    #[must_use]
    pub fn new(node: Arc<Node>, cache: usize) -> Self {
        let tasks = TaskGroup::default();

        let (tx, receiver) = channel(cache);

        tasks.spawn_with_name("discv4 pump", async move {
            loop {
                for record in node.lookup(rand::random()).await {
                    let _ = tx
                        .send(NodeRecord {
                            addr: record.tcp_addr(),
                            id: record.id,
                        })
                        .await;
                }
            }
        });

        Self { tasks, receiver }
    }
}

#[async_trait]
impl Discovery for Discv4 {
    async fn get_new_peer(&mut self) -> anyhow::Result<NodeRecord> {
        Ok(self
            .receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Discovery task is dead."))?)
    }
}
