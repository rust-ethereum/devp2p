use crate::types::*;
use discv4::Node;
use std::{pin::Pin, sync::Arc};
use task_group::TaskGroup;
use tokio::{
    stream::Stream,
    sync::mpsc::{channel, Receiver},
};

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

impl Stream for Discv4 {
    type Item = anyhow::Result<NodeRecord>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver)
            .poll_next(cx)
            .map(|opt| opt.map(Ok))
    }
}
