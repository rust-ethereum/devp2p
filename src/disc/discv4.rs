use crate::types::*;
use discv4::Node;
use educe::Educe;
use std::{pin::Pin, sync::Arc};
use task_group::TaskGroup;
use tokio::{
    stream::Stream,
    sync::mpsc::{channel, Receiver},
};

#[derive(Educe)]
#[educe(Default)]
pub struct Discv4Builder {
    #[educe(Default(1))]
    concurrent_lookups: usize,
    #[educe(Default(20))]
    cache: usize,
}

impl Discv4Builder {
    pub fn with_concurrent_lookups(mut self, concurrent_lookups: usize) -> Self {
        self.concurrent_lookups = concurrent_lookups;
        self
    }

    pub fn with_cache(mut self, cache: usize) -> Self {
        self.cache = cache;
        self
    }

    pub fn build(self, node: Arc<Node>) -> Discv4 {
        Discv4::new(node, self.concurrent_lookups, self.cache)
    }
}

pub struct Discv4 {
    #[allow(unused)]
    tasks: TaskGroup,
    receiver: Receiver<NodeRecord>,
}

impl Discv4 {
    #[must_use]
    fn new(node: Arc<Node>, concurrent_lookups: usize, cache: usize) -> Self {
        let tasks = TaskGroup::default();

        let (tx, receiver) = channel(cache);

        for i in 0..concurrent_lookups {
            let node = node.clone();
            let tx = tx.clone();
            tasks.spawn_with_name(format!("discv4 lookup #{}", i), {
                async move {
                    let node = node.clone();
                    let tx = tx.clone();
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
                }
            });
        }

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
