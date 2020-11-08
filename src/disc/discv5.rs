use std::{pin::Pin, sync::Arc};

use crate::{types::*, util::*};
use anyhow::anyhow;
use futures::stream::BoxStream;
use futures_intrusive::channel::UnbufferedChannel;
use secp256k1::PublicKey;
use task_group::TaskGroup;
use tokio::{
    select,
    stream::{Stream, StreamExt},
    sync::mpsc::channel,
};
use tracing::*;

pub struct Discv5 {
    #[allow(unused)]
    tasks: TaskGroup,
    receiver: BoxStream<'static, anyhow::Result<NodeRecord>>,
}

impl Discv5 {
    pub fn new(mut disc: discv5::Discv5, cache: usize) -> Self {
        let tasks = TaskGroup::default();

        let errors = Arc::new(UnbufferedChannel::new());
        let (tx, mut nodes) = channel(cache);

        tasks.spawn_with_name("discv5 pump", {
            let errors = errors.clone();
            async move {
                async {
                    loop {
                        match disc.find_node(discv5::enr::NodeId::random()).await {
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
                                            if let discv5::enr::CombinedPublicKey::Secp256k1(pk) =
                                                node.public_key()
                                            {
                                                if tx
                                                    .send(NodeRecord {
                                                        addr: (ip, port).into(),
                                                        id: pk2id(
                                                            &PublicKey::from_slice(&pk.to_bytes())
                                                                .unwrap(),
                                                        ),
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

        let (tx, receiver) = channel(1);
        tasks.spawn_with_name("discv4 pump 2", async move {
            loop {
                let err_fut = errors.receive();
                let node_fut = nodes.next();

                select! {
                    Some(error) = err_fut => {
                        if tx.send(Err(error)).await.is_err() {
                            return;
                        }
                    }
                    Some(node) = node_fut => {
                        if tx.send(Ok(node)).await.is_err() {
                            return;
                        }
                    }
                    else => {
                        return;
                    }
                }
            }
        });

        Self {
            tasks,
            receiver: Box::pin(receiver),
        }
    }
}

impl Stream for Discv5 {
    type Item = anyhow::Result<NodeRecord>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}
