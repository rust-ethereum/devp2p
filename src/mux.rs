use crate::types::*;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use rlp::{Encodable, Rlp, RlpStream};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    future::Future,
    sync::Arc,
    time::Duration,
};
use task_group::TaskGroup;
use tokio::sync::oneshot::{channel as oneshot, Sender as OneshotSender};
use tracing::*;

pub type RequestCallback = OneshotSender<(Bytes, OneshotSender<ReputationReport>)>;

#[derive(Debug)]
struct RequestCallbackData<ResponseKind: Debug> {
    data: RequestCallback,
    expected_response_id: ResponseKind,
}

#[derive(Debug)]
struct RequestMultiplexer<RK: Debug> {
    inner: HashMap<PeerId, HashMap<u64, RequestCallbackData<RK>>>,
}

impl<RK: Debug> Default for RequestMultiplexer<RK> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<RK: Debug> RequestMultiplexer<RK> {
    fn save_callback(&mut self, peer_id: PeerId, callback: RequestCallbackData<RK>) -> u64 {
        let peer = self.inner.entry(peer_id).or_default();
        loop {
            let request_id = rand::random();

            if let Entry::Vacant(vacant) = peer.entry(request_id) {
                vacant.insert(callback);
                return request_id;
            }
        }
    }

    fn retrieve_callback(
        &mut self,
        peer_id: PeerId,
        request_id: u64,
    ) -> Option<RequestCallbackData<RK>> {
        if let Entry::Occupied(mut entry) = self.inner.entry(peer_id) {
            if let Some(callback) = entry.get_mut().remove(&request_id) {
                if entry.get().is_empty() {
                    entry.remove();
                }
                return Some(callback);
            }
        }

        None
    }
}

pub enum MessageKind<Request, Response, Gossip> {
    Request(Request),
    Response(Response),
    Gossip(Gossip),
}

#[async_trait]
pub trait MuxProtocol: Send + Sync + 'static {
    type RequestKind: Clone + Send + Sync;
    type ResponseKind: From<Self::RequestKind> + PartialEq + Eq + Debug + Send + Sync;
    type GossipKind: Send + Sync;

    fn capabilities(&self) -> CapabilityInfo;
    fn parse_message_id(
        &self,
        id: usize,
    ) -> Option<MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>>;
    fn to_message_id(
        &self,
        kind: MessageKind<Self::RequestKind, Self::ResponseKind, Self::GossipKind>,
    ) -> usize;
    async fn on_peer_connect(&self) -> Option<Message>;
    /// Handle incoming request, optionally forming a response and reputation report.
    async fn handle_request(
        &self,
        id: Self::RequestKind,
        peer: IngressPeer,
        payload: Bytes,
    ) -> (Option<Vec<EncodableObject>>, Option<ReputationReport>);
    async fn handle_gossip(
        &self,
        id: Self::GossipKind,
        peer: IngressPeer,
        payload: Bytes,
    ) -> Option<ReputationReport>;
}

pub type EncodableObject = Box<dyn Encodable + Send + 'static>;

/// Multiplexing server which enables request-response logic over generic bytes.
pub struct MuxServer<P2P: CapabilityRegistrar, Protocol: MuxProtocol> {
    tasks: Arc<TaskGroup>,
    inflight_requests: Arc<Mutex<RequestMultiplexer<<Protocol as MuxProtocol>::ResponseKind>>>,

    protocol: Arc<Protocol>,
    devp2p_handle: Arc<P2P::ServerHandle>,
    devp2p_owned_handle: Option<Arc<P2P>>,
}

impl<P2P: CapabilityRegistrar, Protocol: MuxProtocol> MuxServer<P2P, Protocol> {
    /// Register the protocol server with the RLPx node.
    #[must_use]
    pub fn new(registrar: &P2P, protocol: Arc<Protocol>) -> Self {
        struct Handler<Protocol: MuxProtocol> {
            inflight_requests:
                Arc<Mutex<RequestMultiplexer<<Protocol as MuxProtocol>::ResponseKind>>>,
            protocol: Arc<Protocol>,
        }

        #[async_trait]
        impl<Protocol: MuxProtocol> CapabilityServer for Handler<Protocol> {
            async fn on_peer_connect(&self, _: PeerId) -> PeerConnectOutcome {
                PeerConnectOutcome::Retain {
                    hello: self.protocol.on_peer_connect().await,
                }
            }

            async fn on_ingress_message(
                &self,
                peer: IngressPeer,
                message: Message,
            ) -> Result<(Option<Message>, Option<ReputationReport>), HandleError> {
                let mut out = None;
                let mut reputation_report = None;

                match self.protocol.parse_message_id(message.id) {
                    None => {
                        debug!("Skipping unidentified message from with id {}", message.id);
                        reputation_report = Some(ReputationReport::Bad);
                    }
                    Some(MessageKind::Response(response)) => {
                        let request_id = Rlp::new(message.data.as_ref()).val_at(0)?;

                        // Get the callback
                        let sender = self
                            .inflight_requests
                            .lock()
                            .retrieve_callback(peer.id, request_id);

                        if let Some(RequestCallbackData {
                            data: sender,
                            expected_response_id,
                        }) = sender
                        {
                            if expected_response_id != response {
                                debug!(
                                    "Peer sent us wrong reply! Expected: {:?}, Got: {:?}",
                                    expected_response_id, response
                                );
                                reputation_report = Some(ReputationReport::Kick);
                            } else {
                                let payload = message
                                    .data
                                    .slice_ref(Rlp::new(message.data.as_ref()).at(1)?.data()?);
                                let (tx, rx) = oneshot();
                                // No-op if dropped.
                                let _ = sender.send((payload, tx));
                                if let Ok(v) = rx.await {
                                    reputation_report = Some(v)
                                }
                            }
                        } else {
                            trace!("Peer {} sent us unsolicited reply!", peer.id);

                            reputation_report = Some(ReputationReport::Kick);
                        }
                    }
                    Some(MessageKind::Request(request)) => {
                        let request_id: u64 = Rlp::new(message.data.as_ref()).val_at(0)?;
                        let payload = message
                            .data
                            .slice_ref(Rlp::new(message.data.as_ref()).at(1)?.data()?);

                        let mut stream = RlpStream::new();
                        stream.append(&request_id);

                        let (out_encodable, rep) = self
                            .protocol
                            .handle_request(request.clone(), peer, payload)
                            .await;
                        if let Some(encodables) = out_encodable {
                            for value in encodables {
                                stream.append(&value);
                            }
                            out = Some(Message {
                                id: self
                                    .protocol
                                    .to_message_id(MessageKind::Response(request.into())),
                                data: Bytes::from(stream.out()),
                            });
                        }
                        reputation_report = rep;
                    }
                    Some(MessageKind::Gossip(gossip)) => {
                        reputation_report = self
                            .protocol
                            .handle_gossip(gossip, peer, message.data)
                            .await;
                    }
                }
                Ok((out, reputation_report))
            }
        }

        let tasks = Default::default();
        let inflight_requests = Arc::new(Mutex::new(RequestMultiplexer::default()));

        let devp2p_handle = Arc::new(registrar.register(
            protocol.capabilities(),
            Arc::new(Handler {
                inflight_requests: inflight_requests.clone(),
                protocol: protocol.clone(),
            }),
        ));
        Self {
            tasks,
            inflight_requests,
            protocol,
            devp2p_handle,
            devp2p_owned_handle: None,
        }
    }

    /// Register the protocol server with the devp2p client and make protocol server the owner of devp2p instance
    #[must_use]
    pub fn new_owned(registrar: Arc<P2P>, request_handler: Arc<Protocol>) -> Self {
        let mut this = Self::new(&*registrar, request_handler);
        this.devp2p_owned_handle = Some(registrar);
        this
    }

    // Send request
    pub fn send_request<RequestBuilder, DataHandler>(
        &self,
        retry_timeout: Duration,
        request_builder: Arc<RequestBuilder>,
        data_handler: Arc<DataHandler>,
    ) -> impl Future<Output = Result<(), Shutdown>> + Send + 'static
    where
        RequestBuilder: Fn(
                Arc<P2P::ServerHandle>,
            ) -> Option<(
                <P2P::ServerHandle as ServerHandle>::EgressPeerHandle,
                Protocol::RequestKind,
                Vec<EncodableObject>,
            )> + Send
            + Sync
            + 'static,
        DataHandler: Fn(Bytes) -> Option<ReputationReport> + Send + Sync + 'static,
    {
        let tasks = self.tasks.clone();
        let inflight_requests = self.inflight_requests.clone();
        let devp2p_handle = self.devp2p_handle.clone();
        let protocol = self.protocol.clone();
        async move {
            // Keep sending the request until successful
            loop {
                if let Some((peer, message_id, data)) = (request_builder)(devp2p_handle.clone()) {
                    let (tx, rx) = oneshot();

                    let peer_id = peer.peer_id();
                    let request_id = inflight_requests.lock().save_callback(
                        peer_id,
                        RequestCallbackData {
                            data: tx,
                            expected_response_id: message_id.clone().into(),
                        },
                    );

                    let mut out = RlpStream::new();
                    out.append(&request_id);
                    for obj in data {
                        out.append(&obj);
                    }
                    match peer
                        .send_message(Message {
                            id: protocol.to_message_id(MessageKind::Request(message_id)),
                            data: Bytes::from(out.out()),
                        })
                        .await
                    {
                        Err(PeerSendError::PeerGone) => {
                            continue;
                        }
                        Err(PeerSendError::Shutdown) => return Err(Shutdown),
                        Ok(()) => {}
                    }

                    // Reap on timeout
                    tasks.spawn({
                        let inflight_requests = inflight_requests.clone();
                        async move {
                            tokio::time::delay_for(retry_timeout).await;
                            let _ = inflight_requests
                                .lock()
                                .retrieve_callback(peer_id, request_id);
                            // TODO: penalize the peer
                        }
                    });

                    if let Ok((bytes, reputation_callback)) = rx.await {
                        if let Some(report) = (data_handler)(bytes) {
                            let _ = reputation_callback.send(report);
                        }
                    } else {
                        continue;
                    }
                }

                return Ok(());
            }
        }
    }
}
