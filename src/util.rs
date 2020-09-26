use async_trait::async_trait;
use ethereum_types::{H256, H512};
use futures::{future::abortable, Stream};
use generic_array::GenericArray;
use hmac::{Hmac, Mac, NewMac};
use k256::{ecdsa::VerifyKey, EncodedPoint};
use parking_lot::Mutex;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::prelude::*;
use tracing::*;

pub struct TaskHandle<T>(Pin<Box<dyn Future<Output = Result<T, Shutdown>> + Send + 'static>>);

impl<T> Future for TaskHandle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Shutdown>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[derive(Clone, Debug)]
pub struct Shutdown;

/// Common trait that various runtimes should implement.
#[async_trait]
pub trait Runtime {
    /// Runtime's TCP stream type.
    type TcpStream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    type TcpServer: Stream<Item = Self::TcpStream> + Unpin + Send + 'static;

    fn spawn(&self, fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>);
    async fn sleep(&self, duration: Duration);
    async fn connect_tcp(&self, target: String) -> io::Result<Self::TcpStream>;
    async fn tcp_server(&self, addr: String) -> io::Result<Self::TcpServer>;
}

#[derive(Default, Debug)]
pub struct TaskGroup(Mutex<Vec<futures::future::AbortHandle>>);

impl TaskGroup {
    pub fn spawn<Fut, T>(&self, future: Fut) -> TaskHandle<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut group = self.0.lock();
        let (t, handle) = abortable(future);
        group.push(handle);
        let spawned_handle = tokio::spawn(t);
        TaskHandle(Box::pin(async move {
            Ok(spawned_handle
                .await
                .map_err(|_| {
                    trace!("Runtime shutdown");
                    Shutdown
                })?
                .map_err(|_| {
                    trace!("Task group shutdown");
                    Shutdown
                })?)
        }))
    }
}

impl Drop for TaskGroup {
    fn drop(&mut self) {
        for handle in &*self.0.lock() {
            handle.abort();
        }
    }
}

pub fn keccak256(data: &[u8]) -> H256 {
    H256::from(Keccak256::digest(data).as_ref())
}

pub fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).unwrap();
    hmac.update(input);
    H256::from_slice(&*hmac.finalize().into_bytes())
}

pub fn pk2id(pk: &VerifyKey) -> H512 {
    H512::from_slice(&*EncodedPoint::from(pk).to_untagged_bytes().unwrap())
}

pub fn id2pk(id: H512) -> Result<VerifyKey, signature::Error> {
    VerifyKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(GenericArray::from_slice(id.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn pk2id2pk() {
        let prikey = SigningKey::random(&mut OsRng);
        let pubkey = prikey.verify_key();
        assert_eq!(pubkey, id2pk(pk2id(&pubkey)).unwrap());
    }
}
