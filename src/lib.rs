pub extern crate dpt;
pub extern crate rlpx;

extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate secp256k1;

use dpt::{DPTNode, DPTStream};
use rlpx::{CapabilityInfo, RLPxStream};
use tokio_core::reactor::{Handle, Timeout};
use std::time::Duration;
use std::net::SocketAddr;
use std::io;
use secp256k1::key::SecretKey;

pub struct DevP2PStream {
    dpt: DPTStream,
    rlpx: RLPxStream,
    ping_interval: Duration,
    ping_timeout: Timeout,
    optimal_peers_len: usize,
    handle: Handle,
}

impl DevP2PStream {
    pub fn new(addr: &SocketAddr,
               handle: &Handle, secret_key: SecretKey,
               protocol_version: usize, client_version: String,
               capabilities: Vec<CapabilityInfo>,
               bootstrap_nodes: Vec<DPTNode>,
               ping_interval: Duration,
               optimal_peers_len: usize) -> Result<Self, io::Error> {
        let port = addr.port();

        let dpt = DPTStream::new(addr, handle, secret_key.clone(),
                                 bootstrap_nodes, port)?;
        let rlpx = RLPxStream::new(handle, secret_key.clone(),
                                   protocol_version, client_version,
                                   capabilities, port);
        let ping_timeout = Timeout::new(ping_interval, handle)?;

        Ok(DevP2PStream {
            dpt, rlpx, ping_interval, ping_timeout,
            optimal_peers_len, handle: handle.clone()
        })
    }
}
