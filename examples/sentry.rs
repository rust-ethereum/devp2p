use arrayvec::ArrayString;
use devp2p::*;
use libsecp256k1::SecretKey;
use maplit::btreemap;
use rand::rngs::OsRng;
use std::sync::Arc;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

const CLIENT_VERSION: &str = "rust-devp2p/0.1.0";
const DNS_BOOTNODE: &str = "all.mainnet.ethdisco.net";

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    let secret_key = SecretKey::random(&mut OsRng);

    let dns_resolver = dnsdisc::Resolver::new(Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .await
            .unwrap(),
    ));

    let discovery = DnsDiscovery::new(Arc::new(dns_resolver), DNS_BOOTNODE.to_string(), None);

    let client = RLPxNode::new(
        secret_key,
        CLIENT_VERSION.to_string(),
        Some(ListenOptions {
            discovery: Some(Arc::new(tokio::sync::Mutex::new(discovery))),
            max_peers: 50,
            addr: "0.0.0.0:30303".parse().unwrap(),
        }),
    )
    .await
    .unwrap();

    let _handle = client.register_protocol_server(
        btreemap! { CapabilityId {
            name: CapabilityName(ArrayString::from("eth").unwrap()),
            version: 63
        } => 17 },
        Arc::new(|_, _, _| Box::pin(async { Ok((None, None)) })),
        Arc::new(|| None),
    );

    futures::future::pending().await
}
