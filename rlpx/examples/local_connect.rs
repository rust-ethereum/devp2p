use arrayvec::ArrayString;
use ethereum_types::H512;
use hex_literal::hex;
use libsecp256k1::SecretKey;
use rand::rngs::OsRng;
use rlpx::{CapabilityInfo, CapabilityName, RLPxStream};
use tokio::stream::StreamExt;

const REMOTE_ID: H512 = H512(hex!("103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1"));

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    let addr = "127.0.0.1:30303".parse().unwrap();
    let mut client = RLPxStream::new(
        SecretKey::random(&mut OsRng),
        4,
        "etclient Rust/0.1.0".to_string(),
        vec![
            CapabilityInfo {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 62,
                length: 8,
            },
            CapabilityInfo {
                name: CapabilityName(ArrayString::from("eth").unwrap()),
                version: 63,
                length: 17,
            },
        ],
        None,
    )
    .await
    .unwrap();

    client.add_peer(addr, REMOTE_ID).await.unwrap();

    let timeout = 5;
    let mut delay = tokio::time::delay_for(std::time::Duration::from_secs(timeout));

    println!(
        "{}",
        tokio::select! {
            _ = &mut delay => {
                format!("timed out after {} secs", timeout)
            }
            val = client.next() => {
                format!("va: {:?}", val.unwrap())
            }
        }
    );
}
