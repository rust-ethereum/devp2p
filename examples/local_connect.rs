use devp2p::RLPxNode;
use ethereum_types::H512;
use hex_literal::hex;
use libsecp256k1::SecretKey;
use rand::rngs::OsRng;

const REMOTE_ID: H512 = H512(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666"));

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    let addr = "18.138.108.67:30303".parse().unwrap();
    let client = RLPxNode::new(
        SecretKey::random(&mut OsRng),
        "rust-devp2p/0.1.0".to_string(),
        None,
    )
    .await
    .unwrap();

    client.add_peer(addr, REMOTE_ID).await.unwrap();

    let timeout = 5;
    tokio::time::delay_for(std::time::Duration::from_secs(timeout)).await;
}
