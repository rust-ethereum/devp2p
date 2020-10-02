use devp2p::{ecies::ECIESStream, PeerId};
use hex_literal::hex;
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::net::TcpStream;

const REMOTE_ID: PeerId = PeerId(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666 "));

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    ECIESStream::connect(
        TcpStream::connect("18.138.108.67:30303").await.unwrap(),
        Arc::new(SigningKey::random(&mut OsRng)),
        REMOTE_ID,
    )
    .await
    .unwrap();
}
