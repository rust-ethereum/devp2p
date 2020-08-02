use crate::ecies::ECIESStream;
use ethereum_types::H512;
use hex_literal::hex;
use libsecp256k1::SecretKey;
use rand::rngs::OsRng;
use tokio::net::TcpStream;

const REMOTE_ID: H512 = H512(hex!("d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666 "));

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    ECIESStream::connect(
        TcpStream::connect("18.138.108.67:30303").await.unwrap(),
        SecretKey::random(&mut OsRng),
        REMOTE_ID,
    )
    .await
    .unwrap();
}
