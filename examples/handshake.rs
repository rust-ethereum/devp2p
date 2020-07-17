use ethereum_types::H512;
use hex_literal::hex;
use libsecp256k1::SecretKey;
use rand::rngs::OsRng;
use rlpx::ecies::ECIESStream;
use tokio::net::TcpStream;

// const REMOTE_ID: H512 = H512(hex!("589e7485b1d29a06c86827aa9e8c3d4a5f7c6dce25aca3202a46f5a038be0cfdc1b7aa1c172656bc1f3d82e49b1e2ac73276ba9953a232651f69c593c83315da"));
const REMOTE_ID: H512 = H512(hex!("bf05c3987d3bfcbb5c24cc389a7dcf31798d35e826a4147d9e49d2f8b056fcb17ff05d6fe32739b8552985e2c41c2324911007ddb5a0c487b7dca3b44aa5a7ae"));

#[tokio::main]
async fn main() {
    let _ = env_logger::init();

    ECIESStream::connect(
        TcpStream::connect("127.0.0.1:30303").await.unwrap(),
        SecretKey::random(&mut OsRng),
        REMOTE_ID,
    )
    .await
    .unwrap();
}
