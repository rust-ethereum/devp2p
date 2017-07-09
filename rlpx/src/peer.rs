use errors::ECIESError;
use ecies::{ECIESCodec, ECIESValue};
use futures::future;
use futures::{Future, Stream, Sink};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_io::AsyncRead;
use tokio_io::codec::Framed;
use secp256k1::key::SecretKey;
use bigint::H512;
use std::net::SocketAddr;
use std::io;

pub struct Peer {
    stream: Framed<TcpStream, ECIESCodec>,
    remote_id: H512,
}

impl Peer {
    pub fn connect_client(
        addr: &SocketAddr, handle: &Handle,
        secret_key: SecretKey, remote_id: H512
    ) -> Box<Future<Item = Peer, Error = io::Error>> {
        let ecies = match ECIESCodec::new_client(secret_key, remote_id) {
            Ok(val) => val,
            Err(e) => return Box::new(future::err(
                io::Error::new(io::ErrorKind::Other, "invalid handshake")))
                as Box<Future<Item = Peer, Error = io::Error>>,
        };

        let stream = TcpStream::connect(addr, handle)
            .and_then(|socket| socket.framed(ecies).send(ECIESValue::Auth))
            .and_then(|transport| transport.into_future().map_err(|(e, _)| e))
            .and_then(move |(ack, transport)| {
                if ack == Some(ECIESValue::Ack) {
                    Ok(Peer {
                        stream: transport,
                        remote_id: remote_id,
                    })
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "invalid handshake"))
                }
            });

        Box::new(stream)
    }
}
