use std::{fmt::Debug, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub trait Transport: AsyncRead + AsyncWrite + Debug + Send + Unpin + 'static {
    fn remote_addr(&self) -> Option<SocketAddr>;
}

impl Transport for TcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}
