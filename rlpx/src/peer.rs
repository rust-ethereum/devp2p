pub enum PeerState {
    Auth, Ack, Header, Body
}

// pub struct Peer {
//     client_id: String,
//     capabilities: Vec<Capability>,
//     address: SocketAddr,

//     id: H512,
//     remote_id: H512,

//     socket: TcpStream,
// }
