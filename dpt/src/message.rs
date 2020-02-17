use bigint::{H256, H512};
use rlp::{Decodable, DecoderError, Encodable, RlpStream, UntrustedRlp};
use std::net::{IpAddr, Ipv4Addr};

pub struct Neighbour {
    pub address: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub id: H512,
}

impl Encodable for Neighbour {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        let address: Vec<u8> = match self.address.clone() {
            IpAddr::V4(v) => v.octets().as_ref().into(),
            IpAddr::V6(v) => v.octets().as_ref().into(),
        };
        s.append(&address);
        s.append(&self.udp_port);
        s.append(&self.tcp_port);
        s.append(&self.id);
    }
}

impl Decodable for Neighbour {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let address_raw: Vec<u8> = rlp.val_at(0)?;
        let address = if address_raw.len() == 4 {
            let mut raw = [0u8; 4];
            for i in 0..4 {
                raw[i] = address_raw[i];
            }
            IpAddr::from(raw)
        } else if address_raw.len() == 16 {
            let mut raw = [0u8; 16];
            for i in 0..16 {
                raw[i] = address_raw[i];
            }
            IpAddr::from(raw)
        } else {
            return Err(DecoderError::Custom("wrong address length"));
        };
        Ok(Self {
            address,
            udp_port: rlp.val_at(1)?,
            tcp_port: rlp.val_at(2)?,
            id: rlp.val_at(3)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub address: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl Encodable for Endpoint {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        let address: Vec<u8> = match self.address.clone() {
            IpAddr::V4(v) => v.octets().as_ref().into(),
            IpAddr::V6(v) => v.octets().as_ref().into(),
        };
        s.append(&address);
        s.append(&self.udp_port);
        s.append(&self.tcp_port);
    }
}

impl Decodable for Endpoint {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        let address_raw: Vec<u8> = rlp.val_at(0)?;
        let address = if address_raw.len() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                address_raw[0],
                address_raw[1],
                address_raw[2],
                address_raw[3],
            ))
        } else if address_raw.len() == 16 {
            let mut raw = [0u8; 16];
            for i in 0..16 {
                raw[i] = address_raw[i];
            }
            IpAddr::from(raw)
        } else {
            return Err(DecoderError::Custom("wrong address length"));
        };
        Ok(Self {
            address,
            udp_port: rlp.val_at(1)?,
            tcp_port: rlp.val_at(2)?,
        })
    }
}

pub struct FindNeighboursMessage {
    pub id: H512,
    pub expire: u64,
}

impl Encodable for FindNeighboursMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.id);
        s.append(&self.expire);
    }
}

impl Decodable for FindNeighboursMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            id: rlp.val_at(0)?,
            expire: rlp.val_at(1)?,
        })
    }
}

pub struct NeighboursMessage {
    pub nodes: Vec<Neighbour>,
    pub expire: u64,
}

impl Encodable for NeighboursMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append_list(&self.nodes);
        s.append(&self.expire);
    }
}

impl Decodable for NeighboursMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            nodes: rlp.list_at(0)?,
            expire: rlp.val_at(1)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PingMessage {
    pub from: Endpoint,
    pub to: Endpoint,
    pub expire: u64,
}

impl Encodable for PingMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&4u32); // Version 4
        s.append(&self.from);
        s.append(&self.to);
        s.append(&self.expire);
    }
}

impl Decodable for PingMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            from: rlp.val_at(1)?,
            to: rlp.val_at(2)?,
            expire: rlp.val_at(3)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PongMessage {
    pub to: Endpoint,
    pub echo: H256,
    pub expire: u64,
}

impl Encodable for PongMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.to);
        s.append(&self.echo);
        s.append(&self.expire);
    }
}

impl Decodable for PongMessage {
    fn decode(rlp: &UntrustedRlp) -> Result<Self, DecoderError> {
        Ok(Self {
            to: rlp.val_at(0)?,
            echo: rlp.val_at(1)?,
            expire: rlp.val_at(2)?,
        })
    }
}
