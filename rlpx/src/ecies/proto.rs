use futures::future;
use futures::{Future, Stream, Sink};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{Framed, Encoder, Decoder};
use tokio_core::reactor::Core;
use bytes::{BytesMut, BufMut};
use errors::ECIESError;
use secp256k1::key::SecretKey;
use bigint::H512;
use std::io;
use super::algorithm::ECIES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ECIESState {
    Auth, Ack, Header, Body
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ECIESValue {
    Auth, Ack, Header(usize), Body(Vec<u8>)
}

pub struct ECIESCodec {
    ecies: ECIES,
    state: ECIESState,
}

impl ECIESCodec {
    pub fn new_server(secret_key: SecretKey) -> Result<Self, ECIESError> {
        Ok(Self {
            ecies: ECIES::new_server(secret_key)?,
            state: ECIESState::Auth
        })
    }

    pub fn new_client(secret_key: SecretKey, remote_id: H512) -> Result<Self, ECIESError> {
        Ok(Self {
            ecies: ECIES::new_client(secret_key, remote_id)?,
            state: ECIESState::Auth
        })
    }
}

impl Decoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<ECIESValue>, io::Error> {
        match self.state {
            ECIESState::Auth => {
                if buf.len() < self.ecies.auth_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.auth_len());
                self.ecies.parse_auth(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Auth))
            },
            ECIESState::Ack => {
                if buf.len() < self.ecies.ack_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.ack_len());
                self.ecies.parse_ack(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Ack))
            },
            ECIESState::Header => {
                if buf.len() < self.ecies.header_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.header_len());
                let size = self.ecies.parse_header(&data)?;

                self.state = ECIESState::Body;
                Ok(Some(ECIESValue::Header(size)))
            },
            ECIESState::Body => {
                if buf.len() < self.ecies.body_len() {
                    return Ok(None);
                }

                let data = buf.split_to(self.ecies.body_len());
                let ret = self.ecies.parse_body(&data)?;

                self.state = ECIESState::Header;
                Ok(Some(ECIESValue::Body(ret)))
            },
        }
    }
}

impl Encoder for ECIESCodec {
    type Item = ECIESValue;
    type Error = io::Error;

    fn encode(&mut self, msg: ECIESValue, buf: &mut BytesMut) -> Result<(), io::Error> {
        match msg {
            ECIESValue::Auth => {
                let data = self.ecies.create_auth()?;
                self.state = ECIESState::Ack;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Ack => {
                let data = self.ecies.create_ack()?;
                self.state = ECIESState::Header;
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Header(size) => {
                let data = self.ecies.create_header(size);
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            },
            ECIESValue::Body(val) => {
                let data = self.ecies.create_body(val.as_ref());
                buf.reserve(data.len());
                buf.extend(data);
                Ok(())
            }
        }
    }
}
