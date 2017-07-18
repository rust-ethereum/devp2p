use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, LogsBloom, Gas, H256, U256, B256};
use block::{Header, Transaction};

/// ETH message version 62 and 63
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETHMessage {
    Status {
        protocol_version: usize,
        network_id: usize,
        total_difficulty: U256,
        best_hash: H256,
        genesis_hash: H256,
    },
    NewBlockHashes(Vec<(H256, U256)>),
    Transactions(Vec<Transaction>),
    GetBlockHeaders {
        number: U256,
        max_headers: usize,
        skip: usize,
        reverse: bool,
    },
    BlockHeaders(Vec<Header>),
    GetBlockBodies(Vec<H256>),
    BlockBodies(Vec<(Vec<Transaction>, Vec<Header>)>),
    Unknown,
}

impl ETHMessage {
    /// Get the message id of the ETH message
    pub fn id(&self) -> usize {
        match self {
            &ETHMessage::Status { .. } => 0,
            &ETHMessage::NewBlockHashes(_) => 1,
            &ETHMessage::Transactions(_) => 2,
            &ETHMessage::GetBlockHeaders { .. } => 3,
            &ETHMessage::BlockHeaders(_) => 4,
            &ETHMessage::GetBlockBodies(_) => 5,
            &ETHMessage::BlockBodies(_) => 6,
            &ETHMessage::Unknown => 127,
        }
    }

    /// Decode a RLP into ETH message using the given message id
    pub fn decode(rlp: &UntrustedRlp, id: usize) -> Result<Self, DecoderError> {
        Ok(match id {
            0 => {
                ETHMessage::Status {
                    protocol_version: rlp.val_at(0)?,
                    network_id: rlp.val_at(1)?,
                    total_difficulty: rlp.val_at(2)?,
                    best_hash: rlp.val_at(3)?,
                    genesis_hash: rlp.val_at(4)?,
                }
            },
            1 => {
                let mut r = Vec::new();
                for i in 0..rlp.item_count()? {
                    let d = rlp.at(i)?;
                    r.push((d.val_at(0)?, d.val_at(1)?));
                }
                ETHMessage::NewBlockHashes(r)
            },
            2 => {
                ETHMessage::Transactions(rlp.as_list()?)
            },
            3 => {
                ETHMessage::GetBlockHeaders {
                    number: rlp.val_at(0)?,
                    max_headers: rlp.val_at(1)?,
                    skip: rlp.val_at(2)?,
                    reverse: rlp.val_at(3)?,
                }
            },
            4 => {
                ETHMessage::BlockHeaders(rlp.as_list()?)
            },
            5 => {
                ETHMessage::GetBlockBodies(rlp.as_list()?)
            },
            6 => {
                let mut r = Vec::new();
                for i in 0..rlp.item_count()? {
                    let d = rlp.at(i)?;
                    r.push((d.list_at(0)?, d.list_at(1)?));
                }
                ETHMessage::BlockBodies(r)
            },
            _ => {
                ETHMessage::Unknown
            },
        })
    }
}

impl Encodable for ETHMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &ETHMessage::Status {
                protocol_version, network_id, total_difficulty, best_hash, genesis_hash
            } => {
                s.begin_list(5);
                s.append(&protocol_version);
                s.append(&network_id);
                s.append(&total_difficulty);
                s.append(&best_hash);
                s.append(&genesis_hash);
            },
            &ETHMessage::NewBlockHashes(ref hashes) => {
                s.begin_list(hashes.len());
                for &(hash, number) in hashes {
                    s.begin_list(2);
                    s.append(&hash);
                    s.append(&number);
                }
            },
            &ETHMessage::Transactions(ref transactions) => {
                s.append_list(&transactions);
            },
            &ETHMessage::GetBlockHeaders {
                number,
                max_headers, skip, reverse
            } => {
                s.begin_list(4);
                s.append(&number);
                s.append(&max_headers);
                s.append(&skip);
                s.append(&reverse);
            },
            &ETHMessage::BlockHeaders(ref headers) => {
                s.append_list(&headers);
            },
            &ETHMessage::GetBlockBodies(ref hashes) => {
                s.append_list(&hashes);
            },
            &ETHMessage::BlockBodies(ref bodies) => {
                for &(ref transactions, ref ommers) in bodies {
                    s.begin_list(2);
                    s.append_list(&transactions);
                    s.append_list(&ommers);
                }
            },
            &ETHMessage::Unknown => {
                s.begin_list(0);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ETHMessage;
    use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};

    #[test]
    fn test_new_block_hashes_message() {
        let data: [u8; 39] = [230, 229, 160, 11, 242, 248, 253, 140, 225, 253, 52, 9, 21, 69, 46, 23, 90, 133, 106, 179, 73, 226, 76, 239, 254, 249, 176, 45, 113, 180, 213, 192, 189, 117, 194, 131, 62, 213, 12];
        ETHMessage::decode(&UntrustedRlp::new(&data), 1).unwrap();
    }

    #[test]
    fn test_get_block_headers_message() {
        let data: [u8; 8] = [199, 131, 29, 76, 0, 1, 128, 128];
        ETHMessage::decode(&UntrustedRlp::new(&data), 3).unwrap();
    }
}
