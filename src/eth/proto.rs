use rlp::{Encodable, Decodable, RlpStream, DecoderError, UntrustedRlp};
use bigint::{Address, LogsBloom, Gas, H256, U256, B256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ETHMessage {
    Status {
        protocol_version: usize,
        network_id: usize,
        total_difficulty: U256,
        best_hash: H256,
        genesis_hash: H256,
    },
    Unknown,
}

impl ETHMessage {
    pub fn id(&self) -> usize {
        match self {
            &ETHMessage::Status { .. } => 0,
            &ETHMessage::Unknown => 127,
        }
    }

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
            &ETHMessage::Unknown => {
                s.begin_list(0);
            },
        }
    }
}
