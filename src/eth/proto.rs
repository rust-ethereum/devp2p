use ethereum::{Block, Header, Transaction};
use ethereum_forkid::ForkId;
use ethereum_types::{H256, U256};
use rlp::{DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[allow(clippy::pub_enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestMessageId {
    GetBlockHeaders,
    GetBlockBodies,
    GetPooledTransactions,
    GetNodeData,
    GetReceipts,
}

impl RequestMessageId {
    #[must_use]
    pub const fn into_response(self) -> ResponseMessageId {
        match self {
            Self::GetBlockHeaders => ResponseMessageId::BlockHeaders,
            Self::GetBlockBodies => ResponseMessageId::BlockBodies,
            Self::GetPooledTransactions => ResponseMessageId::PooledTransactions,
            Self::GetNodeData => ResponseMessageId::NodeData,
            Self::GetReceipts => ResponseMessageId::Receipts,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseMessageId {
    BlockHeaders,
    BlockBodies,
    PooledTransactions,
    NodeData,
    Receipts,
}

impl From<RequestMessageId> for ResponseMessageId {
    fn from(id: RequestMessageId) -> Self {
        match id {
            RequestMessageId::GetBlockHeaders => Self::BlockHeaders,
            RequestMessageId::GetBlockBodies => Self::BlockBodies,
            RequestMessageId::GetPooledTransactions => Self::PooledTransactions,
            RequestMessageId::GetNodeData => Self::NodeData,
            RequestMessageId::GetReceipts => Self::Receipts,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GossipMessageId {
    Status,
    NewBlockHashes,
    Transactions,
    NewBlock,
    NewPooledTransactionHashes,
}

#[allow(clippy::pub_enum_variant_names)]
pub enum EthGossipMessage {
    NewBlockHashes(Vec<(H256, U256)>),
    NewTransactionHashes,
    NewBlock {
        block: Block,
        total_difficulty: U256,
    },
}

pub struct Transactions(pub Vec<Transaction>);

#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Status {
    pub protocol_version: usize,
    pub network_id: usize,
    pub total_difficulty: U256,
    pub best_hash: H256,
    pub genesis_hash: H256,
    pub fork_id: ForkId,
}

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
    GetBlockHeadersByNumber {
        number: U256, // TODO: this can also be a hash.
        max_headers: usize,
        skip: usize,
        reverse: bool,
    },
    GetBlockHeadersByHash {
        hash: H256,
        max_headers: usize,
        skip: usize,
        reverse: bool,
    },
    BlockHeaders(Vec<Header>),
    GetBlockBodies(Vec<H256>),
    BlockBodies(Vec<(Vec<Transaction>, Vec<Header>)>),
    NewBlock {
        block: Block,
        total_difficulty: U256,
    },
    Unknown,
}

impl ETHMessage {
    /// Get the message id of the ETH message
    #[must_use]
    pub const fn id(&self) -> usize {
        match self {
            Self::Status { .. } => 0,
            Self::NewBlockHashes(_) => 1,
            Self::Transactions(_) => 2,
            Self::GetBlockHeadersByNumber { .. } | Self::GetBlockHeadersByHash { .. } => 3,
            Self::BlockHeaders(_) => 4,
            Self::GetBlockBodies(_) => 5,
            Self::BlockBodies(_) => 6,
            Self::NewBlock { .. } => 7,
            Self::Unknown => 127,
        }
    }

    /// Decode a RLP into ETH message using the given message id
    ///
    /// # Errors
    /// Errors out on failure to decode contents based on provided `id`.
    pub fn decode(rlp: &Rlp, id: usize) -> Result<Self, DecoderError> {
        Ok(match id {
            0 => Self::Status {
                protocol_version: rlp.val_at(0)?,
                network_id: rlp.val_at(1)?,
                total_difficulty: rlp.val_at(2)?,
                best_hash: rlp.val_at(3)?,
                genesis_hash: rlp.val_at(4)?,
            },
            1 => {
                let mut r = Vec::new();
                for i in 0..rlp.item_count()? {
                    let d = rlp.at(i)?;
                    r.push((d.val_at(0)?, d.val_at(1)?));
                }
                Self::NewBlockHashes(r)
            }
            2 => Self::Transactions(rlp.as_list()?),
            3 => {
                let reverse: u32 = rlp.val_at(3)?;
                if rlp.at(0)?.size() == 32 {
                    Self::GetBlockHeadersByHash {
                        hash: rlp.val_at(0)?,
                        max_headers: rlp.val_at(1)?,
                        skip: rlp.val_at(2)?,
                        reverse: reverse != 0,
                    }
                } else {
                    Self::GetBlockHeadersByNumber {
                        number: rlp.val_at(0)?,
                        max_headers: rlp.val_at(1)?,
                        skip: rlp.val_at(2)?,
                        reverse: reverse != 0,
                    }
                }
            }
            4 => Self::BlockHeaders(rlp.as_list()?),
            5 => Self::GetBlockBodies(rlp.as_list()?),
            6 => {
                let mut r = Vec::new();
                for i in 0..rlp.item_count()? {
                    let d = rlp.at(i)?;
                    r.push((d.list_at(0)?, d.list_at(1)?));
                }
                Self::BlockBodies(r)
            }
            7 => Self::NewBlock {
                block: rlp.val_at(0)?,
                total_difficulty: rlp.val_at(1)?,
            },
            _ => Self::Unknown,
        })
    }
}

impl Encodable for ETHMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Self::Status {
                protocol_version,
                network_id,
                total_difficulty,
                best_hash,
                genesis_hash,
            } => {
                s.begin_list(5);
                s.append(protocol_version);
                s.append(network_id);
                s.append(total_difficulty);
                s.append(best_hash);
                s.append(genesis_hash);
            }
            Self::NewBlockHashes(hashes) => {
                s.begin_list(hashes.len());
                for (hash, number) in hashes {
                    s.begin_list(2);
                    s.append(hash);
                    s.append(number);
                }
            }
            Self::Transactions(transactions) => {
                s.append_list(transactions);
            }
            Self::GetBlockHeadersByNumber {
                number,
                max_headers,
                skip,
                reverse,
            } => {
                s.begin_list(4);
                s.append(number);
                s.append(max_headers);
                s.append(skip);
                s.append(&if *reverse { 1_u32 } else { 0_u32 });
            }
            Self::GetBlockHeadersByHash {
                hash,
                max_headers,
                skip,
                reverse,
            } => {
                s.begin_list(4);
                s.append(hash);
                s.append(max_headers);
                s.append(skip);
                s.append(&if *reverse { 1_u32 } else { 0_u32 });
            }
            Self::BlockHeaders(headers) => {
                s.append_list(headers);
            }
            Self::GetBlockBodies(hashes) => {
                s.append_list(hashes);
            }
            Self::BlockBodies(bodies) => {
                for (transactions, ommers) in bodies {
                    s.begin_list(2);
                    s.append_list(transactions);
                    s.append_list(ommers);
                }
            }
            Self::NewBlock {
                block,
                total_difficulty,
            } => {
                s.begin_list(2);
                s.append(block);
                s.append(total_difficulty);
            }
            Self::Unknown => {
                s.begin_list(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ETHMessage;
    use ethereum_types::H256;
    use hex_literal::hex;
    use rlp::{self, Rlp};

    #[test]
    fn test_new_block_hashes_message() {
        let data =
            hex!("e6e5a00bf2f8fd8ce1fd340915452e175a856ab349e24ceffef9b02d71b4d5c0bd75c2833ed50c");
        ETHMessage::decode(&Rlp::new(&data), 1).unwrap();
    }

    #[test]
    fn test_get_block_headers_message() {
        let data: [u8; 8] = [199, 131, 29, 76, 0, 1, 128, 128];
        ETHMessage::decode(&Rlp::new(&data), 3).unwrap();
    }

    #[test]
    fn test_get_block_headers_hash_message() {
        let hash = H256::random();
        let message = ETHMessage::GetBlockHeadersByHash {
            hash,
            max_headers: 2048,
            skip: 0,
            reverse: false,
        };
        assert_eq!(
            message,
            ETHMessage::decode(&Rlp::new(&rlp::encode(&message)), 3).unwrap()
        );
    }

    #[test]
    fn test_block_headers_message() {
        let data = hex!("f90861f90214a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000850400000000808213888080a011bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82faa00000000000000000000000000000000000000000000000000000000000000000880000000000000042f90211a0d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479405a56e2d52c817161883f50c441c3228cfe54d9fa0d67e4d450343046425ae4271474353857ab860dbc0a1dde64b41b5cd3a532bf3a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff80000001821388808455ba422499476574682f76312e302e302f6c696e75782f676f312e342e32a0969b900de27b6ac6a67742365dd65f55a0526c41fd18e1b16f1a1215c2e66f5988539bd4979fef1ec4f90218a088e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dd2f1e6e498202e86d8f5442af596580a4f03c2ca04943d941637411107494da9ec8bc04359d731bfd08b72b4d0edcbd4cd2ecb341a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503ff00100002821388808455ba4241a0476574682f76312e302e302d30636463373634372f6c696e75782f676f312e34a02f0790c5aa31ab94195e1f6443d645af5b75c46c04fbf9911711198a0ce8fdda88b853fa261a86aa9ef90218a0b495a1d7e6663152ae92708da4843337b958146015a2802f4193a410044698c9a06b17b938c6e4ef18b26ad81b9ca3515f27fd9c4e82aac56a1fd8eab288785e41945088d623ba0fcf0131e0897a91734a4d83596aa0a076ab0b899e8387436ff2658e2988f83cbf1af1590b9fe9feca3714f8d1824940a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008503fe802ffe03821388808455ba4260a0476574682f76312e302e302d66633739643332642f6c696e75782f676f312e34a065e12eec23fe6555e6bcdb47aa25269ae106e5f16b54e1e92dcee25e1c8ad037882e9344e0cbde83ce");
        ETHMessage::decode(&Rlp::new(&data), 4).unwrap();
    }
}
