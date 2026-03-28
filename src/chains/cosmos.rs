use alloc::string::String;
use alloc::vec::Vec;

use prost::Message;
use sha2::{Digest, Sha256};

/// Protobuf-encoded signing payload for Cosmos SDK transactions.
///
/// Matches the `SignDoc` message in the Cosmos SDK:
/// <https://github.com/cosmos/cosmos-sdk/blob/main/proto/cosmos/tx/v1beta1/tx.proto>
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SignDoc {
    /// Encoded `TxBody` protobuf bytes (messages, memo, timeout).
    #[prost(bytes = "vec", tag = "1")]
    pub body_bytes: Vec<u8>,
    /// Encoded `AuthInfo` protobuf bytes (signer info + fee).
    #[prost(bytes = "vec", tag = "2")]
    pub auth_info_bytes: Vec<u8>,
    /// Chain identifier, e.g. `"osmosis-1"` or `"cosmoshub-4"`.
    #[prost(string, tag = "3")]
    pub chain_id: String,
    /// On-chain account number of the signer.
    #[prost(uint64, tag = "4")]
    pub account_number: u64,
    /// Per-account sequence number, incremented on each transaction.
    #[prost(uint64, tag = "5")]
    pub sequence: u64,
}

impl SignDoc {
    pub fn to_sign_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_sign_bytes());
        let out = hasher.finalize();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&out);
        hash
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignDocBytes(pub Vec<u8>);

impl From<SignDoc> for SignDocBytes {
    fn from(doc: SignDoc) -> Self {
        Self(doc.to_sign_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{SignDoc, SignDocBytes};

    #[test]
    fn from_signdoc_to_bytes_matches_encoder() {
        let doc = SignDoc {
            body_bytes: vec![1, 2, 3],
            auth_info_bytes: vec![4, 5],
            chain_id: "osmosis-1".to_string(),
            account_number: 9,
            sequence: 3,
        };

        let expected = doc.to_sign_bytes();
        let converted: SignDocBytes = doc.into();
        assert_eq!(converted.0, expected);
    }

    #[test]
    fn signing_hash_changes_when_field_changes() {
        let a = SignDoc {
            body_bytes: vec![0xAA],
            auth_info_bytes: vec![0xBB],
            chain_id: "osmosis-1".to_string(),
            account_number: 1,
            sequence: 0,
        };
        let mut b = a.clone();
        b.account_number = 2;
        assert_ne!(a.signing_hash(), b.signing_hash());

        let mut c = a.clone();
        c.sequence = 1;
        assert_ne!(a.signing_hash(), c.signing_hash());
    }
}
