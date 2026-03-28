use alloc::string::String;
use alloc::vec::Vec;

use crate::{evm::abi, Address};

use super::keccak256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

impl Domain {
    /// Convenience constructor; accepts any `&str`-like name and version.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        chain_id: u64,
        verifying_contract: Address,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            chain_id,
            verifying_contract,
        }
    }

    pub fn separator(&self) -> [u8; 32] {
        // EIP-712 domain hash:
        // keccak256(typeHash || keccak256(name) || keccak256(version) || chainId || contract)
        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );

        let mut encoded = Vec::with_capacity(32 * 5);
        abi::push_word(&mut encoded, type_hash);
        abi::push_word(&mut encoded, keccak256(self.name.as_bytes()));
        abi::push_word(&mut encoded, keccak256(self.version.as_bytes()));
        abi::encode_u64(&mut encoded, self.chain_id);
        abi::encode_address(&mut encoded, self.verifying_contract);
        keccak256(&encoded)
    }
}
