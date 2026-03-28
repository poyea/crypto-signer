use alloc::string::String;
use alloc::vec::Vec;

use crate::{evm::abi, Address};

use super::keccak256;

/// EIP-712 domain parameters.
///
/// Uniquely identifies a contract and chain so that a signature produced for
/// one contract or network cannot be replayed on another.
///
/// Build with [`Domain::new`] rather than filling fields directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    /// Human-readable name of the signing domain (e.g. `"USDC"`).
    pub name: String,
    /// Version string of the signing domain (e.g. `"1"`).
    pub version: String,
    /// EIP-155 chain ID (e.g. `1` for Ethereum mainnet, `137` for Polygon).
    pub chain_id: u64,
    /// Address of the contract that will verify the signature.
    pub verifying_contract: Address,
}

impl Domain {
    /// Create a new domain, accepting any `&str`-compatible name and version.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "evm")] {
    /// use crypto_signer::{Address, Domain};
    /// let domain = Domain::new("USDC", "1", 137, Address::new([0x11; 20]));
    /// # }
    /// ```
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

    /// Compute the EIP-712 domain separator hash.
    ///
    /// The result is stable for the same inputs and can be cached.
    /// It is passed to [`eip712_digest`](super::eip712_digest) when building
    /// the final signing digest.
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
