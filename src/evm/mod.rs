/// EVM / EIP-712 signing primitives.
///
/// This module provides everything needed to sign structured data on
/// Ethereum-compatible chains:
///
/// - [`Domain`] — EIP-712 domain parameters (name, version, chain ID, contract)
/// - [`TypedMessage`] — typestate wrapper that enforces sign-before-use
/// - [`Eip712Type`] — implement this trait on your payload struct to make it signable
/// - [`messages`] — built-in [`Permit`](messages::Permit) and [`Order`](messages::Order) payloads
/// - [`abi`] — low-level ABI encoding helpers used by payload impls
pub mod abi;
pub mod domain;
pub mod eip712;
pub mod messages;

pub use domain::Domain;
pub use eip712::{Eip712Type, Signed, TypedMessage, Unsigned};

use sha3::{Digest, Keccak256};

/// Compute the Keccak-256 digest of `input`.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    hash
}

/// Compute the EIP-712 typed-data digest:
/// `keccak256("\x19\x01" ‖ domainSeparator ‖ structHash)`.
///
/// This is the 32-byte value that gets signed by the private key.
pub fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 66];
    encoded[0] = 0x19;
    encoded[1] = 0x01;
    encoded[2..34].copy_from_slice(&domain_separator);
    encoded[34..66].copy_from_slice(&struct_hash);
    keccak256(&encoded)
}
