pub mod abi;
pub mod domain;
pub mod eip712;
pub mod messages;

pub use domain::Domain;
pub use eip712::{Eip712Type, Signed, TypedMessage, Unsigned};

use sha3::{Digest, Keccak256};

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    hash
}

pub fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 66];
    encoded[0] = 0x19;
    encoded[1] = 0x01;
    encoded[2..34].copy_from_slice(&domain_separator);
    encoded[34..66].copy_from_slice(&struct_hash);
    keccak256(&encoded)
}
