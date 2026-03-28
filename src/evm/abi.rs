/// Low-level ABI encoding helpers.
///
/// These functions append a single ABI-encoded word (32 bytes, big-endian,
/// zero-padded) to an output buffer. They are used by [`Eip712Type::encode_data`]
/// implementations to build the struct hash input.
///
/// You only need these if you are implementing [`Eip712Type`] for a custom type.
///
/// [`Eip712Type`]: super::eip712::Eip712Type
use alloc::vec::Vec;

use crate::Address;

/// Append a raw 32-byte word to `out`.
pub fn push_word(out: &mut Vec<u8>, word: [u8; 32]) {
    out.extend_from_slice(&word);
}

/// ABI-encode an Ethereum `address` (right-aligned in a 32-byte word).
pub fn encode_address(out: &mut Vec<u8>, address: Address) {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address.as_bytes());
    push_word(out, word);
}

/// ABI-encode a `uint8` value (right-aligned in a 32-byte word).
pub fn encode_u8(out: &mut Vec<u8>, value: u8) {
    let mut word = [0_u8; 32];
    word[31] = value;
    push_word(out, word);
}

/// ABI-encode a `uint64` value (right-aligned in a 32-byte word).
pub fn encode_u64(out: &mut Vec<u8>, value: u64) {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    push_word(out, word);
}

/// ABI-encode a `uint128` / `uint256` value (right-aligned in a 32-byte word).
pub fn encode_u128(out: &mut Vec<u8>, value: u128) {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    push_word(out, word);
}

/// ABI-encode a `bytes32` value (passed through as-is).
pub fn encode_bytes32(out: &mut Vec<u8>, value: [u8; 32]) {
    push_word(out, value);
}
