use alloc::vec::Vec;

use crate::Address;

pub fn push_word(out: &mut Vec<u8>, word: [u8; 32]) {
    out.extend_from_slice(&word);
}

pub fn encode_address(out: &mut Vec<u8>, address: Address) {
    let mut word = [0_u8; 32];
    word[12..].copy_from_slice(address.as_bytes());
    push_word(out, word);
}

pub fn encode_u8(out: &mut Vec<u8>, value: u8) {
    let mut word = [0_u8; 32];
    word[31] = value;
    push_word(out, word);
}

pub fn encode_u64(out: &mut Vec<u8>, value: u64) {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    push_word(out, word);
}

pub fn encode_u128(out: &mut Vec<u8>, value: u128) {
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    push_word(out, word);
}

pub fn encode_bytes32(out: &mut Vec<u8>, value: [u8; 32]) {
    push_word(out, value);
}
