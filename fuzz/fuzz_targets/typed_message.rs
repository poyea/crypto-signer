#![no_main]

use crypto_signer::evm::{abi, eip712_digest, keccak256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 81 {
        return;
    }

    let mut addr = [0_u8; 20];
    addr.copy_from_slice(&data[..20]);

    let mut bytes32 = [0_u8; 32];
    bytes32.copy_from_slice(&data[20..52]);

    let mut out = Vec::with_capacity(32 * 4);
    abi::encode_address(&mut out, crypto_signer::Address::new(addr));
    abi::encode_bytes32(&mut out, bytes32);
    abi::encode_u64(&mut out, u64::from_be_bytes(data[52..60].try_into().expect("len")));
    abi::encode_u128(
        &mut out,
        u128::from_be_bytes(data[60..76].try_into().expect("len")),
    );

    let domain = keccak256(&out);
    let struct_hash = keccak256(&data[76..]);
    let _ = eip712_digest(domain, struct_hash);
});
