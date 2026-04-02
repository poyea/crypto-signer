#![cfg(feature = "evm")]

use crypto_signer::evm::{abi, eip712_digest, keccak256};

fn addr(hex_address: &str) -> crypto_signer::Address {
    let raw = hex::decode(hex_address).expect("valid hex");
    let mut out = [0_u8; 20];
    out.copy_from_slice(&raw);
    crypto_signer::Address::new(out)
}

#[test]
fn eip712_official_mail_vectors_match() {
    // Vectors from EIP-712 official asset:
    // https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js
    let mail_type = "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
    let mail_type_hash = keccak256(mail_type.as_bytes());
    assert_eq!(
        hex::encode(mail_type_hash),
        "a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
    );

    let person_type_hash = keccak256("Person(string name,address wallet)".as_bytes());
    let mut from_encoded = Vec::with_capacity(32 * 3);
    abi::push_word(&mut from_encoded, person_type_hash);
    abi::push_word(&mut from_encoded, keccak256("Cow".as_bytes()));
    abi::encode_address(
        &mut from_encoded,
        addr("cd2a3d9f938e13cd947ec05abc7fe734df8dd826"),
    );
    let from_hash = keccak256(&from_encoded);

    let mut to_encoded = Vec::with_capacity(32 * 3);
    abi::push_word(&mut to_encoded, person_type_hash);
    abi::push_word(&mut to_encoded, keccak256("Bob".as_bytes()));
    abi::encode_address(
        &mut to_encoded,
        addr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    let to_hash = keccak256(&to_encoded);

    let mut mail_encoded = Vec::with_capacity(32 * 4);
    abi::push_word(&mut mail_encoded, mail_type_hash);
    abi::push_word(&mut mail_encoded, from_hash);
    abi::push_word(&mut mail_encoded, to_hash);
    abi::push_word(&mut mail_encoded, keccak256("Hello, Bob!".as_bytes()));

    let mail_struct_hash = keccak256(&mail_encoded);
    assert_eq!(
        hex::encode(mail_struct_hash),
        "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    );

    let mut domain_encoded = Vec::with_capacity(32 * 5);
    let domain_type_hash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    abi::push_word(&mut domain_encoded, domain_type_hash);
    abi::push_word(&mut domain_encoded, keccak256("Ether Mail".as_bytes()));
    abi::push_word(&mut domain_encoded, keccak256("1".as_bytes()));
    abi::encode_u64(&mut domain_encoded, 1);
    abi::encode_address(
        &mut domain_encoded,
        addr("cccccccccccccccccccccccccccccccccccccccc"),
    );

    let domain_separator = keccak256(&domain_encoded);
    assert_eq!(
        hex::encode(domain_separator),
        "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    );

    let digest = eip712_digest(domain_separator, mail_struct_hash);
    assert_eq!(
        hex::encode(digest),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
}

#[test]
fn eip2612_permit_typehash_matches_spec_constant() {
    let permit =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
    let got = keccak256(permit.as_bytes());
    // Widely used EIP-2612 constant in reference implementations.
    assert_eq!(
        hex::encode(got),
        "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9"
    );
}

/// Verify that signing a digest and then recovering the signer address returns
/// the same address as the signer reports. This tests the full round-trip
/// locally without requiring a live endpoint.
#[cfg(feature = "k256-signer")]
#[test]
fn recover_signer_roundtrip() {
    use crypto_signer::backends::local_k256::LocalK256Signer;
    use crypto_signer::{recover_signer, Signer};
    use k256::ecdsa::SigningKey;

    let key = SigningKey::from_bytes(&[0x07_u8; 32].into()).expect("valid key");
    let signer = LocalK256Signer::from_signing_key(key);

    let digest = [0xde_u8; 32];
    let sig = signer.sign_hash(digest).expect("signing must not fail");
    let recovered = recover_signer(digest, &sig).expect("recovery must succeed");
    assert_eq!(
        recovered,
        signer.address(),
        "recovered address must match signer"
    );
}

/// Recovery must fail cleanly when `v` is neither 27 nor 28.
#[cfg(feature = "k256-signer")]
#[test]
fn recover_signer_rejects_bad_v() {
    use crypto_signer::evm::RecoveryError;
    use crypto_signer::{recover_signer, Signature};

    let sig = Signature::new(0, [0u8; 32], [0u8; 32]);
    assert_eq!(
        recover_signer([0u8; 32], &sig),
        Err(RecoveryError::InvalidRecoveryId)
    );
}

/// `NetworkConfig::polygon_mainnet()` returns chain ID 137.
#[test]
fn network_config_polygon_mainnet_chain_id() {
    use crypto_signer::evm::NetworkConfig;
    assert_eq!(NetworkConfig::polygon_mainnet().chain_id, 137);
}

/// `NetworkConfig::polygon_mumbai()` returns chain ID 80001.
#[test]
fn network_config_polygon_mumbai_chain_id() {
    use crypto_signer::evm::NetworkConfig;
    assert_eq!(NetworkConfig::polygon_mumbai().chain_id, 80001);
}
