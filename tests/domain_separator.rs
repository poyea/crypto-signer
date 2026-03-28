#![cfg(feature = "evm")]

use crypto_signer::{Address, Domain};

#[test]
fn domain_separator_is_deterministic() {
    let domain = Domain::new("USDC", "1", 1, Address::new([0xAB; 20]));

    let a = domain.separator();
    let b = domain.separator();
    assert_eq!(a, b);
    assert_ne!(a, [0_u8; 32]);
}
