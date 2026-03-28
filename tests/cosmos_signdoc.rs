#![cfg(feature = "cosmos")]

use crypto_signer::chains::cosmos::SignDoc;

#[test]
fn cosmos_signdoc_is_deterministic_and_nonempty() {
    let doc = SignDoc {
        body_bytes: vec![0x0a, 0x01, 0x01],
        auth_info_bytes: vec![0x12, 0x01, 0x02],
        chain_id: "osmosis-1".to_string(),
        account_number: 12345,
        sequence: 0,
    };

    let a = doc.to_sign_bytes();
    let b = doc.to_sign_bytes();
    assert_eq!(a, b);
    assert!(!a.is_empty());

    let h1 = doc.signing_hash();
    let h2 = doc.signing_hash();
    assert_eq!(h1, h2);
    assert_ne!(h1, [0_u8; 32]);
}
