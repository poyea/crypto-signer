#![cfg(feature = "evm")]

use crypto_signer::evm::messages::Order;
use crypto_signer::{Address, Domain, PermitBuilder, Signature, Signer, TypedMessage};

#[derive(Clone, Copy)]
struct TestSigner(Address);

impl Signer for TestSigner {
    type Error = core::convert::Infallible;

    fn address(&self) -> Address {
        self.0
    }

    fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
        let mut r = [0_u8; 32];
        let mut s = [0_u8; 32];
        r.copy_from_slice(&hash);
        for (i, b) in hash.iter().enumerate() {
            s[i] = b.wrapping_add(1);
        }
        Ok(Signature::new(27, r, s))
    }
}

fn domain() -> Domain {
    Domain::new("USDC", "1", 137, Address::new([0x11; 20]))
}

#[test]
fn permit_builder_derives_owner() {
    let signer = TestSigner(Address::new([0x22; 20]));
    let unsigned = PermitBuilder::new(domain())
        .spender(Address::new([0x33; 20]))
        .value(1_000_000)
        .nonce(42)
        .deadline(1_700_000_000)
        .build(&signer)
        .expect("permit builds");

    let signed = unsigned.sign(&signer).expect("permit signs");
    let (v, r, s) = signed.vrs();

    assert_eq!(v, 27);
    assert_ne!(r, [0_u8; 32]);
    assert_ne!(s, [0_u8; 32]);
}

#[test]
fn order_generic_message_signs() {
    let signer = TestSigner(Address::new([0x44; 20]));
    let order = Order {
        token_id: [0x55; 32],
        price: 72,
        size: 100,
        side: 0,
        nonce: 7,
    };

    let signed = TypedMessage::new(domain(), order)
        .sign(&signer)
        .expect("order signs");

    let (v, _, _) = signed.vrs();
    assert_eq!(v, 27);
}
