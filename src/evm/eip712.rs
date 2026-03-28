use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{Signature, Signer};

use super::{eip712_digest, keccak256, Domain};

/// Marker type for a message that has not yet been signed.
#[derive(Debug)]
pub struct Unsigned;
/// Marker type for a message that has been signed.
#[derive(Debug)]
pub struct Signed;

/// Trait implemented by every EIP-712 structured-data payload.
///
/// Implementing this trait is all that's needed to make a type signable via
/// [`TypedMessage`]. The signing plumbing (`sign()`, `vrs()`, etc.) is
/// provided for free.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "evm")] {
/// use alloc::vec::Vec;
/// use crypto_signer::evm::{abi, Eip712Type};
///
/// pub struct Transfer {
///     pub recipient: crypto_signer::Address,
///     pub amount: u128,
/// }
///
/// impl Eip712Type for Transfer {
///     const TYPE_STRING: &'static str =
///         "Transfer(address recipient,uint256 amount)";
///
///     fn encode_data(&self, out: &mut Vec<u8>) {
///         abi::encode_address(out, self.recipient);
///         abi::encode_u128(out, self.amount);
///     }
/// }
/// # }
/// ```
pub trait Eip712Type {
    const TYPE_STRING: &'static str;

    fn encode_data(&self, out: &mut Vec<u8>);

    fn type_hash() -> [u8; 32] {
        keccak256(Self::TYPE_STRING.as_bytes())
    }

    fn struct_hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(192);
        encoded.extend_from_slice(&Self::type_hash());
        self.encode_data(&mut encoded);
        keccak256(&encoded)
    }
}

#[derive(Clone, Debug)]
pub struct TypedMessage<T, State = Unsigned> {
    pub domain: Domain,
    pub payload: T,
    signature: Option<Signature>,
    _state: PhantomData<State>,
}

impl<T: Eip712Type> TypedMessage<T, Unsigned> {
    pub fn new(domain: Domain, payload: T) -> Self {
        Self {
            domain,
            payload,
            signature: None,
            _state: PhantomData,
        }
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        eip712_digest(self.domain.separator(), self.payload.struct_hash())
    }

    pub fn sign<S: Signer>(self, signer: &S) -> Result<TypedMessage<T, Signed>, S::Error> {
        let signature = signer.sign_hash(self.signing_hash())?;
        Ok(TypedMessage {
            domain: self.domain,
            payload: self.payload,
            signature: Some(signature),
            _state: PhantomData,
        })
    }
}

impl<T: Eip712Type> TypedMessage<T, Signed> {
    pub fn vrs(&self) -> (u8, [u8; 32], [u8; 32]) {
        let signature = self.signature.expect("signature exists on Signed state");
        (signature.v, signature.r, signature.s)
    }

    pub fn signature(&self) -> Signature {
        self.signature.expect("signature exists on Signed state")
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{Domain, Eip712Type, TypedMessage};
    use crate::{Address, Signature, Signer};

    #[derive(Clone, Copy)]
    struct DummySigner;

    impl Signer for DummySigner {
        type Error = core::convert::Infallible;

        fn address(&self) -> Address {
            Address::new([0x01; 20])
        }

        fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
            Ok(Signature::new(27, hash, [0xAB; 32]))
        }
    }

    #[derive(Clone)]
    struct DummyPayload {
        word: [u8; 32],
    }

    impl Eip712Type for DummyPayload {
        const TYPE_STRING: &'static str = "Dummy(bytes32 word)";

        fn encode_data(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.word);
        }
    }

    fn domain() -> Domain {
        Domain::new("Test", "1", 1, Address::new([0x11; 20]))
    }

    #[test]
    fn type_hash_and_struct_hash_are_nonzero() {
        let payload = DummyPayload { word: [0x22; 32] };
        let type_hash = DummyPayload::type_hash();
        let struct_hash = payload.struct_hash();
        assert_ne!(type_hash, [0_u8; 32]);
        assert_ne!(struct_hash, [0_u8; 32]);
    }

    #[test]
    fn signing_and_signature_accessors_work() {
        let payload = DummyPayload { word: [0x33; 32] };
        let unsigned = TypedMessage::new(domain(), payload);
        let hash = unsigned.signing_hash();
        assert_ne!(hash, [0_u8; 32]);

        let signed = unsigned.sign(&DummySigner).expect("infallible sign");
        let sig = signed.signature();
        let (v, r, s) = signed.vrs();

        assert_eq!(v, 27);
        assert_eq!(sig.v, v);
        assert_eq!(sig.r, r);
        assert_eq!(sig.s, s);
    }
}
