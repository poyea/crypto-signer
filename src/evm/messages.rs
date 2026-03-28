use alloc::vec::Vec;

use crate::{evm::abi, BuildError, Signer};

use super::{Domain, Eip712Type, Signed, TypedMessage, Unsigned};

/// Error returned by [`PermitBuilder::build_and_sign`].
#[derive(Debug)]
pub enum PermitSignError<E> {
    /// The builder was missing a required field. Check the inner [`BuildError`] for which one.
    Build(BuildError),
    /// The signing step failed.
    Sign(E),
}

impl<E: core::fmt::Debug> core::fmt::Display for PermitSignError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Build(e) => write!(f, "permit build failed: {e}"),
            Self::Sign(e) => write!(f, "permit sign failed: {e:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for PermitSignError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(e) => Some(e),
            Self::Sign(e) => Some(e),
        }
    }
}

/// EIP-2612 `Permit` payload — gasless ERC-20 approval via signature.
///
/// Encodes as: `keccak256(typeHash ‖ owner ‖ spender ‖ value ‖ nonce ‖ deadline)`.
///
/// Use [`PermitBuilder`] to construct and sign rather than filling fields directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    /// The token owner whose allowance is being set.
    pub owner: crate::Address,
    /// The spender who will receive the allowance.
    pub spender: crate::Address,
    /// Token amount to approve (in the token's base unit).
    pub value: u128,
    /// On-chain nonce of `owner` (prevents replay).
    pub nonce: u64,
    /// Unix timestamp after which the signature is invalid.
    pub deadline: u64,
}

impl Eip712Type for Permit {
    const TYPE_STRING: &'static str =
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

    fn encode_data(&self, out: &mut Vec<u8>) {
        abi::encode_address(out, self.owner);
        abi::encode_address(out, self.spender);
        abi::encode_u128(out, self.value);
        abi::encode_u64(out, self.nonce);
        abi::encode_u64(out, self.deadline);
    }
}

/// EIP-712 `Order` payload for on-chain order-book protocols.
///
/// `side`: `0` = buy, `1` = sell (protocol-defined convention).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// Unique token/asset identifier.
    pub token_id: [u8; 32],
    /// Order price in base units.
    pub price: u128,
    /// Order size in base units.
    pub size: u128,
    /// Order side: `0` = buy, `1` = sell.
    pub side: u8,
    /// Per-user nonce to prevent replay.
    pub nonce: u64,
}

impl Eip712Type for Order {
    const TYPE_STRING: &'static str =
        "Order(uint256 tokenId,uint256 price,uint256 size,uint8 side,uint256 nonce)";

    fn encode_data(&self, out: &mut Vec<u8>) {
        abi::encode_bytes32(out, self.token_id);
        abi::encode_u128(out, self.price);
        abi::encode_u128(out, self.size);
        abi::encode_u8(out, self.side);
        abi::encode_u64(out, self.nonce);
    }
}

/// Builder for an EIP-2612 [`Permit`] message.
///
/// Set all required fields then call [`build`](PermitBuilder::build) (returns
/// an unsigned message) or [`build_and_sign`](PermitBuilder::build_and_sign)
/// (builds and signs in one step).
///
/// The `owner` field is derived from the signer's address automatically.
///
/// # Errors
///
/// [`build`](PermitBuilder::build) and [`build_and_sign`](PermitBuilder::build_and_sign)
/// return an error if any required field is missing.
#[derive(Clone, Debug)]
pub struct PermitBuilder {
    domain: Domain,
    spender: Option<crate::Address>,
    value: Option<u128>,
    nonce: Option<u64>,
    deadline: Option<u64>,
}

impl PermitBuilder {
    /// Create a new builder for the given EIP-712 domain.
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            spender: None,
            value: None,
            nonce: None,
            deadline: None,
        }
    }

    /// Set the spender address.
    pub fn spender(mut self, spender: crate::Address) -> Self {
        self.spender = Some(spender);
        self
    }

    /// Set the token amount to approve.
    pub fn value(mut self, value: u128) -> Self {
        self.value = Some(value);
        self
    }

    /// Set the owner's on-chain nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Set the Unix timestamp deadline.
    pub fn deadline(mut self, deadline: u64) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Build the unsigned [`Permit`] message, deriving `owner` from `signer.address()`.
    ///
    /// Call `.sign(signer)` on the result to produce a signed message.
    pub fn build<S: Signer>(
        self,
        signer: &S,
    ) -> Result<TypedMessage<Permit, Unsigned>, BuildError> {
        let payload = Permit {
            owner: signer.address(),
            spender: self.spender.ok_or(BuildError::MissingSpender)?,
            value: self.value.ok_or(BuildError::MissingValue)?,
            nonce: self.nonce.ok_or(BuildError::MissingNonce)?,
            deadline: self.deadline.ok_or(BuildError::MissingDeadline)?,
        };
        Ok(TypedMessage::new(self.domain, payload))
    }

    /// Build and sign in one step.
    ///
    /// Equivalent to calling `.build(signer)?.sign(signer)` but without
    /// requiring the caller to chain two separate `Result`s.
    pub fn build_and_sign<S: Signer>(
        self,
        signer: &S,
    ) -> Result<TypedMessage<Permit, Signed>, PermitSignError<S::Error>> {
        self.build(signer)
            .map_err(PermitSignError::Build)?
            .sign(signer)
            .map_err(PermitSignError::Sign)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{Domain, Eip712Type, Order, Permit, PermitBuilder};
    use crate::{Address, BuildError, Signature, Signer};

    #[derive(Clone, Copy)]
    struct DummySigner(Address);

    impl Signer for DummySigner {
        type Error = core::convert::Infallible;

        fn address(&self) -> Address {
            self.0
        }

        fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
            Ok(Signature::new(27, hash, hash))
        }
    }

    fn domain() -> Domain {
        Domain::new("USDC", "1", 1, Address::new([0x99; 20]))
    }

    #[test]
    fn permit_and_order_encode_expected_word_count() {
        let permit = Permit {
            owner: Address::new([0x01; 20]),
            spender: Address::new([0x02; 20]),
            value: 1,
            nonce: 2,
            deadline: 3,
        };
        let mut permit_encoded = Vec::new();
        permit.encode_data(&mut permit_encoded);
        assert_eq!(permit_encoded.len(), 32 * 5);

        let order = Order {
            token_id: [0xAB; 32],
            price: 1,
            size: 2,
            side: 1,
            nonce: 3,
        };
        let mut order_encoded = Vec::new();
        order.encode_data(&mut order_encoded);
        assert_eq!(order_encoded.len(), 32 * 5);
    }

    #[test]
    fn build_and_sign_convenience_works() {
        let signer = DummySigner(Address::new([0xAA; 20]));
        let signed = PermitBuilder::new(domain())
            .spender(Address::new([0xBB; 20]))
            .value(500)
            .nonce(0)
            .deadline(9_999_999)
            .build_and_sign(&signer)
            .expect("build_and_sign should succeed");
        let (v, r, _s) = signed.vrs();
        assert_eq!(v, 27);
        assert_ne!(r, [0_u8; 32]);
    }

    #[test]
    fn build_and_sign_propagates_build_error() {
        use super::PermitSignError;
        let signer = DummySigner(Address::new([0xCC; 20]));
        let err = PermitBuilder::new(domain())
            .build_and_sign(&signer)
            .unwrap_err();
        assert!(matches!(err, PermitSignError::Build(_)));
    }

    #[test]
    fn permit_builder_reports_missing_fields() {
        let signer = DummySigner(Address::new([0xAA; 20]));

        let err = match PermitBuilder::new(domain()).build(&signer) {
            Err(e) => e,
            Ok(_) => panic!("expected MissingSpender"),
        };
        assert_eq!(err, BuildError::MissingSpender);

        let err = match PermitBuilder::new(domain())
            .spender(Address::new([0xBB; 20]))
            .build(&signer)
        {
            Err(e) => e,
            Ok(_) => panic!("expected MissingValue"),
        };
        assert_eq!(err, BuildError::MissingValue);

        let err = match PermitBuilder::new(domain())
            .spender(Address::new([0xBB; 20]))
            .value(10)
            .build(&signer)
        {
            Err(e) => e,
            Ok(_) => panic!("expected MissingNonce"),
        };
        assert_eq!(err, BuildError::MissingNonce);

        let err = match PermitBuilder::new(domain())
            .spender(Address::new([0xBB; 20]))
            .value(10)
            .nonce(1)
            .build(&signer)
        {
            Err(e) => e,
            Ok(_) => panic!("expected MissingDeadline"),
        };
        assert_eq!(err, BuildError::MissingDeadline);
    }
}
