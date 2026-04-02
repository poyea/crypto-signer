use crate::{Address, Signature};

/// Whether the signing account is a plain EOA or a smart-contract wallet.
///
/// Pass this to any builder or header helper that needs to distinguish between
/// the two account models. Using a typed enum instead of a raw integer prevents
/// the Safe/EOA address confusion that causes silent auth failures.
///
/// # Example
///
/// ```rust
/// use crypto_signer::{Address, SignerType};
///
/// // Plain private-key account
/// let eoa = SignerType::Eoa;
///
/// // Gnosis Safe — the Safe contract address must be provided
/// let safe = SignerType::Safe { funder: Address::new([0xAA; 20]) };
///
/// // Determine the address the CLOB should see as the order maker
/// let maker = safe.clob_address(Address::new([0xBB; 20]));
/// assert_eq!(maker, Address::new([0xAA; 20]));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerType {
    /// Plain EOA (`sig_type = 0`).
    ///
    /// The signing key owns the account directly. The signer's own address
    /// is used for all on-chain and API-facing fields.
    Eoa,
    /// Gnosis Safe or other smart-contract wallet (`sig_type = 2`).
    ///
    /// `funder` is the Safe contract address — the entity on whose behalf
    /// orders are placed and whose nonce must be queried.
    Safe {
        /// The Safe contract address (the order maker / API key owner).
        funder: Address,
    },
}

impl SignerType {
    /// Return the sig_type integer used in Polymarket L2 auth headers.
    ///
    /// - `0` for EOA
    /// - `2` for Safe
    pub const fn sig_type(&self) -> u8 {
        match self {
            Self::Eoa => 0,
            Self::Safe { .. } => 2,
        }
    }

    /// Return the address the CLOB should see as the account owner.
    ///
    /// For an EOA this is `signing_address`; for a Safe it is `funder`.
    /// Use this to build `POLY_ADDRESS` headers and to query Safe nonces —
    /// never use the raw signing address for Safe accounts.
    pub fn clob_address(&self, signing_address: Address) -> Address {
        match self {
            Self::Eoa => signing_address,
            Self::Safe { funder } => *funder,
        }
    }
}

/// Error returned when a builder is missing a required field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// No spender address was provided; call `.spender(addr)`.
    MissingSpender,
    /// No token value was provided; call `.value(amount)`.
    MissingValue,
    /// No nonce was provided; call `.nonce(n)`.
    MissingNonce,
    /// No deadline was provided; call `.deadline(unix_ts)`.
    MissingDeadline,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::MissingSpender => "missing spender; call .spender(address) on the builder",
            Self::MissingValue => "missing value; call .value(amount) on the builder",
            Self::MissingNonce => "missing nonce; call .nonce(n) on the builder",
            Self::MissingDeadline => "missing deadline; call .deadline(unix_ts) on the builder",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildError {}

/// Core signing interface.
///
/// Implement this trait on any type that holds a private key — local, KMS-backed,
/// or hardware. The crate provides a ready-made implementation via
/// [`LocalK256Signer`](crate::backends::local_k256::LocalK256Signer).
///
/// A blanket `impl<T: Signer> Signer for &T` is provided so signers can be
/// passed by reference without wrapping.
pub trait Signer {
    /// Error type returned when signing fails.
    type Error: core::fmt::Debug;

    /// Return the Ethereum-style address derived from this signer's public key.
    fn address(&self) -> Address;

    /// Sign a 32-byte pre-hashed digest. Returns a recoverable ECDSA signature.
    fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error>;
}

impl<T: Signer + ?Sized> Signer for &T {
    type Error = T::Error;

    fn address(&self) -> Address {
        (*self).address()
    }

    fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
        (*self).sign_hash(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::{BuildError, Signer};
    use crate::{Address, Signature};

    #[derive(Clone, Copy)]
    struct DummySigner;

    impl Signer for DummySigner {
        type Error = core::convert::Infallible;

        fn address(&self) -> Address {
            Address::new([0x12; 20])
        }

        fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
            Ok(Signature::new(27, hash, hash))
        }
    }

    #[test]
    fn build_error_display_messages() {
        assert!(BuildError::MissingSpender.to_string().contains(".spender("));
        assert!(BuildError::MissingValue.to_string().contains(".value("));
        assert!(BuildError::MissingNonce.to_string().contains(".nonce("));
        assert!(BuildError::MissingDeadline
            .to_string()
            .contains(".deadline("));
    }

    #[test]
    fn signer_reference_blanket_impl_works() {
        let signer = DummySigner;
        let by_ref: &DummySigner = &signer;

        let addr = by_ref.address();
        assert_eq!(addr.as_bytes(), &[0x12; 20]);

        let hash = [0xAA; 32];
        let sig = by_ref.sign_hash(hash).expect("infallible");
        assert_eq!(sig.v, 27);
        assert_eq!(sig.r, hash);
        assert_eq!(sig.s, hash);
    }

    #[test]
    fn signer_type_sig_type_values() {
        assert_eq!(super::SignerType::Eoa.sig_type(), 0);
        assert_eq!(
            super::SignerType::Safe {
                funder: Address::new([0u8; 20])
            }
            .sig_type(),
            2
        );
    }

    #[test]
    fn signer_type_clob_address_eoa_returns_signing_address() {
        let signing = Address::new([0x11; 20]);
        assert_eq!(super::SignerType::Eoa.clob_address(signing), signing);
    }

    #[test]
    fn signer_type_clob_address_safe_returns_funder() {
        let funder = Address::new([0xAA; 20]);
        let signing = Address::new([0xBB; 20]);
        let result = super::SignerType::Safe { funder }.clob_address(signing);
        assert_eq!(result, funder);
        assert_ne!(result, signing);
    }
}
