use crate::{Address, Signature};

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
}
