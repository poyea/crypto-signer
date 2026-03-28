use crate::{Address, Signature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    MissingSpender,
    MissingValue,
    MissingNonce,
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

pub trait Signer {
    type Error: core::fmt::Debug;

    fn address(&self) -> Address;
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
