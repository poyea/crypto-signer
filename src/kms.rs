use alloc::format;
use alloc::string::String;

use crate::Signer;

/// Extension trait for signers backed by a remote Key Management Service.
///
/// Implementors add key-identity methods on top of the core [`Signer`]
/// interface. The private key material never enters application memory;
/// signing happens inside the KMS provider.
///
/// # Example
///
/// ```rust,ignore
/// use crypto_signer::{Address, Signature, Signer};
/// use crypto_signer::kms::KmsSigner;
///
/// struct AwsKmsSigner {
///     key_arn: String,
///     region: String,
///     address: Address,
/// }
///
/// impl Signer for AwsKmsSigner {
///     type Error = Box<dyn core::fmt::Debug>;
///     fn address(&self) -> Address { self.address }
///     fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
///         // Call AWS KMS `Sign` API with algorithm ECDSA_SHA_256.
///         // The KMS returns a DER-encoded signature; decode r/s and set v.
///         todo!()
///     }
/// }
///
/// impl KmsSigner for AwsKmsSigner {
///     fn key_id(&self) -> &str  { &self.key_arn }
///     fn provider(&self) -> &str { "aws" }
///     fn region(&self) -> Option<&str> { Some(&self.region) }
/// }
/// ```
pub trait KmsSigner: Signer {
    /// The provider-specific key identifier (ARN, resource name, key alias, etc.).
    fn key_id(&self) -> &str;

    /// The KMS provider name, e.g. `"aws"`, `"gcp"`, `"azure"`, `"vault"`.
    fn provider(&self) -> &str;

    /// Optional region or zone for the KMS endpoint, e.g. `"us-east-1"`.
    /// Defaults to `None` for providers that do not use regions.
    fn region(&self) -> Option<&str> {
        None
    }

    /// Returns a unique string identifying this signer as `"provider:key_id"`.
    fn signer_id(&self) -> String {
        format!("{}:{}", self.provider(), self.key_id())
    }
}

#[cfg(test)]
mod tests {
    use super::KmsSigner;
    use crate::{Address, Signature, Signer};

    struct DummyKms;

    impl Signer for DummyKms {
        type Error = core::convert::Infallible;

        fn address(&self) -> Address {
            Address::new([0x34; 20])
        }

        fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
            Ok(Signature::new(28, hash, hash))
        }
    }

    impl KmsSigner for DummyKms {
        fn key_id(&self) -> &str {
            "key-123"
        }

        fn provider(&self) -> &str {
            "aws"
        }

        fn region(&self) -> Option<&str> {
            Some("us-east-1")
        }
    }

    #[test]
    fn signer_id_uses_provider_and_key_id() {
        let kms = DummyKms;
        assert_eq!(kms.signer_id(), "aws:key-123");
    }

    #[test]
    fn region_is_accessible() {
        let kms = DummyKms;
        assert_eq!(kms.region(), Some("us-east-1"));
    }

    #[test]
    fn kms_signer_also_behaves_as_signer() {
        let kms = DummyKms;
        let addr = kms.address();
        assert_eq!(addr.as_bytes(), &[0x34; 20]);

        let hash = [0x44; 32];
        let sig = kms.sign_hash(hash).expect("infallible");
        assert_eq!(sig.v, 28);
        assert_eq!(sig.r, hash);
        assert_eq!(sig.s, hash);
    }
}
