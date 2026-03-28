/// Concrete signer backend implementations.
///
/// - [`local_k256`] — local secp256k1 signer backed by the [`k256`](https://docs.rs/k256) crate.
///   Enabled by the `k256-signer` feature (on by default).
///
/// To use a KMS or hardware wallet instead, implement [`Signer`](crate::Signer) and
/// optionally [`KmsSigner`](crate::kms::KmsSigner) or [`HardwareWallet`](crate::hw::HardwareWallet).
#[cfg(feature = "k256-signer")]
pub mod local_k256;
