/// EVM / EIP-712 signing primitives.
///
/// This module provides everything needed to sign structured data on
/// Ethereum-compatible chains:
///
/// - [`Domain`] — EIP-712 domain parameters (name, version, chain ID, contract)
/// - [`NetworkConfig`] — injectable network/contract address presets
/// - [`TypedMessage`] — typestate wrapper that enforces sign-before-use
/// - [`Eip712Type`] — implement this trait on your payload struct to make it signable
/// - [`messages`] — built-in [`Permit`](messages::Permit) and [`Order`](messages::Order) payloads
/// - [`abi`] — low-level ABI encoding helpers used by payload impls
pub mod abi;
pub mod domain;
pub mod eip712;
pub mod messages;
pub mod network;

pub use domain::Domain;
pub use eip712::{Eip712Type, Signed, TypedMessage, Unsigned};
pub use network::NetworkConfig;

use sha3::{Digest, Keccak256};

/// Compute the Keccak-256 digest of `input`.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    hash
}

/// Compute the EIP-712 typed-data digest:
/// `keccak256("\x19\x01" ‖ domainSeparator ‖ structHash)`.
///
/// This is the 32-byte value that gets signed by the private key.
pub fn eip712_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 66];
    encoded[0] = 0x19;
    encoded[1] = 0x01;
    encoded[2..34].copy_from_slice(&domain_separator);
    encoded[34..66].copy_from_slice(&struct_hash);
    keccak256(&encoded)
}

/// Error returned by [`recover_signer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// The `v` byte was not `27` or `28`.
    InvalidRecoveryId,
    /// The `r` / `s` bytes are not a valid secp256k1 signature.
    InvalidSignature,
    /// Public key recovery failed (e.g. the digest / signature pair is inconsistent).
    RecoveryFailed,
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRecoveryId => f.write_str("v must be 27 or 28"),
            Self::InvalidSignature => f.write_str("r/s are not a valid secp256k1 signature"),
            Self::RecoveryFailed => {
                f.write_str("public key recovery failed: digest/signature pair is inconsistent")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoveryError {}

/// Recover the Ethereum address that produced `sig` over `digest`.
///
/// Returns `Ok(address)` when recovery succeeds. Callers can compare the
/// result with `signer.address()` to confirm that a key/config is correct
/// without hitting a live endpoint.
///
/// `sig.v` must be `27` or `28` (Ethereum convention).
///
/// # Example
///
/// ```rust
/// # #[cfg(all(feature = "evm", feature = "k256-signer"))] {
/// use crypto_signer::evm::recover_signer;
/// use crypto_signer::backends::local_k256::LocalK256Signer;
/// use crypto_signer::Signer;
/// use k256::ecdsa::SigningKey;
///
/// let key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
/// let signer = LocalK256Signer::from_signing_key(key);
///
/// let digest = [0xab_u8; 32];
/// let sig = signer.sign_hash(digest).unwrap();
/// let recovered = recover_signer(digest, &sig).unwrap();
/// assert_eq!(recovered, signer.address());
/// # }
/// ```
#[cfg(feature = "k256-signer")]
pub fn recover_signer(
    digest: [u8; 32],
    sig: &crate::Signature,
) -> Result<crate::Address, RecoveryError> {
    use k256::ecdsa::{RecoveryId, Signature as KSignature, VerifyingKey};

    if sig.v != 27 && sig.v != 28 {
        return Err(RecoveryError::InvalidRecoveryId);
    }
    let recid = RecoveryId::from_byte(sig.v - 27).ok_or(RecoveryError::InvalidRecoveryId)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r);
    sig_bytes[32..].copy_from_slice(&sig.s);
    let k_sig =
        KSignature::from_bytes((&sig_bytes).into()).map_err(|_| RecoveryError::InvalidSignature)?;

    let vk = VerifyingKey::recover_from_prehash(&digest, &k_sig, recid)
        .map_err(|_| RecoveryError::RecoveryFailed)?;

    let encoded = vk.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    let hash = keccak256(&pubkey_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(crate::Address::new(addr))
}
