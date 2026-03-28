/// Multi-chain payload types and signing helpers.
///
/// Each sub-module is gated by its feature flag:
///
/// - [`bitcoin`] (`bitcoin` feature) — [`PsbtBytes`](bitcoin::PsbtBytes) and [`sign_psbt`](bitcoin::sign_psbt)
/// - [`solana`] (`solana` feature) — [`SolanaTxBytes`](solana::SolanaTxBytes), [`SolanaSignature`](solana::SolanaSignature), [`sign_transaction`](solana::sign_transaction)
/// - [`cosmos`] (`cosmos` feature) — [`SignDoc`](cosmos::SignDoc) and SHA-256 signing hash
#[cfg(feature = "bitcoin")]
pub mod bitcoin;

#[cfg(feature = "solana")]
pub mod solana;

#[cfg(feature = "cosmos")]
pub mod cosmos;
