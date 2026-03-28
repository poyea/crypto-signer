/// Raw Solana transaction bytes ready to be signed.
///
/// Solana transactions are signed over the raw message bytes with Ed25519 —
/// no pre-hashing. Build the bytes yourself using the `solana-sdk` or
/// `solana-transaction-status` crates and pass them here.
///
/// # Example
///
/// ```rust,ignore
/// # #[cfg(all(feature = "solana", feature = "hw"))] {
/// use crypto_signer::chains::solana::{sign_transaction, SolanaTxBytes};
/// use crypto_signer::hw::DerivationPath;
///
/// // m/44'/501'/0'/0' — standard Solana derivation path
/// let path = DerivationPath(vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]);
/// let sig = sign_transaction(&ledger, &path, SolanaTxBytes(tx_bytes))?;
/// assert_eq!(sig.0.len(), 64);
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaTxBytes(pub alloc::vec::Vec<u8>);

/// A 64-byte Ed25519 signature over a Solana transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolanaSignature(pub [u8; 64]);

impl TryFrom<alloc::vec::Vec<u8>> for SolanaSignature {
    type Error = alloc::vec::Vec<u8>;

    fn try_from(v: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; 64]>::try_from(v).map(SolanaSignature)
    }
}

/// Sign raw Solana transaction bytes with an Ed25519 hardware wallet.
///
/// The hardware wallet signs the raw bytes directly (no hashing). Returns a
/// [`SolanaSignature`] that must be injected into the transaction before
/// broadcasting.
#[cfg(feature = "hw")]
pub fn sign_transaction<W: crate::hw::HardwareWallet>(
    wallet: &W,
    path: &crate::hw::DerivationPath,
    tx: SolanaTxBytes,
) -> Result<SolanaSignature, SignError<W::Error>> {
    let raw = wallet
        .sign_sol_message(path, &tx.0)
        .map_err(SignError::Wallet)?;
    SolanaSignature::try_from(raw).map_err(|_| SignError::BadSignatureLength)
}

/// Error returned by [`sign_transaction`].
#[cfg(feature = "hw")]
#[derive(Debug)]
pub enum SignError<E: core::fmt::Debug> {
    /// The hardware wallet returned an error.
    Wallet(E),
    /// The wallet returned a signature that was not exactly 64 bytes.
    BadSignatureLength,
}
