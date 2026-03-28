use alloc::vec::Vec;

use crate::{Address, Signature};

/// A BIP-32/BIP-44 derivation path represented as a sequence of child-key indices.
///
/// Standard paths:
/// - Ethereum: `m/44'/60'/0'/0/0` → `[44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 0]`
/// - Solana:   `m/44'/501'/0'/0'` → `[44 | 0x80000000, 501 | 0x80000000, 0x80000000, 0x80000000]`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

/// Trait for hardware wallet backends (Ledger, Trezor, Coldcard, etc.).
///
/// Each method takes a [`DerivationPath`] so the same device can manage
/// keys for multiple chains and accounts simultaneously.
///
/// # Example
///
/// ```rust,ignore
/// use crypto_signer::hw::{DerivationPath, HardwareWallet};
/// use crypto_signer::{Address, Signature};
///
/// struct LedgerDevice { /* HID connection handle */ }
///
/// impl HardwareWallet for LedgerDevice {
///     type Error = LedgerError;
///
///     fn get_address(&self, path: &DerivationPath) -> Result<Address, Self::Error> {
///         // Send APDU `GET_PUBLIC_KEY` command, derive address from response.
///         todo!()
///     }
///
///     fn sign_eth_hash(&self, path: &DerivationPath, hash: [u8; 32])
///         -> Result<Signature, Self::Error>
///     {
///         // Send APDU `SIGN` command with the 32-byte pre-hash.
///         todo!()
///     }
///
///     fn sign_sol_message(&self, path: &DerivationPath, message: &[u8])
///         -> Result<Vec<u8>, Self::Error>
///     {
///         // Ed25519 signature over raw message bytes (no extra hashing).
///         todo!()
///     }
///
///     fn sign_btc_psbt(&self, path: &DerivationPath, psbt: &[u8])
///         -> Result<Vec<u8>, Self::Error>
///     {
///         // Parse BIP-174 PSBT, sign each input, return updated PSBT.
///         todo!()
///     }
/// }
/// ```
pub trait HardwareWallet {
    type Error: core::fmt::Debug;

    /// Return the public address for the given derivation path.
    fn get_address(&self, path: &DerivationPath) -> Result<Address, Self::Error>;

    /// Sign a 32-byte pre-hashed Ethereum digest. Returns an EVM-compatible
    /// recoverable signature (v, r, s).
    fn sign_eth_hash(
        &self,
        path: &DerivationPath,
        hash: [u8; 32],
    ) -> Result<Signature, Self::Error>;

    /// Sign raw Solana message bytes with Ed25519. Returns the 64-byte signature.
    fn sign_sol_message(
        &self,
        path: &DerivationPath,
        message: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Sign a BIP-174 Partially Signed Bitcoin Transaction. Returns the
    /// updated PSBT bytes with the relevant input(s) signed.
    fn sign_btc_psbt(&self, path: &DerivationPath, psbt: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
