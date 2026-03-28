/// Raw PSBT (Partially Signed Bitcoin Transaction) bytes, as defined in
/// [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki).
///
/// Pass to a [`HardwareWallet`](crate::hw::HardwareWallet) or your own signing backend.
/// The crate does not parse PSBT internally — bring your own parser (e.g.
/// the `bdk` or `bitcoin` crates) and hand the raw bytes here.
///
/// # Example
///
/// ```rust,ignore
/// # #[cfg(all(feature = "bitcoin", feature = "hw"))] {
/// use crypto_signer::chains::bitcoin::{sign_psbt, PsbtBytes};
/// use crypto_signer::hw::DerivationPath;
///
/// // m/84'/0'/0'/0/0 — native SegWit (bech32)
/// let path = DerivationPath(vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0]);
/// let signed = sign_psbt(&ledger, &path, PsbtBytes(raw_psbt_bytes))?;
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbtBytes(pub alloc::vec::Vec<u8>);

/// Sign a PSBT with a hardware wallet and return the signed PSBT bytes.
///
/// The hardware wallet signs each relevant input and returns the updated PSBT
/// with signatures injected. Finalisation into a network-ready transaction is
/// left to the caller (e.g. via the `bitcoin` crate's `Psbt::finalize`).
#[cfg(feature = "hw")]
pub fn sign_psbt<W: crate::hw::HardwareWallet>(
    wallet: &W,
    path: &crate::hw::DerivationPath,
    psbt: PsbtBytes,
) -> Result<PsbtBytes, W::Error> {
    wallet.sign_btc_psbt(path, &psbt.0).map(PsbtBytes)
}
