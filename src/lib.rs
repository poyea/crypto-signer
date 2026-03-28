//! # crypto-signer
//!
//! High-performance, low-latency, lightweight multi-chain signing primitives.
//!
//! ## Ethereum / EVM (EIP-712)
//!
//! ```rust
//! # #[cfg(all(feature = "evm", feature = "k256-signer"))] {
//! use crypto_signer::{Address, Domain, PermitBuilder};
//! use crypto_signer::backends::local_k256::LocalK256Signer;
//! use k256::ecdsa::SigningKey;
//!
//! let key = SigningKey::from_bytes(&[0x01; 32].into()).unwrap();
//! let signer = LocalK256Signer::from_signing_key(key);
//!
//! let domain = Domain::new("USDC", "1", 137, Address::new([0x11; 20]));
//! let signed = PermitBuilder::new(domain)
//!     .spender(Address::new([0x22; 20]))
//!     .value(1_000_000)
//!     .nonce(0)
//!     .deadline(1_700_000_000)
//!     .build_and_sign(&signer)
//!     .expect("signing is infallible with a valid key");
//!
//! let (v, r, s) = signed.vrs();
//! assert!(v == 27 || v == 28);
//! # }
//! ```
//!
//! ## Bitcoin (PSBT via hardware wallet)
//!
//! ```rust,ignore
//! # #[cfg(all(feature = "bitcoin", feature = "hw"))] {
//! use crypto_signer::chains::bitcoin::{sign_psbt, PsbtBytes};
//! use crypto_signer::hw::DerivationPath;
//!
//! // m/84'/0'/0'/0/0 — native SegWit
//! let path = DerivationPath(vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0]);
//! let signed_psbt = sign_psbt(&ledger, &path, PsbtBytes(raw_psbt))?;
//! # }
//! ```
//!
//! ## Solana (Ed25519 via hardware wallet)
//!
//! ```rust,ignore
//! # #[cfg(all(feature = "solana", feature = "hw"))] {
//! use crypto_signer::chains::solana::{sign_transaction, SolanaTxBytes};
//! use crypto_signer::hw::DerivationPath;
//!
//! // m/44'/501'/0'/0'
//! let path = DerivationPath(vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]);
//! let sig = sign_transaction(&ledger, &path, SolanaTxBytes(tx_bytes))?;
//! assert_eq!(sig.0.len(), 64);
//! # }
//! ```
//!
//! ## Cosmos (SignDoc SHA-256)
//!
//! ```rust
//! # #[cfg(all(feature = "cosmos", feature = "k256-signer"))] {
//! use crypto_signer::chains::cosmos::SignDoc;
//! use crypto_signer::Signer;
//! use crypto_signer::backends::local_k256::LocalK256Signer;
//! use k256::ecdsa::SigningKey;
//!
//! let key = SigningKey::from_bytes(&[0x02; 32].into()).unwrap();
//! let signer = LocalK256Signer::from_signing_key(key);
//!
//! let doc = SignDoc {
//!     body_bytes: vec![0x0a, 0x01, 0x01],
//!     auth_info_bytes: vec![0x12, 0x01, 0x02],
//!     chain_id: "osmosis-1".to_string(),
//!     account_number: 42,
//!     sequence: 1,
//! };
//!
//! let hash = doc.signing_hash();
//! let signature = signer.sign_hash(hash).expect("valid key");
//! # }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod signer;
pub mod types;

#[cfg(feature = "evm")]
pub mod evm;

pub mod backends;
pub mod chains;

#[cfg(feature = "kms")]
pub mod kms;

#[cfg(feature = "hw")]
pub mod hw;

pub use signer::{BuildError, Signer};
pub use types::{Address, Signature};

#[cfg(feature = "evm")]
pub use evm::{
    domain::Domain,
    eip712::{Eip712Type, Signed, TypedMessage, Unsigned},
    messages::{Order, Permit, PermitBuilder, PermitSignError},
};

#[cfg(feature = "bitcoin")]
pub use chains::bitcoin::PsbtBytes;

#[cfg(feature = "solana")]
pub use chains::solana::{SolanaSignature, SolanaTxBytes};
