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
