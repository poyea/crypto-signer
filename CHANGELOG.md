# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-28

### Fixed

- EIP-712 typed message signing with `TypedMessage<T, Unsigned|Signed>` typestate
- `Eip712Type` trait for custom payload types
- `PermitBuilder` with `build_and_sign` convenience method and `PermitSignError<E>` error type
- `Order` message type for EIP-712 order signing
- `Domain::new()` constructor; `name` and `version` fields are owned `String`
- Local secp256k1 signer backend via `k256` (`k256-signer` feature)
- `K256SignerError` with `SigningFailed` and `InvalidSignature` variants
- Cosmos `SignDoc` protobuf encoding with SHA-256 signing hash and `sequence` field
- `KmsSigner` extension trait with `key_id`, `provider`, `region`, and `signer_id`
- `HardwareWallet` trait with `DerivationPath` for Ledger/Trezor-style backends
- `serde` feature: `Serialize`/`Deserialize` derives on `Address` and `Signature`
- Feature flags: `evm`, `cosmos`, `bitcoin`, `solana`, `kms`, `hw`, `k256-signer`, `ed25519-signer`, `serde`, `std`
- `no_std` compatible (default features excluded)
- CI: lint, test (stable + beta), benchmarks, coverage ≥ 90%, `cargo audit`, `cargo deny`, fuzz smoke
- Publish workflow: triggered on `v*.*.*` tags, verifies tag matches `Cargo.toml` version
- Use cargo rustc for staticlib to keep no_std check clean


