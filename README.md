# crypto-signer

[![CI](https://github.com/poyea/crypto-signer/actions/workflows/ci.yml/badge.svg)](https://github.com/poyea/crypto-signer/actions/workflows/ci.yml)
[![Coverage >= 90%](https://img.shields.io/badge/coverage-%3E%3D90%25-brightgreen)](https://github.com/poyea/crypto-signer/actions/workflows/ci.yml)
[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-orange)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/poyea/crypto-signer/blob/main/LICENSE)

High-performance, low-latency, lightweight multi-chain signing primitives in Rust.

## Feature Flags

- `evm`: EIP-712 domain/message signing primitives
- `bitcoin`: Bitcoin module stubs
- `solana`: Solana module stubs
- `cosmos`: Cosmos SignDoc protobuf encoding and SHA-256 signing hash
- `kms`: KMS backend extension point
- `hw`: hardware wallet extension point
- `k256-signer`: local secp256k1 signer backend
- `ed25519-signer`: local Ed25519 signer backend
- `serde`: serde derives
- `std`: standard library support

Default features: `std`, `evm`, `k256-signer`.

## Specs & Standards

All implementations are spec-driven and validated against official test vectors:

- **EIP-712**: [Official Mail example](https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js)
- **EIP-2612**: Permit typehash constant verified against reference implementations
- **Cosmos**: Protobuf SignDoc SHA-256 signing as per Tendermint/Cosmos SDK

## Usage

The core pattern is generic and typestate-driven:

- `TypedMessage<T, Unsigned>` for pre-signing
- `TypedMessage<T, Signed>` for post-signing
- `Eip712Type` implemented once per payload type

Each new EIP-712 message requires only a data struct + one trait impl.

## Performance

Benchmarks on modern hardware (LTO + fat codegen):

| Operation | Time |
|-----------|------|
| EIP-712 Permit sign | ~4.7 µs |
| EIP-712 Order sign | ~4.6 µs |

Run locally: `cargo bench --bench eip712 --features evm,k256-signer`

## Quick Start

```rust
use crypto_signer::{Address, Domain, PermitBuilder};

let domain = Domain::new("USDC", "1", 137, Address::new([0x11; 20]));

let _unsigned = PermitBuilder::new(domain)
	.spender(Address::new([0x22; 20]))
	.value(1_000_000)
	.nonce(0)
	.deadline(1_700_000_000);
```

## Quality Gates and Getting Started

CI runs on every push:

- `cargo fmt --check` — code style
- `cargo clippy --all-targets --all-features -- -D warnings` — lint warnings denied
- `cargo test --all-features --all-targets` — all tests with all feature combinations
- `cargo check --no-default-features` — `no_std` compatibility gate
- `cargo bench --bench eip712` — performance regression detection
- `cargo audit` — vulnerability scanning
- `cargo deny check advisories licenses bans sources` — supply chain policy enforcement
- `cargo llvm-cov --all-features --summary-only --fail-under-lines 90` — code coverage floor at 90%

## Buy me a coffee
* ETH/Polygon: 0xCba7FBDe48C6F7A496f7c8304eCB8a813c234C02
* BTC: bc1qf5jenprghcuazckeycx0k3h5hn46a3qetec4m2
* SOL: 9NRLGeyxQA6nJ2b1wkFpJGtQJ7xudFEqthXRKguXzdd4

Thank you!

## LICENSE
MIT
