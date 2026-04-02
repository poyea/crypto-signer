use crate::Address;

/// Injectable network configuration for EVM chains.
///
/// Collects the chain ID and well-known contract addresses for a single
/// deployment environment. Pass this to your domain builder and L2 header
/// helper instead of hardcoding constants, so that staging and mainnet can
/// coexist without forking the crate.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "evm")] {
/// use crypto_signer::evm::NetworkConfig;
///
/// // Use a built-in preset …
/// let mainnet = NetworkConfig::polygon_mainnet();
///
/// // … or construct your own for a custom deployment.
/// use crypto_signer::Address;
/// let custom = NetworkConfig {
///     chain_id: 80001,
///     exchange: Address::new([0xAA; 20]),
///     ctf: Address::new([0xBB; 20]),
///     usdc: Address::new([0xCC; 20]),
///     relayer: Address::new([0xDD; 20]),
/// };
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// EIP-155 chain ID (e.g. `137` for Polygon mainnet, `80001` for Mumbai).
    pub chain_id: u64,
    /// Central limit order-book exchange contract address.
    pub exchange: Address,
    /// Conditional token framework (CTF) contract address.
    pub ctf: Address,
    /// USDC (or bridged USDC.e) token contract address.
    pub usdc: Address,
    /// Relayer contract address used for gasless order submission.
    pub relayer: Address,
}

impl NetworkConfig {
    /// Polygon mainnet preset (chain ID 137).
    ///
    /// Contract addresses are the publicly deployed Polymarket CLOB contracts.
    /// Verify against the official Polymarket documentation before use in
    /// production.
    pub fn polygon_mainnet() -> Self {
        Self {
            chain_id: 137,
            // Polymarket CLOB Exchange
            exchange: Address::new(from_hex("4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E")),
            // Conditional Token Framework
            ctf: Address::new(from_hex("4D97DCd97eC945f40cF65F87097ACe5EA0476045")),
            // Bridged USDC.e on Polygon
            usdc: Address::new(from_hex("2791Bca1f2de4661ED88A30C99A7a9449Aa84174")),
            // Relayer
            relayer: Address::new(from_hex("C5E33Ccd97e3e682B5f8C82Cf8a6Ee98278C1F5b")),
        }
    }

    /// Polygon Mumbai testnet preset (chain ID 80001).
    ///
    /// Use for integration tests and staging environments.
    pub fn polygon_mumbai() -> Self {
        Self {
            chain_id: 80001,
            exchange: Address::new(from_hex("4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E")),
            ctf: Address::new(from_hex("7D8610E9567d2a6C9FBf66a5A13E9Ba8bb120d43")),
            usdc: Address::new(from_hex("2E8DCfE708D44ae2e406a1c02DFE2Fa13012f961")),
            relayer: Address::new(from_hex("C5E33Ccd97e3e682B5f8C82Cf8a6Ee98278C1F5b")),
        }
    }
}

/// Decode a 40-character lowercase (or mixed-case) hex string into 20 bytes.
/// Panics at compile time if the input is not exactly 40 hex chars — used only
/// for the preset constants above.
const fn from_hex(s: &str) -> [u8; 20] {
    let b = s.as_bytes();
    assert!(b.len() == 40, "address must be exactly 40 hex chars");
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}
