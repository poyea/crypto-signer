use core::fmt;
use core::fmt::Write;

/// A 20-byte Ethereum-style address.
///
/// - [`Display`](fmt::Display) formats as EIP-55 checksummed hex: `0xAbCd...`.
/// - [`Debug`] formats as lowercase hex: `0xabcd...` (useful for log output).
///
/// Implements `serde::{Serialize, Deserialize}` when the `serde` feature is enabled.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Address([u8; 20]);

impl Address {
    /// Construct an address from raw bytes.
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Return the underlying 20 bytes.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        f.write_str("0x")?;
        for byte in self.0 {
            let hi = usize::from(byte >> 4);
            let lo = usize::from(byte & 0x0f);
            f.write_char(char::from(HEX[hi]))?;
            f.write_char(char::from(HEX[lo]))?;
        }
        Ok(())
    }
}

impl fmt::Display for Address {
    /// Formats the address as an EIP-55 checksummed hex string (`0xAbCd…`).
    ///
    /// EIP-55 capitalises each hex letter based on the keccak256 hash of the
    /// lowercase address, ensuring that a single-character typo is detectable
    /// with 99.986 % probability. Some wallets and RPC endpoints reject
    /// non-checksummed addresses; always use `Display` / `to_string()` when
    /// building HTTP headers, JSON fields, or user-facing output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use sha3::{Digest, Keccak256};

        const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

        // 1. Produce the 40-byte lowercase ASCII hex of the address.
        let mut hex_bytes = [0u8; 40];
        for (i, byte) in self.0.iter().enumerate() {
            hex_bytes[2 * i] = HEX_LOWER[usize::from(byte >> 4)];
            hex_bytes[2 * i + 1] = HEX_LOWER[usize::from(byte & 0xf)];
        }

        // 2. Hash the lowercase hex.
        let hash = Keccak256::digest(hex_bytes);

        // 3. Emit checksummed characters.
        f.write_str("0x")?;
        for (i, &c) in hex_bytes.iter().enumerate() {
            // High nibble of hash byte when i is even, low nibble when odd.
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
            if nibble >= 8 {
                f.write_char(char::from(c.to_ascii_uppercase()))?;
            } else {
                f.write_char(char::from(c))?;
            }
        }
        Ok(())
    }
}

/// A recoverable ECDSA signature: recovery byte `v` plus 32-byte components `r` and `s`.
///
/// `v` is `27` or `28` (Ethereum convention). Some protocols use `0`/`1` instead;
/// subtract `27` if needed.
///
/// Implements `serde::{Serialize, Deserialize}` when the `serde` feature is enabled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Signature {
    /// Construct a signature from its components.
    pub const fn new(v: u8, r: [u8; 32], s: [u8; 32]) -> Self {
        Self { v, r, s }
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, Signature};

    #[test]
    fn address_new_and_as_bytes_roundtrip() {
        let input = [0xAB_u8; 20];
        let addr = Address::new(input);
        assert_eq!(addr.as_bytes(), &input);
    }

    #[test]
    fn address_debug_is_lower_hex_prefixed() {
        let addr = Address::new([0xEF; 20]);
        let debug = format!("{addr:?}");
        assert!(debug.starts_with("0x"));
        assert_eq!(debug.len(), 42);
        assert!(debug.chars().skip(2).all(|c| c.is_ascii_hexdigit()));
        assert_eq!(debug, debug.to_ascii_lowercase());
    }

    /// EIP-55 test vectors from https://eips.ethereum.org/EIPS/eip-55
    #[test]
    fn address_display_is_eip55_checksummed() {
        let cases: &[([u8; 20], &str)] = &[
            (
                hex_addr("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                hex_addr("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"),
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                hex_addr("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"),
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                hex_addr("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"),
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];
        for (bytes, expected) in cases {
            let addr = Address::new(*bytes);
            assert_eq!(format!("{addr}"), *expected, "EIP-55 mismatch for {addr:?}");
        }
    }

    fn hex_addr(s: &str) -> [u8; 20] {
        let lower: alloc::string::String = s.to_ascii_lowercase();
        let v = (0..lower.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&lower[i..i + 2], 16).unwrap())
            .collect::<alloc::vec::Vec<_>>();
        v.try_into().unwrap()
    }

    #[test]
    fn signature_constructor_sets_fields() {
        let r = [0x11_u8; 32];
        let s = [0x22_u8; 32];
        let sig = Signature::new(27, r, s);
        assert_eq!(sig.v, 27);
        assert_eq!(sig.r, r);
        assert_eq!(sig.s, s);
    }

    #[cfg(feature = "serde")]
    fn assert_serde<T: serde::Serialize + for<'de> serde::Deserialize<'de>>() {}

    #[cfg(feature = "serde")]
    #[test]
    fn address_and_signature_implement_serde() {
        assert_serde::<Address>();
        assert_serde::<Signature>();
    }
}
