use core::fmt;
use core::fmt::Write;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Address([u8; 20]);

impl Address {
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Signature {
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
