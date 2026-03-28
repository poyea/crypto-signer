use crate::{Address, Signature, Signer};
use k256::ecdsa::{RecoveryId, Signature as KSignature, SigningKey};
use sha3::{Digest, Keccak256};

#[derive(Clone)]
pub struct LocalK256Signer {
    key: SigningKey,
    address: Address,
}

impl LocalK256Signer {
    pub fn from_signing_key(key: SigningKey) -> Self {
        let verify = key.verifying_key();
        let encoded = verify.to_encoded_point(false);
        let pubkey = encoded.as_bytes();
        let hash = keccak256(&pubkey[1..]);
        let mut addr = [0_u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Self {
            key,
            address: Address::new(addr),
        }
    }
}

#[derive(Debug)]
pub enum K256SignerError {
    /// The ECDSA signing operation failed. Possible causes: invalid key
    /// material, RNG failure, or internal k256 error.
    SigningFailed,
    /// The signature bytes produced by the backend were malformed and could
    /// not be decoded into (r, s, v) components.
    InvalidSignature,
}

impl core::fmt::Display for K256SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SigningFailed => {
                f.write_str("ecdsa signing failed; verify the key is a valid secp256k1 private key")
            }
            Self::InvalidSignature => f.write_str(
                "signing produced an invalid signature; this is a bug — please report it",
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for K256SignerError {}

impl Signer for LocalK256Signer {
    type Error = K256SignerError;

    fn address(&self) -> Address {
        self.address
    }

    fn sign_hash(&self, hash: [u8; 32]) -> Result<Signature, Self::Error> {
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(&hash)
            .map_err(|_| K256SignerError::SigningFailed)?;

        signature_from_k256(sig, recid)
    }
}

fn signature_from_k256(sig: KSignature, recid: RecoveryId) -> Result<Signature, K256SignerError> {
    let bytes = sig.to_bytes();
    if bytes.len() != 64 {
        return Err(K256SignerError::InvalidSignature);
    }
    let mut r = [0_u8; 32];
    let mut s = [0_u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    let v = recid.to_byte().saturating_add(27);
    Ok(Signature::new(v, r, s))
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&out);
    hash
}

#[cfg(test)]
mod tests {
    use super::LocalK256Signer;
    use crate::Signer;
    use k256::ecdsa::SigningKey;

    #[test]
    fn derives_address_and_signs_hash() {
        let key_bytes = [7_u8; 32];
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).expect("valid private key");
        let signer = LocalK256Signer::from_signing_key(signing_key);

        let address = signer.address();
        assert_ne!(address.as_bytes(), &[0_u8; 20]);

        let hash = [0x55; 32];
        let sig = signer.sign_hash(hash).expect("signing should succeed");
        assert!(sig.v == 27 || sig.v == 28);
        assert_ne!(sig.r, [0_u8; 32]);
        assert_ne!(sig.s, [0_u8; 32]);
    }

    #[test]
    fn error_display_messages_are_descriptive() {
        use super::K256SignerError;
        let msg = K256SignerError::SigningFailed.to_string();
        assert!(msg.contains("secp256k1"), "expected hint in message: {msg}");
        let msg = K256SignerError::InvalidSignature.to_string();
        assert!(
            msg.contains("invalid signature"),
            "expected hint in message: {msg}"
        );
    }
}
