//! Strict Sparkle-compatible Ed25519 signature verification.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Independently authenticated raw Sparkle public key from the official bundle.
pub const PINNED_SPARKLE_PUBLIC_KEY_BASE64: &str = "mNfr1v9t63BfgDtlw4C8lRvSY6uMggIXABDOCi3tS6k=";

/// SHA-256 fingerprint of the 32 decoded public-key bytes.
pub const PINNED_SPARKLE_PUBLIC_KEY_SHA256: &str =
    "9ffe67dd945eba7930671c7c7f4dbfc84b7ddcebe7618f82f227f1f70ef20058";

/// Machine-readable proof of the signature check that was performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureVerification {
    /// Exact signature algorithm and message semantics.
    pub algorithm: &'static str,
    /// Whether strict verification succeeded.
    pub verified: bool,
    /// Fingerprint of the independently pinned raw public key.
    pub public_key_sha256: String,
}

/// A malformed key/signature or failed cryptographic check.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// Base64 input is malformed, non-canonical, or the wrong length.
    #[error("invalid {0} encoding")]
    Encoding(&'static str),

    /// The compiled key does not match its reviewed fingerprint.
    #[error("compiled Sparkle key fingerprint does not match its pin")]
    KeyFingerprint,

    /// Strict Ed25519 verification failed.
    #[error("Sparkle Ed25519 signature verification failed")]
    Verification,
}

/// Strictly verifies an RFC 8032 Ed25519 signature over the exact supplied
/// message bytes.
pub fn verify_ed25519_bytes(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<(), SignatureError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| SignatureError::Encoding("Ed25519 public key"))?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| SignatureError::Verification)
}

/// Verifies a canonical Sparkle signature over the exact complete artifact
/// bytes using the independently pinned production key.
pub fn verify_pinned_sparkle_signature(
    artifact_bytes: &[u8],
    signature_base64: &str,
) -> Result<SignatureVerification, SignatureError> {
    let public_key =
        decode_canonical::<32>(PINNED_SPARKLE_PUBLIC_KEY_BASE64, "Sparkle public key")?;
    let fingerprint = Sha256::digest(public_key);
    if hex_lower(&fingerprint) != PINNED_SPARKLE_PUBLIC_KEY_SHA256 {
        return Err(SignatureError::KeyFingerprint);
    }
    let signature = decode_canonical::<64>(signature_base64, "Sparkle signature")?;
    verify_ed25519_bytes(artifact_bytes, &signature, &public_key)?;

    Ok(SignatureVerification {
        algorithm: "ed25519-rfc8032-exact-artifact-bytes",
        verified: true,
        public_key_sha256: PINNED_SPARKLE_PUBLIC_KEY_SHA256.to_owned(),
    })
}

fn decode_canonical<const N: usize>(
    encoded: &str,
    label: &'static str,
) -> Result<[u8; N], SignatureError> {
    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| SignatureError::Encoding(label))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| SignatureError::Encoding(label))?;
    if BASE64_STANDARD.encode(decoded) != encoded {
        return Err(SignatureError::Encoding(label));
    }
    Ok(decoded)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
