#![forbid(unsafe_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::signature::{
    PINNED_SPARKLE_PUBLIC_KEY_BASE64, PINNED_SPARKLE_PUBLIC_KEY_SHA256, verify_ed25519_bytes,
};
use sha2::{Digest, Sha256};

#[test]
fn verifies_the_rfc8032_empty_message_vector_strictly() {
    let public_key: [u8; 32] =
        decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature: [u8; 64] = decode_hex(concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b"
    ));

    verify_ed25519_bytes(b"", &signature, &public_key).expect("RFC 8032 vector must verify");

    let mut mutated = signature;
    mutated[0] ^= 1;
    verify_ed25519_bytes(b"", &mutated, &public_key).expect_err("mutated signature must fail");
}

#[test]
fn production_key_bytes_match_the_reviewed_fingerprint() {
    let key = BASE64_STANDARD
        .decode(PINNED_SPARKLE_PUBLIC_KEY_BASE64)
        .expect("compiled public key must decode");
    let digest = Sha256::digest(key);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(actual, PINNED_SPARKLE_PUBLIC_KEY_SHA256);
}

fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2);
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .expect("test vector must be hexadecimal");
    }
    decoded
}
