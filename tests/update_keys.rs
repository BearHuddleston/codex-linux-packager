#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::update::generate_update_signing_key;
use sha2::{Digest, Sha256};

#[test]
fn update_key_generation_is_private_no_replace_and_emits_only_public_identity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
        .expect("private directory mode");
    let path = temporary.path().join("release.seed");

    let receipt = generate_update_signing_key(&path).expect("generate update key");
    let metadata = fs::metadata(&path).expect("private key metadata");
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.len(), 32);
    assert!(generate_update_signing_key(&path).is_err());

    let public = BASE64_STANDARD
        .decode(receipt.public_key_base64)
        .expect("public key base64");
    assert_eq!(public.len(), 32);
    assert_eq!(receipt.public_key_sha256, digest(&public));
    assert_eq!(fs::metadata(&path).expect("preserved key").len(), 32);
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
