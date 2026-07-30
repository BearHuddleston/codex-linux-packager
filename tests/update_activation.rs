#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

use codex_linux_packager::update::{ActivationRequest, activate_appimage};
use sha2::{Digest, Sha256};

#[test]
fn atomic_activation_keeps_the_old_appimage_as_a_versioned_rollback() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let current = temporary.path().join("Codex.AppImage");
    let replacement = temporary.path().join(".verified-update");
    let old_bytes = synthetic_appimage(0x11);
    let new_bytes = synthetic_appimage(0x22);
    write_image(&current, &old_bytes, 0o755);
    write_image(&replacement, &new_bytes, 0o600);

    let receipt = activate_appimage(&ActivationRequest {
        current_appimage: current.clone(),
        replacement: replacement.clone(),
        current_version: "26.721.81911".to_owned(),
        current_build: "5973".to_owned(),
        replacement_version: "26.801.10001".to_owned(),
        replacement_build: "6001".to_owned(),
        replacement_sha256: digest(&new_bytes),
        replacement_bytes: u64::try_from(new_bytes.len()).expect("fixture length"),
    })
    .expect("activate verified AppImage");

    let backup = temporary
        .path()
        .join("Codex.AppImage.rollback-26.721.81911-5973");
    assert_eq!(fs::read(&current).expect("active AppImage"), new_bytes);
    assert_eq!(fs::read(&backup).expect("rollback AppImage"), old_bytes);
    assert!(!replacement.exists());
    assert_eq!(
        fs::metadata(&current).expect("active metadata").mode() & 0o7777,
        0o755
    );
    assert_eq!(receipt.current_appimage, current);
    assert_eq!(receipt.rollback_appimage, backup);
    assert_eq!(receipt.replacement_sha256, digest(&new_bytes));
    assert_eq!(receipt.previous_sha256, digest(&old_bytes));
    assert_eq!(
        receipt.commit_primitive,
        "renameat2_RENAME_EXCHANGE_then_no_replace_rollback_publish"
    );
}

#[test]
fn activation_refuses_existing_rollback_and_symlink_substitution_without_changes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let current = temporary.path().join("Codex.AppImage");
    let replacement = temporary.path().join(".verified-update");
    let rollback = temporary
        .path()
        .join("Codex.AppImage.rollback-26.721.81911-5973");
    let old_bytes = synthetic_appimage(0x33);
    let new_bytes = synthetic_appimage(0x44);
    write_image(&current, &old_bytes, 0o755);
    write_image(&replacement, &new_bytes, 0o600);
    fs::write(&rollback, b"caller-owned").expect("existing rollback");

    let request = ActivationRequest {
        current_appimage: current.clone(),
        replacement: replacement.clone(),
        current_version: "26.721.81911".to_owned(),
        current_build: "5973".to_owned(),
        replacement_version: "26.801.10001".to_owned(),
        replacement_build: "6001".to_owned(),
        replacement_sha256: digest(&new_bytes),
        replacement_bytes: u64::try_from(new_bytes.len()).expect("fixture length"),
    };
    assert!(activate_appimage(&request).is_err());
    assert_eq!(fs::read(&current).expect("preserved current"), old_bytes);
    assert_eq!(
        fs::read(&replacement).expect("preserved replacement"),
        new_bytes
    );
    assert_eq!(
        fs::read(&rollback).expect("preserved rollback"),
        b"caller-owned"
    );

    fs::remove_file(&replacement).expect("remove owned test replacement");
    symlink(&current, &replacement).expect("symlink substitution");
    assert!(activate_appimage(&request).is_err());
    assert_eq!(fs::read(&current).expect("preserved after link"), old_bytes);
    assert!(
        fs::symlink_metadata(&replacement)
            .expect("replacement link")
            .file_type()
            .is_symlink()
    );
}

fn write_image(path: &std::path::Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("write synthetic AppImage");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
}

fn synthetic_appimage(marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; 256];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[8..12].copy_from_slice(b"AI\x02\0");
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
