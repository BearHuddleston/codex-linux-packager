#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use codex_linux_packager::appdir::{AppDirRequest, build_appdir};
use codex_linux_packager::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use codex_linux_packager::runtime::{RuntimeInventoryEntry, RuntimeManifest};
use sha2::{Digest, Sha256};

const EPOCH: i64 = 1_785_308_418;

#[test]
fn appdir_is_deterministic_renames_electron_and_preserves_sandboxing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let runtime = temporary.path().join("runtime");
    let runtime_manifest_sha256 = synthetic_runtime(&runtime);
    let first = temporary.path().join("first.AppDir");
    let second = temporary.path().join("second.AppDir");

    let first_manifest = build_appdir(&AppDirRequest {
        runtime: runtime.clone(),
        runtime_manifest_sha256: runtime_manifest_sha256.clone(),
        output: first.clone(),
        source_date_epoch: EPOCH,
    })
    .expect("first deterministic AppDir");
    let second_manifest = build_appdir(&AppDirRequest {
        runtime,
        runtime_manifest_sha256,
        output: second.clone(),
        source_date_epoch: EPOCH,
    })
    .expect("second deterministic AppDir");

    assert_eq!(first_manifest, second_manifest);
    assert!(!first.join("usr/lib/codex-desktop/electron").exists());
    assert!(first.join("usr/lib/codex-desktop/codex-desktop").is_file());
    assert!(
        first.join(".DirIcon").is_file(),
        "appimagetool must not need to mutate a read-only AppDir"
    );
    assert_eq!(
        fs::read(first.join(".DirIcon")).expect("DirIcon"),
        fs::read(first.join("codex-linux-packager.svg")).expect("generic icon")
    );
    let launcher = fs::read_to_string(first.join("AppRun")).expect("launcher");
    assert!(!launcher.contains("--no-sandbox"));
    assert!(launcher.contains("--disable-setuid-sandbox"));
    assert!(launcher.contains("CODEX_LINUX_DISPLAY_BACKEND"));
    assert!(launcher.contains("--ozone-platform=wayland"));
    assert!(launcher.contains("--ozone-platform=x11"));
    for entry in &first_manifest.entries {
        let left = fs::read(first.join(&entry.path)).expect("first AppDir entry");
        let right = fs::read(second.join(&entry.path)).expect("second AppDir entry");
        assert_eq!(left, right, "content differs for {:?}", entry.path);
        assert_eq!(
            fs::metadata(first.join(&entry.path))
                .expect("entry metadata")
                .mtime(),
            EPOCH,
            "timestamp differs for {:?}",
            entry.path
        );
    }
}

fn synthetic_runtime(root: &Path) -> String {
    fs::create_dir(root).expect("runtime root");
    fs::set_permissions(root, fs::Permissions::from_mode(0o755)).expect("runtime mode");
    let elf = minimal_elf();
    let files = [
        ("electron", elf.as_slice(), 0o755, "elf_x86_64"),
        ("resources/app.asar", b"synthetic-asar", 0o644, "asar"),
        ("resources/codex", elf.as_slice(), 0o755, "elf_x86_64"),
        (
            "resources/codex-code-mode-host",
            elf.as_slice(),
            0o755,
            "elf_x86_64",
        ),
        ("resources/rg", elf.as_slice(), 0o755, "elf_x86_64"),
        (
            "resources/codex-resources/bwrap",
            elf.as_slice(),
            0o755,
            "elf_x86_64",
        ),
        (
            "resources/app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
            elf.as_slice(),
            0o644,
            "elf_x86_64",
        ),
        (
            "resources/app.asar.unpacked/node_modules/node-pty/build/Release/pty.node",
            elf.as_slice(),
            0o644,
            "elf_x86_64",
        ),
    ];
    let mut entries = Vec::new();
    for (index, (path, bytes, mode, format)) in files.iter().enumerate() {
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().expect("file parent")).expect("runtime directory");
        normalize_directory_modes(root, destination.parent().expect("file parent"));
        fs::write(&destination, bytes).expect("runtime file");
        fs::set_permissions(&destination, fs::Permissions::from_mode(*mode))
            .expect("runtime file mode");
        entries.push(RuntimeInventoryEntry {
            source: format!("synthetic_{index:02}"),
            source_path: (*path).to_owned(),
            output_path: Some((*path).to_owned()),
            disposition: "included".to_owned(),
            sha256: digest(bytes),
            bytes: u64::try_from(bytes.len()).expect("fixture length"),
            mode: Some(format!("{mode:04o}")),
            format: (*format).to_owned(),
        });
    }
    entries.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.source_path.cmp(&right.source_path))
    });
    let app_asar_sha256 = entries
        .iter()
        .find(|entry| entry.output_path.as_deref() == Some("resources/app.asar"))
        .expect("ASAR entry")
        .sha256
        .clone();
    let manifest = RuntimeManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_runtime".to_owned(),
        publication_scope: "bytes_at_durable_commit_boundary_under_documented_threat_model"
            .to_owned(),
        application_version: "synthetic-1".to_owned(),
        application_build: "1".to_owned(),
        source_archive_sha256: "11".repeat(32),
        app_asar_sha256,
        native_manifest_sha256: "22".repeat(32),
        electron_zip_sha256: "33".repeat(32),
        codex_package_sha256: "44".repeat(32),
        electron_version: "42.3.0".to_owned(),
        codex_version: "0.146.0-test".to_owned(),
        ripgrep_version: "15.2.0 (synthetic)".to_owned(),
        entries,
    };
    let encoded = to_json_line(&manifest).expect("canonical runtime manifest");
    fs::write(root.join("manifest.json"), encoded.as_bytes()).expect("runtime manifest");
    fs::set_permissions(
        root.join("manifest.json"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("manifest mode");
    digest(encoded.as_bytes())
}

fn normalize_directory_modes(root: &Path, leaf: &Path) {
    let mut current = leaf.to_owned();
    loop {
        fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
            .expect("runtime directory mode");
        if current == root {
            break;
        }
        current = current.parent().expect("directory parent").to_owned();
    }
}

fn minimal_elf() -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
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
