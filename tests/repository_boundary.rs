#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const MAX_TRACKED_FILE_BYTES: u64 = 1_048_576;

#[test]
fn candidate_git_tree_contains_only_auditable_source_material() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let paths = candidate_paths(&root).expect("candidate Git paths should be enumerable");
    assert!(!paths.is_empty(), "candidate Git tree must not be empty");

    let mut violations = Vec::new();
    for relative in paths {
        inspect_candidate(&root, &relative, &mut violations);
    }

    assert!(
        violations.is_empty(),
        "repository-boundary violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn private_key_material_is_detected_independent_of_filename() {
    let disguised_key = format!("-----BEGIN {} KEY-----\nsynthetic\n", "PRIVATE");

    assert_eq!(
        recognized_secret_kind(disguised_key.as_bytes()),
        Some("private-key")
    );
}

fn candidate_paths(root: &Path) -> io::Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(root)
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
        .map(bytes_to_path)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(unix)]
fn bytes_to_path(raw: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;

    PathBuf::from(OsString::from_vec(raw.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_path(raw: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(raw).into_owned())
}

fn inspect_candidate(root: &Path, relative: &Path, violations: &mut Vec<String>) {
    let display = relative.to_string_lossy();
    if !is_safe_relative_path(relative) {
        violations.push(format!("{display}: path is not a safe relative path"));
        return;
    }

    if let Some(reason) = forbidden_path_reason(relative) {
        violations.push(format!("{display}: {reason}"));
    }

    let full_path = root.join(relative);
    let metadata = match fs::symlink_metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A tracked deletion is part of the candidate worktree, not its
            // resulting tree. It disappears once the candidate is committed.
            return;
        }
        Err(error) => {
            violations.push(format!("{display}: cannot inspect metadata: {error}"));
            return;
        }
    };

    if metadata.file_type().is_symlink() {
        violations.push(format!("{display}: symlinks are forbidden"));
        return;
    }
    if !metadata.is_file() {
        violations.push(format!("{display}: only regular files may enter Git"));
        return;
    }
    if metadata.len() > MAX_TRACKED_FILE_BYTES {
        violations.push(format!(
            "{display}: {} bytes exceeds the {}-byte limit",
            metadata.len(),
            MAX_TRACKED_FILE_BYTES
        ));
        return;
    }

    match read_bounded(&full_path) {
        Ok(bytes) => {
            if let Some(kind) = recognized_binary_kind(&bytes) {
                violations.push(format!("{display}: recognized {kind} binary content"));
            } else if let Some(kind) = recognized_secret_kind(&bytes) {
                violations.push(format!("{display}: recognized {kind} material"));
            } else if std::str::from_utf8(&bytes).is_err() {
                violations.push(format!("{display}: tracked files must be UTF-8 text"));
            }
        }
        Err(error) => violations.push(format!("{display}: cannot read file: {error}")),
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn forbidden_path_reason(path: &Path) -> Option<&'static str> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if components
        .iter()
        .any(|component| component == "codex.app" || component == "chatgpt.app")
    {
        return Some("extracted application bundles are forbidden");
    }

    if matches!(
        file_name.as_str(),
        ".env"
            | ".netrc"
            | ".npmrc"
            | ".pypirc"
            | "app.asar"
            | "credentials.json"
            | "id_dsa"
            | "id_ecdsa"
            | "id_ed25519"
            | "id_rsa"
            | "secrets.json"
            | "service-account.json"
    ) || file_name.starts_with(".env.")
    {
        return Some("credential or payload filename is forbidden");
    }

    let extension = path
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    if extension.as_deref().is_some_and(|value| {
        matches!(
            value,
            "7z" | "a"
                | "appimage"
                | "asar"
                | "bin"
                | "class"
                | "deb"
                | "delta"
                | "dll"
                | "dmg"
                | "dylib"
                | "elf"
                | "exe"
                | "gif"
                | "gz"
                | "icns"
                | "ico"
                | "jar"
                | "jpeg"
                | "jpg"
                | "key"
                | "node"
                | "o"
                | "p12"
                | "p8"
                | "pem"
                | "pfx"
                | "pkg"
                | "png"
                | "pyc"
                | "rar"
                | "rpm"
                | "so"
                | "tar"
                | "tbz"
                | "tgz"
                | "wasm"
                | "webp"
                | "xz"
                | "zip"
                | "zst"
                | "zsync"
        )
    }) {
        return Some("archive, binary, credential, or branding extension is forbidden");
    }

    None
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_TRACKED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TRACKED_FILE_BYTES {
        return Err(io::Error::other("file grew beyond repository limit"));
    }
    Ok(bytes)
}

fn recognized_binary_kind(bytes: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"\x7fELF", "ELF"),
        (b"MZ", "PE"),
        (b"\xfe\xed\xfa\xce", "Mach-O"),
        (b"\xfe\xed\xfa\xcf", "Mach-O"),
        (b"\xce\xfa\xed\xfe", "Mach-O"),
        (b"\xcf\xfa\xed\xfe", "Mach-O"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal"),
        (b"!<arch>\n", "ar archive"),
        (b"PK\x03\x04", "ZIP"),
        (b"PK\x05\x06", "ZIP"),
        (b"PK\x07\x08", "ZIP"),
        (b"\x1f\x8b", "gzip"),
        (b"\xfd7zXZ\0", "XZ"),
        (b"\x28\xb5\x2f\xfd", "Zstandard"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"%PDF-", "PDF"),
        (b"\0asm", "WebAssembly"),
    ];

    MAGICS
        .iter()
        .find_map(|(magic, kind)| bytes.starts_with(magic).then_some(*kind))
        .or_else(|| bytes.contains(&0).then_some("NUL-containing"))
}

fn recognized_secret_kind(bytes: &[u8]) -> Option<&'static str> {
    const PREFIX: &[u8] = b"-----BEGIN ";
    const LABELS: &[&[u8]] = &[
        b"PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
        b"PGP PRIVATE KEY BLOCK",
    ];
    const SUFFIX: &[u8] = b"-----";

    LABELS.iter().find_map(|label| {
        let mut marker = Vec::with_capacity(PREFIX.len() + label.len() + SUFFIX.len());
        marker.extend_from_slice(PREFIX);
        marker.extend_from_slice(label);
        marker.extend_from_slice(SUFFIX);
        bytes
            .windows(marker.len())
            .any(|window| window == marker)
            .then_some("private-key")
    })
}
