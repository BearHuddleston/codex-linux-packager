//! Deterministic AppDir construction from one independently pinned runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::extract::{ExtractionError, TreePublisher};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::runtime::{RuntimeInventoryEntry, RuntimeManifest, classify_binary};

const MAX_RUNTIME_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RUNTIME_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RUNTIME_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RUNTIME_ENTRIES: usize = 20_000;
const PUBLICATION_SCOPE: &str = "bytes_at_durable_commit_boundary_under_documented_threat_model";
const RUNTIME_PREFIX: &str = "usr/lib/codex-desktop";
pub(crate) const APPDIR_MANIFEST_PATH: &str = "usr/share/codex-linux-packager/appdir-manifest.json";
const RUNTIME_MANIFEST_PATH: &str = "usr/share/codex-linux-packager/runtime-manifest.json";

const APP_RUN: &str = r#"#!/bin/sh
set -eu

if [ -n "${APPDIR:-}" ]; then
    app_root=$APPDIR
else
    app_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
fi

program=$app_root/usr/lib/codex-desktop/codex-desktop
case "${CODEX_LINUX_DISPLAY_BACKEND:-auto}" in
    auto)
        exec "$program" --disable-setuid-sandbox "$@"
        ;;
    wayland)
        exec "$program" --disable-setuid-sandbox --ozone-platform=wayland "$@"
        ;;
    x11)
        exec "$program" --disable-setuid-sandbox --ozone-platform=x11 "$@"
        ;;
    *)
        echo "CODEX_LINUX_DISPLAY_BACKEND must be auto, wayland, or x11" >&2
        exit 64
        ;;
esac
"#;

const DESKTOP_ENTRY: &str = r#"[Desktop Entry]
Type=Application
Version=1.0
Name=Codex Desktop (Unofficial)
Comment=Unofficial and unaffiliated Linux packaging test
Exec=codex-linux-packager %U
Terminal=false
Categories=Development;
MimeType=x-scheme-handler/codex;
StartupWMClass=Codex
Icon=codex-linux-packager
X-AppImage-Name=Codex Desktop (Unofficial)
"#;

const GENERIC_ICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <metadata>Original generic terminal icon, MIT licensed with codex-linux-packager; no OpenAI branding.</metadata>
  <rect x="16" y="28" width="224" height="200" rx="24" fill="#20242b"/>
  <rect x="30" y="54" width="196" height="156" rx="8" fill="#f2f4f7"/>
  <path d="M62 94l38 34-38 34" fill="none" stroke="#20242b" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M120 168h66" fill="none" stroke="#20242b" stroke-width="14" stroke-linecap="round"/>
</svg>
"##;

/// Inputs for one deterministic no-replace AppDir generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDirRequest {
    /// Published runtime generation.
    pub runtime: PathBuf,
    /// Independently recorded SHA-256 of `runtime/manifest.json`.
    pub runtime_manifest_sha256: String,
    /// New AppDir path.
    pub output: PathBuf,
    /// Explicit normalized timestamp for every file and directory.
    pub source_date_epoch: i64,
}

/// One complete AppDir file, excluding the self-referential AppDir manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppDirEntry {
    /// Path within the AppDir.
    pub path: String,
    /// Origin within the runtime, or a stable generated-input label.
    pub source: String,
    /// Exact SHA-256.
    pub sha256: String,
    /// Exact bytes.
    pub bytes: u64,
    /// Normalized mode.
    pub mode: String,
}

/// Deterministic AppDir provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppDirManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Truthful publication guarantee scope.
    pub publication_scope: String,
    /// Independently supplied runtime manifest digest.
    pub runtime_manifest_sha256: String,
    /// Timestamp applied to the complete tree.
    pub source_date_epoch: i64,
    /// Runtime executable name chosen so Electron reports packaged mode.
    pub packaged_executable: String,
    /// Display policy exposed by `AppRun`.
    pub display_backend_policy: String,
    /// Chromium sandbox policy.
    pub sandbox_policy: String,
    /// Identity and redistribution disclaimer.
    pub identity_notice: String,
    /// License for the generated generic icon.
    pub icon_license: String,
    /// Complete sorted file inventory, excluding this manifest.
    pub entries: Vec<AppDirEntry>,
}

/// Runtime validation, AppDir construction, or no-replace publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppDirError {
    /// Request or runtime generation is invalid.
    #[error("invalid AppDir input: {0}")]
    Input(String),
    /// Private tree construction failed.
    #[error("AppDir transaction failed: {0}")]
    Transaction(String),
    /// No-replace publication failed before commit.
    #[error("AppDir publication failed before commit: {0}")]
    Publication(String),
    /// The name committed but parent durability is uncertain.
    #[error("AppDir committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

/// Independently validates a runtime generation and publishes an AppDir.
pub fn build_appdir(request: &AppDirRequest) -> Result<AppDirManifest, AppDirError> {
    validate_request(request)?;
    let manifest_bytes = read_relative_regular(
        &request.runtime,
        "manifest.json",
        MAX_RUNTIME_MANIFEST_BYTES,
        0o644,
    )?;
    verify_sha256(
        &manifest_bytes,
        &request.runtime_manifest_sha256,
        "independently pinned runtime manifest",
    )?;
    let runtime_manifest: RuntimeManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| AppDirError::Input(format!("parse runtime manifest: {error}")))?;
    let canonical = to_json_line(&runtime_manifest)
        .map_err(|error| AppDirError::Input(format!("canonicalize runtime manifest: {error}")))?;
    if canonical.as_bytes() != manifest_bytes {
        return Err(AppDirError::Input(
            "runtime manifest is not canonical schema-1 JSON".to_owned(),
        ));
    }
    let included = validate_runtime_manifest(&runtime_manifest)?;
    let expected_files: BTreeSet<String> = included
        .keys()
        .cloned()
        .chain(std::iter::once("manifest.json".to_owned()))
        .collect();
    validate_exact_tree(&request.runtime, &expected_files, None, false)?;

    let mut publisher = TreePublisher::new(&request.output)
        .map_err(|error| AppDirError::Transaction(error.to_string()))?;
    let mut entries = Vec::with_capacity(included.len().saturating_add(5));
    let build = (|| -> Result<(), AppDirError> {
        for (source_path, entry) in &included {
            let content = read_relative_regular(
                &request.runtime,
                source_path,
                MAX_RUNTIME_FILE_BYTES,
                parse_mode(entry.mode.as_deref())?,
            )?;
            verify_entry(&content, entry)?;
            let output_path = runtime_output_path(source_path);
            let mode = parse_mode(entry.mode.as_deref())?;
            publisher
                .write_file(&output_path, &content, mode)
                .map_err(|error| AppDirError::Transaction(error.to_string()))?;
            entries.push(appdir_entry(
                &output_path,
                &format!("runtime:{source_path}"),
                &content,
                mode,
            )?);
        }
        publisher
            .write_file(RUNTIME_MANIFEST_PATH, &manifest_bytes, 0o644)
            .map_err(|error| AppDirError::Transaction(error.to_string()))?;
        entries.push(appdir_entry(
            RUNTIME_MANIFEST_PATH,
            "runtime:manifest.json",
            &manifest_bytes,
            0o644,
        )?);
        for (path, source, bytes, mode) in [
            (
                ".DirIcon",
                "generated:generic-mit-icon-v1-appimagetool-regular-diricon",
                GENERIC_ICON.as_bytes(),
                0o644,
            ),
            ("AppRun", "generated:app-run-v1", APP_RUN.as_bytes(), 0o755),
            (
                "codex-linux-packager.desktop",
                "generated:desktop-entry-v1",
                DESKTOP_ENTRY.as_bytes(),
                0o644,
            ),
            (
                "codex-linux-packager.svg",
                "generated:generic-mit-icon-v1",
                GENERIC_ICON.as_bytes(),
                0o644,
            ),
        ] {
            publisher
                .write_file(path, bytes, mode)
                .map_err(|error| AppDirError::Transaction(error.to_string()))?;
            entries.push(appdir_entry(path, source, bytes, mode)?);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let appdir_manifest = manifest_document(request, entries.clone());
        let encoded = to_json_line(&appdir_manifest).map_err(|error| {
            AppDirError::Transaction(format!("encode AppDir manifest: {error}"))
        })?;
        publisher
            .write_file(APPDIR_MANIFEST_PATH, encoded.as_bytes(), 0o644)
            .map_err(|error| AppDirError::Transaction(error.to_string()))?;
        publisher
            .normalize_timestamps(request.source_date_epoch)
            .map_err(|error| AppDirError::Transaction(error.to_string()))?;
        Ok(())
    })();
    if let Err(error) = build {
        return Err(cleanup_error(&mut publisher, error));
    }

    let manifest = manifest_document(request, entries);
    match publisher.commit() {
        Ok(()) => Ok(manifest),
        Err(ExtractionError::PostCommitDurability(message)) => {
            Err(AppDirError::PostCommitDurability(message))
        }
        Err(error) => Err(cleanup_error(
            &mut publisher,
            AppDirError::Publication(error.to_string()),
        )),
    }
}

pub(crate) fn validate_appdir_generation(
    root: &Path,
    expected_manifest_sha256: &str,
) -> Result<AppDirManifest, AppDirError> {
    validate_appdir_generation_with_root_policy(root, expected_manifest_sha256, true)
}

pub(crate) fn validate_extracted_appdir_generation(
    root: &Path,
    expected_manifest_sha256: &str,
) -> Result<AppDirManifest, AppDirError> {
    validate_appdir_generation_with_root_policy(root, expected_manifest_sha256, false)
}

fn validate_appdir_generation_with_root_policy(
    root: &Path,
    expected_manifest_sha256: &str,
    require_directory_timestamps: bool,
) -> Result<AppDirManifest, AppDirError> {
    if !root.is_absolute() {
        return Err(AppDirError::Input(
            "AppDir path must be absolute".to_owned(),
        ));
    }
    validate_digest(expected_manifest_sha256, "AppDir manifest")?;
    let manifest_bytes = read_relative_regular(
        root,
        APPDIR_MANIFEST_PATH,
        MAX_RUNTIME_MANIFEST_BYTES,
        0o644,
    )?;
    verify_sha256(
        &manifest_bytes,
        expected_manifest_sha256,
        "independently pinned AppDir manifest",
    )?;
    let manifest: AppDirManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| AppDirError::Input(format!("parse AppDir manifest: {error}")))?;
    let canonical = to_json_line(&manifest)
        .map_err(|error| AppDirError::Input(format!("canonicalize AppDir manifest: {error}")))?;
    if canonical.as_bytes() != manifest_bytes {
        return Err(AppDirError::Input(
            "AppDir manifest is not canonical schema-1 JSON".to_owned(),
        ));
    }
    validate_appdir_manifest(&manifest)?;
    let expected_files: BTreeSet<String> = manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .chain(std::iter::once(APPDIR_MANIFEST_PATH.to_owned()))
        .collect();
    validate_exact_tree(
        root,
        &expected_files,
        Some(manifest.source_date_epoch),
        require_directory_timestamps,
    )?;
    for entry in &manifest.entries {
        let content = read_relative_regular(
            root,
            &entry.path,
            MAX_RUNTIME_FILE_BYTES,
            parse_mode(Some(&entry.mode))?,
        )?;
        let length = u64::try_from(content.len())
            .map_err(|_| AppDirError::Input("AppDir file length does not fit u64".to_owned()))?;
        if length != entry.bytes {
            return Err(AppDirError::Input(format!(
                "AppDir entry {:?} length differs from its manifest",
                entry.path
            )));
        }
        verify_sha256(&content, &entry.sha256, &entry.path)?;
    }
    let launcher = manifest
        .entries
        .iter()
        .find(|entry| entry.path == "AppRun")
        .ok_or_else(|| AppDirError::Input("AppDir has no AppRun entry".to_owned()))?;
    let launcher_bytes =
        read_relative_regular(root, "AppRun", 64 * 1024, parse_mode(Some(&launcher.mode))?)?;
    if contains_bytes(&launcher_bytes, b"--no-sandbox")
        || !contains_bytes(&launcher_bytes, b"CODEX_LINUX_DISPLAY_BACKEND")
        || !contains_bytes(&launcher_bytes, b"--ozone-platform=wayland")
        || !contains_bytes(&launcher_bytes, b"--ozone-platform=x11")
    {
        return Err(AppDirError::Input(
            "AppRun does not preserve sandboxing and explicit display selection".to_owned(),
        ));
    }
    let dir_icon = manifest
        .entries
        .iter()
        .find(|entry| entry.path == ".DirIcon")
        .ok_or_else(|| AppDirError::Input("AppDir has no regular .DirIcon".to_owned()))?;
    let icon = manifest
        .entries
        .iter()
        .find(|entry| entry.path == "codex-linux-packager.svg")
        .ok_or_else(|| AppDirError::Input("AppDir has no generic icon".to_owned()))?;
    if dir_icon.sha256 != icon.sha256 || dir_icon.bytes != icon.bytes {
        return Err(AppDirError::Input(
            "regular .DirIcon differs from the generated generic icon".to_owned(),
        ));
    }
    let runtime_manifest = manifest
        .entries
        .iter()
        .find(|entry| entry.path == RUNTIME_MANIFEST_PATH)
        .ok_or_else(|| AppDirError::Input("AppDir has no embedded runtime manifest".to_owned()))?;
    if runtime_manifest.sha256 != manifest.runtime_manifest_sha256 {
        return Err(AppDirError::Input(
            "embedded runtime manifest digest conflicts with AppDir provenance".to_owned(),
        ));
    }
    Ok(manifest)
}

fn validate_appdir_manifest(manifest: &AppDirManifest) -> Result<(), AppDirError> {
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "linux_x86_64_appdir"
        || manifest.publication_scope != PUBLICATION_SCOPE
        || manifest.packaged_executable != format!("{RUNTIME_PREFIX}/codex-desktop")
        || manifest.display_backend_policy
            != "auto_default_explicit_wayland_or_x11_via_CODEX_LINUX_DISPLAY_BACKEND"
        || manifest.sandbox_policy
            != "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox"
        || manifest.identity_notice
            != "unofficial_and_unaffiliated_tooling_no_payload_redistribution_or_trademark_rights"
        || manifest.icon_license != "original_generic_non_branding_icon_MIT"
    {
        return Err(AppDirError::Input(
            "AppDir manifest identity or policy differs".to_owned(),
        ));
    }
    validate_digest(&manifest.runtime_manifest_sha256, "runtime manifest")?;
    if !(315_532_800..=4_102_444_800).contains(&manifest.source_date_epoch)
        || manifest.entries.is_empty()
        || manifest.entries.len() > MAX_RUNTIME_ENTRIES
    {
        return Err(AppDirError::Input(
            "AppDir timestamp or entry count is outside its bound".to_owned(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for entry in &manifest.entries {
        validate_relative_path(&entry.path)?;
        if previous.is_some_and(|path| entry.path.as_str() <= path)
            || !paths.insert(entry.path.as_str())
        {
            return Err(AppDirError::Input(
                "AppDir inventory is not strictly path-sorted and unique".to_owned(),
            ));
        }
        previous = Some(&entry.path);
        if entry.source.is_empty()
            || entry.source.len() > 4_096
            || !entry.source.is_ascii()
            || entry.bytes > MAX_RUNTIME_FILE_BYTES
        {
            return Err(AppDirError::Input(
                "AppDir entry source or size is invalid".to_owned(),
            ));
        }
        validate_digest(&entry.sha256, "AppDir entry")?;
        parse_mode(Some(&entry.mode))?;
    }
    for required in [
        ".DirIcon",
        "AppRun",
        "codex-linux-packager.desktop",
        "codex-linux-packager.svg",
        "usr/lib/codex-desktop/codex-desktop",
        "usr/lib/codex-desktop/resources/app.asar",
        "usr/lib/codex-desktop/resources/codex",
        "usr/lib/codex-desktop/resources/rg",
        RUNTIME_MANIFEST_PATH,
    ] {
        if !paths.contains(required) {
            return Err(AppDirError::Input(format!(
                "AppDir manifest is missing required path {required:?}"
            )));
        }
    }
    Ok(())
}

fn validate_request(request: &AppDirRequest) -> Result<(), AppDirError> {
    for (label, path) in [("runtime", &request.runtime), ("output", &request.output)] {
        if !path.is_absolute() {
            return Err(AppDirError::Input(format!("{label} path must be absolute")));
        }
    }
    if request.runtime.starts_with(&request.output) || request.output.starts_with(&request.runtime)
    {
        return Err(AppDirError::Input(
            "AppDir output must not alias or contain its runtime input".to_owned(),
        ));
    }
    validate_digest(&request.runtime_manifest_sha256, "runtime manifest")?;
    if !(315_532_800..=4_102_444_800).contains(&request.source_date_epoch) {
        return Err(AppDirError::Input(
            "SOURCE_DATE_EPOCH must be within 1980-01-01..=2100-01-01".to_owned(),
        ));
    }
    Ok(())
}

fn validate_runtime_manifest(
    manifest: &RuntimeManifest,
) -> Result<BTreeMap<String, RuntimeInventoryEntry>, AppDirError> {
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "linux_x86_64_runtime"
        || manifest.publication_scope != PUBLICATION_SCOPE
    {
        return Err(AppDirError::Input(
            "runtime manifest schema, producer, kind, or publication scope differs".to_owned(),
        ));
    }
    for (digest, label) in [
        (&manifest.source_archive_sha256, "source archive"),
        (&manifest.app_asar_sha256, "application ASAR"),
        (&manifest.native_manifest_sha256, "native manifest"),
        (&manifest.electron_zip_sha256, "Electron ZIP"),
        (&manifest.codex_package_sha256, "Codex package"),
    ] {
        validate_digest(digest, label)?;
    }
    for (value, label) in [
        (&manifest.application_version, "application version"),
        (&manifest.application_build, "application build"),
        (&manifest.electron_version, "Electron version"),
        (&manifest.codex_version, "Codex version"),
        (&manifest.ripgrep_version, "ripgrep version"),
    ] {
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(AppDirError::Input(format!(
                "{label} is empty, oversized, or non-ASCII"
            )));
        }
    }
    if manifest.entries.is_empty() || manifest.entries.len() > MAX_RUNTIME_ENTRIES {
        return Err(AppDirError::Input(format!(
            "runtime inventory is outside 1..={MAX_RUNTIME_ENTRIES} entries"
        )));
    }

    let mut included = BTreeMap::new();
    let mut sources = BTreeSet::new();
    let mut previous: Option<(&str, &str)> = None;
    let mut total = 0_u64;
    for entry in &manifest.entries {
        validate_relative_path(&entry.source_path)?;
        if let Some((previous_source, previous_path)) = previous {
            if (entry.source.as_str(), entry.source_path.as_str())
                <= (previous_source, previous_path)
            {
                return Err(AppDirError::Input(
                    "runtime inventory is not strictly source/path sorted".to_owned(),
                ));
            }
        }
        previous = Some((&entry.source, &entry.source_path));
        if entry.source.is_empty()
            || entry.source.len() > 128
            || !entry.source.is_ascii()
            || !sources.insert((entry.source.as_str(), entry.source_path.as_str()))
        {
            return Err(AppDirError::Input(
                "runtime inventory has an invalid or duplicate source".to_owned(),
            ));
        }
        validate_digest(&entry.sha256, "runtime entry")?;
        if entry.bytes > MAX_RUNTIME_FILE_BYTES {
            return Err(AppDirError::Input(
                "runtime entry exceeds its per-file bound".to_owned(),
            ));
        }
        match (&entry.output_path, &entry.mode, entry.disposition.as_str()) {
            (Some(path), Some(mode), "included") => {
                validate_relative_path(path)?;
                parse_mode(Some(mode))?;
                if entry.format != "elf_x86_64" && mode == "0755" {
                    return Err(AppDirError::Input(
                        "runtime executable is not declared Linux x86_64 ELF".to_owned(),
                    ));
                }
                if matches!(entry.format.as_str(), "macho" | "elf_foreign" | "pe")
                    || entry.format.starts_with("elf_foreign_machine_")
                    || entry.format.starts_with("pe_machine_")
                {
                    return Err(AppDirError::Input(
                        "runtime includes foreign executable content".to_owned(),
                    ));
                }
                total = total.checked_add(entry.bytes).ok_or_else(|| {
                    AppDirError::Input("runtime included-byte sum overflowed".to_owned())
                })?;
                if total > MAX_RUNTIME_TOTAL_BYTES {
                    return Err(AppDirError::Input(format!(
                        "runtime exceeds {MAX_RUNTIME_TOTAL_BYTES} included bytes"
                    )));
                }
                if included.insert(path.clone(), entry.clone()).is_some() {
                    return Err(AppDirError::Input(
                        "runtime inventory has a duplicate output path".to_owned(),
                    ));
                }
            }
            (None, None, disposition) if disposition != "included" && !disposition.is_empty() => {}
            _ => {
                return Err(AppDirError::Input(
                    "runtime entry disposition conflicts with its output".to_owned(),
                ));
            }
        }
    }
    for required in [
        "electron",
        "resources/app.asar",
        "resources/codex",
        "resources/codex-code-mode-host",
        "resources/rg",
        "resources/codex-resources/bwrap",
        "resources/app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
        "resources/app.asar.unpacked/node_modules/node-pty/build/Release/pty.node",
    ] {
        if !included.contains_key(required) {
            return Err(AppDirError::Input(format!(
                "runtime is missing required output {required:?}"
            )));
        }
    }
    if included
        .get("resources/app.asar")
        .is_none_or(|entry| entry.sha256 != manifest.app_asar_sha256 || entry.format != "asar")
    {
        return Err(AppDirError::Input(
            "runtime ASAR entry conflicts with its manifest identity".to_owned(),
        ));
    }
    Ok(included)
}

fn verify_entry(content: &[u8], entry: &RuntimeInventoryEntry) -> Result<(), AppDirError> {
    let length = u64::try_from(content.len())
        .map_err(|_| AppDirError::Input("runtime file length does not fit u64".to_owned()))?;
    if length != entry.bytes {
        return Err(AppDirError::Input(format!(
            "runtime file {:?} length differs from its manifest",
            entry.output_path
        )));
    }
    verify_sha256(content, &entry.sha256, "runtime file")?;
    if entry.output_path.as_deref() != Some("resources/app.asar") {
        let detected = classify_binary(content)
            .map_err(|error| AppDirError::Input(format!("classify runtime file: {error}")))?
            .label();
        if detected != entry.format {
            return Err(AppDirError::Input(format!(
                "runtime file {:?} format differs: manifest {:?}, detected {detected:?}",
                entry.output_path, entry.format
            )));
        }
    }
    Ok(())
}

fn runtime_output_path(source: &str) -> String {
    if source == "electron" {
        format!("{RUNTIME_PREFIX}/codex-desktop")
    } else {
        format!("{RUNTIME_PREFIX}/{source}")
    }
}

fn manifest_document(request: &AppDirRequest, entries: Vec<AppDirEntry>) -> AppDirManifest {
    AppDirManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_appdir".to_owned(),
        publication_scope: PUBLICATION_SCOPE.to_owned(),
        runtime_manifest_sha256: request.runtime_manifest_sha256.clone(),
        source_date_epoch: request.source_date_epoch,
        packaged_executable: format!("{RUNTIME_PREFIX}/codex-desktop"),
        display_backend_policy:
            "auto_default_explicit_wayland_or_x11_via_CODEX_LINUX_DISPLAY_BACKEND".to_owned(),
        sandbox_policy: "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox"
            .to_owned(),
        identity_notice:
            "unofficial_and_unaffiliated_tooling_no_payload_redistribution_or_trademark_rights"
                .to_owned(),
        icon_license: "original_generic_non_branding_icon_MIT".to_owned(),
        entries,
    }
}

fn appdir_entry(
    path: &str,
    source: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<AppDirEntry, AppDirError> {
    Ok(AppDirEntry {
        path: path.to_owned(),
        source: source.to_owned(),
        sha256: hex_lower(&Sha256::digest(bytes)),
        bytes: u64::try_from(bytes.len()).map_err(|_| {
            AppDirError::Transaction("AppDir file length does not fit u64".to_owned())
        })?,
        mode: format!("{mode:04o}"),
    })
}

fn validate_exact_tree(
    root: &Path,
    expected: &BTreeSet<String>,
    expected_timestamp: Option<i64>,
    require_directory_timestamps: bool,
) -> Result<(), AppDirError> {
    let root_metadata = std::fs::symlink_metadata(root)
        .map_err(|error| AppDirError::Input(format!("inspect runtime root: {error}")))?;
    if !root_metadata.file_type().is_dir() || root_metadata.permissions().mode() & 0o7777 != 0o755 {
        return Err(AppDirError::Input(
            "runtime root is not a real mode-0755 directory".to_owned(),
        ));
    }
    if require_directory_timestamps {
        validate_timestamp(&root_metadata, expected_timestamp, "runtime/AppDir root")?;
    }
    let mut expected_directories = BTreeSet::new();
    for file in expected {
        let components: Vec<&str> = file.split('/').collect();
        for end in 1..components.len() {
            expected_directories.insert(components[..end].join("/"));
        }
    }
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut stack = vec![(root.to_owned(), String::new(), 0_usize)];
    let mut count = 0_usize;
    while let Some((directory, relative, depth)) = stack.pop() {
        if depth > 64 {
            return Err(AppDirError::Input(
                "runtime directory depth exceeds 64".to_owned(),
            ));
        }
        let mut children = std::fs::read_dir(&directory)
            .map_err(|error| AppDirError::Input(format!("enumerate runtime: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AppDirError::Input(format!("enumerate runtime: {error}")))?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            count = count
                .checked_add(1)
                .ok_or_else(|| AppDirError::Input("runtime inventory overflowed".to_owned()))?;
            if count > MAX_RUNTIME_ENTRIES.saturating_mul(4) {
                return Err(AppDirError::Input(
                    "runtime filesystem exceeds its entry bound".to_owned(),
                ));
            }
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| AppDirError::Input("runtime name is not UTF-8".to_owned()))?;
            validate_component(&name)?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = std::fs::symlink_metadata(child.path()).map_err(|error| {
                AppDirError::Input(format!("inspect runtime {path:?}: {error}"))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(AppDirError::Input("runtime contains a symlink".to_owned()));
            }
            if metadata.file_type().is_dir() {
                if require_directory_timestamps {
                    validate_timestamp(&metadata, expected_timestamp, &path)?;
                }
                if metadata.permissions().mode() & 0o7777 != 0o755 {
                    return Err(AppDirError::Input(format!(
                        "runtime directory {path:?} mode is not 0755"
                    )));
                }
                directories.insert(path.clone());
                stack.push((child.path(), path, depth + 1));
            } else if metadata.file_type().is_file() {
                validate_timestamp(&metadata, expected_timestamp, &path)?;
                files.insert(path);
            } else {
                return Err(AppDirError::Input(
                    "runtime contains a special file".to_owned(),
                ));
            }
        }
    }
    if &files != expected || directories != expected_directories {
        return Err(AppDirError::Input(
            "runtime has missing or unexpected filesystem paths".to_owned(),
        ));
    }
    Ok(())
}

fn validate_timestamp(
    metadata: &std::fs::Metadata,
    expected: Option<i64>,
    label: &str,
) -> Result<(), AppDirError> {
    if let Some(seconds) = expected {
        if metadata.mtime() != seconds || metadata.mtime_nsec() != 0 {
            return Err(AppDirError::Input(format!(
                "{label:?} timestamp is not normalized to SOURCE_DATE_EPOCH"
            )));
        }
    }
    Ok(())
}

fn read_relative_regular(
    root: &Path,
    relative: &str,
    maximum: u64,
    expected_mode: u32,
) -> Result<Vec<u8>, AppDirError> {
    validate_relative_path(relative)?;
    let mut current = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| AppDirError::Input(format!("open {}: {error}", root.display())))?;
    let components: Vec<&str> = relative.split('/').collect();
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| AppDirError::Input("relative file path is empty".to_owned()))?;
    for component in parents {
        current = openat(
            &current,
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            AppDirError::Input(format!("open runtime directory {component:?}: {error}"))
        })?;
    }
    let descriptor = openat(
        &current,
        *name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| AppDirError::Input(format!("open runtime file {relative:?}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| AppDirError::Input(format!("inspect runtime file: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_size < 0
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > maximum)
        || before.st_mode & 0o7777 != expected_mode
    {
        return Err(AppDirError::Input(format!(
            "runtime file {relative:?} has the wrong type, size, or mode"
        )));
    }
    let expected_size = u64::try_from(before.st_size)
        .map_err(|_| AppDirError::Input("runtime size does not fit u64".to_owned()))?;
    let capacity = usize::try_from(expected_size)
        .map_err(|_| AppDirError::Input("runtime size does not fit usize".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(descriptor);
    Read::by_ref(&mut file)
        .take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| AppDirError::Input(format!("read runtime file: {error}")))?;
    if bytes.len() != capacity {
        return Err(AppDirError::Input(
            "runtime file length changed while reading".to_owned(),
        ));
    }
    let after = fstat(&file)
        .map_err(|error| AppDirError::Input(format!("reinspect runtime file: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(AppDirError::Input(
            "runtime file identity changed while reading".to_owned(),
        ));
    }
    Ok(bytes)
}

fn parse_mode(mode: Option<&str>) -> Result<u32, AppDirError> {
    match mode {
        Some("0644") => Ok(0o644),
        Some("0755") => Ok(0o755),
        _ => Err(AppDirError::Input(
            "runtime entry has an invalid mode".to_owned(),
        )),
    }
}

fn validate_relative_path(path: &str) -> Result<(), AppDirError> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || matches!(byte, b'\\' | b':' | 0))
    {
        return Err(AppDirError::Input(
            "path is not bounded safe printable relative ASCII".to_owned(),
        ));
    }
    let mut depth = 0_usize;
    for component in path.split('/') {
        validate_component(component)?;
        depth = depth
            .checked_add(1)
            .ok_or_else(|| AppDirError::Input("path depth overflowed".to_owned()))?;
        if depth > 64 {
            return Err(AppDirError::Input("path exceeds 64 components".to_owned()));
        }
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), AppDirError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > 255
        || component.as_bytes().contains(&0)
    {
        return Err(AppDirError::Input(
            "path contains an unsafe component".to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), AppDirError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppDirError::Input(format!(
            "{label} SHA-256 is not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), AppDirError> {
    if hex_lower(&Sha256::digest(bytes)) != expected {
        return Err(AppDirError::Input(format!(
            "{label} does not match its pinned SHA-256"
        )));
    }
    Ok(())
}

fn cleanup_error(publisher: &mut TreePublisher, original: AppDirError) -> AppDirError {
    match publisher.cleanup() {
        Ok(()) => original,
        Err(cleanup) => AppDirError::Transaction(format!(
            "{original}; private AppDir cleanup was intentionally incomplete: {cleanup}"
        )),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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
