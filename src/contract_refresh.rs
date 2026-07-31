//! Authenticated, compatibility-bounded runtime-contract refresh.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, fchmod, fstat, fsync, open, openat, statat, unlinkat,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::ZipArchive;

use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::native::{NativeContract, native_contract, validate_stage_package_contracts};
use crate::runtime::{
    AuthenticatedSourceResource, BinaryFormat, CodexComponentContract, CodexRuntimeContract,
    RipgrepRuntimeContract, RuntimeApplicationContract, RuntimeContract, RuntimeElectronContract,
    RuntimeTarget, classify_binary, read_regular_input, validate_macho_x86_64,
    validate_runtime_contract,
};
use crate::staging::{ValidatedStage, validate_stage};

const MAX_SOURCE_RESOURCE_BYTES: u64 = 384 * 1024 * 1024;
const MAX_CODEX_PACKAGE_BYTES: u64 = 160 * 1024 * 1024;
const MAX_CODEX_COMPONENT_BYTES: u64 = 384 * 1024 * 1024;
const MAX_CODEX_PACKAGE_ENTRIES: usize = 32;
const MAX_CODEX_PACKAGE_UNCOMPRESSED_BYTES: u64 = 768 * 1024 * 1024;

/// One native package identity re-established from the authenticated ASAR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractNativePackage {
    /// Exact npm package name.
    pub name: String,
    /// Exact package version.
    pub version: String,
    /// SHA-256 of the authenticated package metadata.
    pub source_asar_package_json_sha256: String,
}

/// Deterministic facts derived only from one authenticated stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSourceInspection {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Authenticated application identity.
    pub application: RuntimeApplicationContract,
    /// Electron runtime permitted by the unchanged native ABI boundary.
    pub electron: RuntimeElectronContract,
    /// Exact native package identities permitted by that boundary.
    pub native_packages: Vec<ContractNativePackage>,
    /// Codex CLI version embedded in the authenticated foreign executable.
    pub codex_version: String,
    /// ripgrep version embedded in the authenticated foreign executable.
    pub ripgrep_version: String,
    /// Ten-character ripgrep source revision prefix embedded beside the version.
    pub ripgrep_revision_prefix: String,
    /// Exact authenticated foreign-resource identities.
    pub authenticated_source_resources: Vec<AuthenticatedSourceResource>,
}

/// Inputs needed to correlate an authenticated stage with official Linux
/// release components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRefreshRequest {
    /// Authenticated schema-1 stage generation.
    pub stage: PathBuf,
    /// Exact official Codex Linux package archive.
    pub codex_package: PathBuf,
    /// Exact dereferenced 40-character OpenAI Codex release revision.
    pub codex_revision: String,
    /// Exact dereferenced 40-character ripgrep release revision.
    pub ripgrep_revision: String,
    /// New canonical runtime-contract JSON path.
    pub output: PathBuf,
}

/// Authentication, compatibility, archive, or no-replace publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContractRefreshError {
    /// The request shape is invalid.
    #[error("invalid contract refresh request: {0}")]
    Request(String),
    /// The stage does not satisfy the existing native compatibility boundary.
    #[error("unsupported authenticated application change: {0}")]
    Compatibility(String),
    /// A source identity could not be derived unambiguously.
    #[error("invalid authenticated contract source: {0}")]
    Source(String),
    /// The official Linux package does not match its claimed release.
    #[error("invalid official Codex package: {0}")]
    Package(String),
    /// The generated runtime contract is invalid.
    #[error("invalid refreshed runtime contract: {0}")]
    Contract(String),
    /// The new contract could not be durably published without replacement.
    #[error("contract publication failed: {0}")]
    Publication(String),
}

/// Re-authenticates a stage and derives all source-controlled runtime
/// identities without contacting the network.
pub fn inspect_contract_source(
    stage_path: &Path,
) -> Result<ContractSourceInspection, ContractRefreshError> {
    let stage = validate_stage(stage_path)
        .map_err(|error| ContractRefreshError::Source(format!("validate stage: {error}")))?;
    inspect_validated_contract_source(&stage)
}

fn inspect_validated_contract_source(
    stage: &ValidatedStage,
) -> Result<ContractSourceInspection, ContractRefreshError> {
    let native = native_contract().map_err(|error| {
        ContractRefreshError::Compatibility(format!("load native contract: {error}"))
    })?;
    validate_stage_package_contracts(stage, &native).map_err(|error| {
        ContractRefreshError::Compatibility(format!(
            "Electron/native declarations changed: {error}"
        ))
    })?;

    let mut resources = Vec::with_capacity(3);
    let mut codex_version = None;
    let mut ripgrep_identity = None;
    for name in ["codex", "codex-code-mode-host", "rg"] {
        let bytes = read_source_resource(stage, name)?;
        validate_macho_x86_64(&bytes, name)
            .map_err(|error| ContractRefreshError::Source(error.to_string()))?;
        let marker = match name {
            "codex" => {
                let version = derive_codex_version(&bytes)?;
                codex_version = Some(version.clone());
                Some(version)
            }
            "rg" => {
                let (version, revision_prefix, marker) = derive_ripgrep_identity(&bytes)?;
                ripgrep_identity = Some((version, revision_prefix));
                Some(marker)
            }
            _ => None,
        };
        resources.push(AuthenticatedSourceResource {
            name: name.to_owned(),
            sha256: sha256(&bytes),
            bytes: u64::try_from(bytes.len()).map_err(|_| {
                ContractRefreshError::Source("source resource length does not fit u64".to_owned())
            })?,
            format: "macho_x86_64".to_owned(),
            identity_marker: marker,
        });
    }
    let codex_version = codex_version.ok_or_else(|| {
        ContractRefreshError::Source("Codex source identity was not established".to_owned())
    })?;
    let (ripgrep_version, ripgrep_revision_prefix) = ripgrep_identity.ok_or_else(|| {
        ContractRefreshError::Source("ripgrep source identity was not established".to_owned())
    })?;

    Ok(ContractSourceInspection {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "contract_source_inspection".to_owned(),
        application: RuntimeApplicationContract {
            version: stage.provenance.bundle.version.clone(),
            build: stage.provenance.bundle.build.clone(),
            app_asar_sha256: stage.asar.inspection.asar_sha256.clone(),
        },
        electron: RuntimeElectronContract {
            version: native.electron.version.clone(),
            linux_x64_zip_sha256: native.electron.linux_x64_zip_sha256.clone(),
        },
        native_packages: native_packages(&native),
        codex_version,
        ripgrep_version,
        ripgrep_revision_prefix,
        authenticated_source_resources: resources,
    })
}

/// Generates and durably writes a new canonical runtime contract after
/// validating the exact official Linux package.
pub fn refresh_runtime_contract(
    request: &ContractRefreshRequest,
) -> Result<RuntimeContract, ContractRefreshError> {
    validate_request(request)?;
    let inspection = inspect_contract_source(&request.stage)?;
    validate_revision(&request.codex_revision, "Codex revision")?;
    validate_revision(&request.ripgrep_revision, "ripgrep revision")?;
    if !request
        .ripgrep_revision
        .starts_with(&inspection.ripgrep_revision_prefix)
    {
        return Err(ContractRefreshError::Package(
            "ripgrep release revision conflicts with the authenticated source marker".to_owned(),
        ));
    }

    let archive = read_regular_input(&request.codex_package, MAX_CODEX_PACKAGE_BYTES)
        .map_err(|error| ContractRefreshError::Package(error.to_string()))?;
    let components = inspect_codex_package(&archive, &inspection)?;
    let ripgrep_sha256 = components
        .iter()
        .find(|component| component.archive_path == "codex-path/rg")
        .map(|component| component.sha256.clone())
        .ok_or_else(|| ContractRefreshError::Package("package lost ripgrep".to_owned()))?;
    let native = native_contract().map_err(|error| {
        ContractRefreshError::Compatibility(format!("reload native contract: {error}"))
    })?;
    let contract = RuntimeContract {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        target: RuntimeTarget {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
        },
        application: inspection.application,
        electron: inspection.electron,
        codex: CodexRuntimeContract {
            version: inspection.codex_version.clone(),
            release_tag: format!("rust-v{}", inspection.codex_version),
            revision: request.codex_revision.clone(),
            target: "x86_64-unknown-linux-musl".to_owned(),
            package_archive_sha256: sha256(&archive),
            package_archive_bytes: u64::try_from(archive.len()).map_err(|_| {
                ContractRefreshError::Package("package length does not fit u64".to_owned())
            })?,
            components,
        },
        ripgrep: RipgrepRuntimeContract {
            version: inspection.ripgrep_version,
            revision: request.ripgrep_revision.clone(),
            linux_x64_musl_sha256: ripgrep_sha256,
        },
        authenticated_source_resources: inspection.authenticated_source_resources,
    };
    if contract.electron.version != native.electron.version {
        return Err(ContractRefreshError::Compatibility(
            "Electron version crossed the native ABI boundary".to_owned(),
        ));
    }
    validate_runtime_contract(&contract)
        .map_err(|error| ContractRefreshError::Contract(error.to_string()))?;
    let encoded = to_json_line(&contract)
        .map_err(|error| ContractRefreshError::Publication(error.to_string()))?;
    publish_no_replace(&request.output, encoded.as_bytes())?;
    Ok(contract)
}

fn native_packages(native: &NativeContract) -> Vec<ContractNativePackage> {
    native
        .packages
        .iter()
        .map(|package| ContractNativePackage {
            name: package.name.clone(),
            version: package.version.clone(),
            source_asar_package_json_sha256: package.source_asar_package_json_sha256.clone(),
        })
        .collect()
}

fn derive_codex_version(bytes: &[u8]) -> Result<String, ContractRefreshError> {
    const MARKER: &[u8] = b"Welcome to Codex [v";
    let positions = bytes
        .windows(MARKER.len())
        .enumerate()
        .filter_map(|(index, window)| (window == MARKER).then_some(index))
        .collect::<Vec<_>>();
    if positions.len() != 1 {
        return Err(ContractRefreshError::Source(format!(
            "Codex welcome marker occurs {} times instead of once",
            positions.len()
        )));
    }
    let end = positions[0];
    let lower = end.saturating_sub(256);
    let mut candidates = BTreeSet::new();
    let mut cursor = lower;
    while cursor < end {
        while cursor < end
            && !(bytes[cursor].is_ascii_alphanumeric()
                || matches!(bytes[cursor], b'.' | b'-' | b'+'))
        {
            cursor += 1;
        }
        let start = cursor;
        while cursor < end
            && (bytes[cursor].is_ascii_alphanumeric()
                || matches!(bytes[cursor], b'.' | b'-' | b'+'))
        {
            cursor += 1;
        }
        if start == cursor {
            continue;
        }
        let Ok(candidate) = std::str::from_utf8(&bytes[start..cursor]) else {
            continue;
        };
        if candidate.contains('.')
            && candidate.as_bytes()[0].is_ascii_digit()
            && validate_release_identity(candidate, "Codex version").is_ok()
        {
            candidates.insert(candidate.to_owned());
        }
    }
    if candidates.len() != 1 {
        return Err(ContractRefreshError::Source(format!(
            "Codex version near its welcome marker has {} candidates instead of one",
            candidates.len()
        )));
    }
    candidates
        .into_iter()
        .next()
        .ok_or_else(|| ContractRefreshError::Source("Codex version marker is absent".to_owned()))
}

fn derive_ripgrep_identity(bytes: &[u8]) -> Result<(String, String, String), ContractRefreshError> {
    let mut identities = BTreeSet::new();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_digit()
            || start
                .checked_sub(1)
                .and_then(|index| bytes.get(index))
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'.')
        {
            continue;
        }
        let Some((version_end, version)) = dotted_triplet(bytes, start) else {
            continue;
        };
        let Some(revision_end) = version_end.checked_add(10) else {
            continue;
        };
        let Some(revision) = bytes.get(version_end..revision_end) else {
            continue;
        };
        if !revision
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            || bytes
                .get(revision_end)
                .is_some_and(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            continue;
        }
        let Ok(revision) = std::str::from_utf8(revision) else {
            continue;
        };
        identities.insert((version, revision.to_owned()));
    }
    if identities.len() != 1 {
        return Err(ContractRefreshError::Source(format!(
            "ripgrep version/revision marker has {} candidates instead of one",
            identities.len()
        )));
    }
    let (version, revision) = identities
        .into_iter()
        .next()
        .ok_or_else(|| ContractRefreshError::Source("ripgrep marker is absent".to_owned()))?;
    let marker = format!("{version}{revision}");
    Ok((version, revision, marker))
}

fn dotted_triplet(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    let mut cursor = start;
    for component in 0..3 {
        let component_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor = cursor.checked_add(1)?;
        }
        let length = cursor.checked_sub(component_start)?;
        if length == 0 || length > 4 || (length > 1 && bytes.get(component_start) == Some(&b'0')) {
            return None;
        }
        if component < 2 {
            if bytes.get(cursor) != Some(&b'.') {
                return None;
            }
            cursor = cursor.checked_add(1)?;
        }
    }
    let version = std::str::from_utf8(bytes.get(start..cursor)?).ok()?;
    Some((cursor, version.to_owned()))
}

fn read_source_resource(
    stage: &ValidatedStage,
    name: &str,
) -> Result<Vec<u8>, ContractRefreshError> {
    let path = format!("{}/Contents/Resources/{name}", stage.provenance.bundle.root);
    let mut archive = ZipArchive::new(Cursor::new(stage.source_archive.as_slice()))
        .map_err(|error| ContractRefreshError::Source(format!("reopen source ZIP: {error}")))?;
    let mut matching_index = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            ContractRefreshError::Source(format!("enumerate source ZIP: {error}"))
        })?;
        if entry.name_raw() == path.as_bytes() && matching_index.replace(index).is_some() {
            return Err(ContractRefreshError::Source(format!(
                "source ZIP contains duplicate resource {name:?}"
            )));
        }
    }
    let index = matching_index.ok_or_else(|| {
        ContractRefreshError::Source(format!("source ZIP lacks resource {name:?}"))
    })?;
    let mut entry = archive.by_index(index).map_err(|error| {
        ContractRefreshError::Source(format!("open source resource {name:?}: {error}"))
    })?;
    let size = entry.size();
    if entry.is_dir() || entry.is_symlink() || !(1..=MAX_SOURCE_RESOURCE_BYTES).contains(&size) {
        return Err(ContractRefreshError::Source(format!(
            "source resource {name:?} has an invalid type or size"
        )));
    }
    if entry.compressed_size() == 0 || size > entry.compressed_size().saturating_mul(100) {
        return Err(ContractRefreshError::Source(format!(
            "source resource {name:?} exceeds the compression-ratio bound"
        )));
    }
    let capacity = usize::try_from(size)
        .map_err(|_| ContractRefreshError::Source("resource is too large".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut entry)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ContractRefreshError::Source(format!("read source resource {name:?}: {error}"))
        })?;
    if bytes.len() != capacity {
        return Err(ContractRefreshError::Source(format!(
            "source resource {name:?} changed length"
        )));
    }
    Ok(bytes)
}

fn inspect_codex_package(
    bytes: &[u8],
    source: &ContractSourceInspection,
) -> Result<Vec<CodexComponentContract>, ContractRefreshError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|error| {
        ContractRefreshError::Package(format!("parse package archive: {error}"))
    })?;
    let expected_files = supported_component_layout();
    let expected_directories = BTreeSet::from([
        "bin".to_owned(),
        "codex-path".to_owned(),
        "codex-resources".to_owned(),
        "codex-resources/zsh".to_owned(),
        "codex-resources/zsh/bin".to_owned(),
    ]);
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in entries {
        count = count
            .checked_add(1)
            .ok_or_else(|| ContractRefreshError::Package("entry count overflowed".to_owned()))?;
        if count > MAX_CODEX_PACKAGE_ENTRIES {
            return Err(ContractRefreshError::Package(format!(
                "package exceeds {MAX_CODEX_PACKAGE_ENTRIES} entries"
            )));
        }
        let mut entry = entry.map_err(|error| {
            ContractRefreshError::Package(format!("read package entry: {error}"))
        })?;
        let is_directory = entry.header().entry_type().is_dir();
        if !is_directory && !entry.header().entry_type().is_file() {
            return Err(ContractRefreshError::Package(
                "package contains a link or special file".to_owned(),
            ));
        }
        let path = safe_relative_path(&entry.path_bytes())?;
        if is_directory {
            if !directories.insert(path) {
                return Err(ContractRefreshError::Package(
                    "package contains a duplicate directory".to_owned(),
                ));
            }
            continue;
        }
        let layout = expected_files.get(path.as_str()).ok_or_else(|| {
            ContractRefreshError::Package(format!("unexpected package file {path:?}"))
        })?;
        if files.contains_key(&path) {
            return Err(ContractRefreshError::Package(format!(
                "duplicate package file {path:?}"
            )));
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| ContractRefreshError::Package("size sum overflowed".to_owned()))?;
        if size > MAX_CODEX_COMPONENT_BYTES || total > MAX_CODEX_PACKAGE_UNCOMPRESSED_BYTES {
            return Err(ContractRefreshError::Package(
                "package exceeds an uncompressed size bound".to_owned(),
            ));
        }
        let capacity = usize::try_from(size)
            .map_err(|_| ContractRefreshError::Package("component is too large".to_owned()))?;
        let mut content = Vec::with_capacity(capacity);
        Read::by_ref(&mut entry)
            .take(size.saturating_add(1))
            .read_to_end(&mut content)
            .map_err(|error| {
                ContractRefreshError::Package(format!("read component {path:?}: {error}"))
            })?;
        if content.len() != capacity {
            return Err(ContractRefreshError::Package(format!(
                "component {path:?} changed length"
            )));
        }
        validate_package_component(&path, &content, source)?;
        files.insert(
            path.clone(),
            CodexComponentContract {
                archive_path: path,
                runtime_path: layout.0.map(str::to_owned),
                disposition: layout.1.to_owned(),
                sha256: sha256(&content),
                bytes: size,
                mode: layout.2.map(str::to_owned),
            },
        );
    }
    if directories != expected_directories || files.len() != expected_files.len() {
        return Err(ContractRefreshError::Package(
            "package inventory differs from the supported Linux layout".to_owned(),
        ));
    }
    expected_files
        .keys()
        .map(|path| {
            files.remove(*path).ok_or_else(|| {
                ContractRefreshError::Package(format!("package lacks file {path:?}"))
            })
        })
        .collect()
}

type ComponentLayout = (Option<&'static str>, &'static str, Option<&'static str>);

fn supported_component_layout() -> BTreeMap<&'static str, ComponentLayout> {
    BTreeMap::from([
        (
            "bin/codex",
            (Some("resources/codex"), "included", Some("0755")),
        ),
        (
            "bin/codex-code-mode-host",
            (
                Some("resources/codex-code-mode-host"),
                "included",
                Some("0755"),
            ),
        ),
        (
            "codex-package.json",
            (
                Some("resources/codex-package.json"),
                "included",
                Some("0644"),
            ),
        ),
        (
            "codex-path/rg",
            (Some("resources/rg"), "included", Some("0755")),
        ),
        (
            "codex-resources/bwrap",
            (
                Some("resources/codex-resources/bwrap"),
                "included",
                Some("0755"),
            ),
        ),
        (
            "codex-resources/zsh/bin/zsh",
            (None, "omitted_glibc_2_38_optional_zsh", None),
        ),
    ])
}

fn validate_package_component(
    path: &str,
    bytes: &[u8],
    source: &ContractSourceInspection,
) -> Result<(), ContractRefreshError> {
    if path == "codex-package.json" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct Package {
            layout_version: u32,
            version: String,
            target: String,
            variant: String,
            entrypoint: String,
            resources_dir: String,
            path_dir: String,
        }
        let package: Package = serde_json::from_slice(bytes).map_err(|error| {
            ContractRefreshError::Package(format!("parse package metadata: {error}"))
        })?;
        if package.layout_version != 1
            || package.version != source.codex_version
            || package.target != "x86_64-unknown-linux-musl"
            || package.variant != "codex"
            || package.entrypoint != "bin/codex"
            || package.resources_dir != "codex-resources"
            || package.path_dir != "codex-path"
        {
            return Err(ContractRefreshError::Package(
                "package metadata conflicts with the authenticated source".to_owned(),
            ));
        }
        return Ok(());
    }
    if classify_binary(bytes)
        .map_err(|error| ContractRefreshError::Package(format!("classify {path:?}: {error}")))?
        != BinaryFormat::ElfX86_64
    {
        return Err(ContractRefreshError::Package(format!(
            "{path:?} is not Linux x86_64 ELF"
        )));
    }
    let required_marker = match path {
        "bin/codex" => Some(source.codex_version.as_str()),
        "codex-path/rg" => source
            .authenticated_source_resources
            .iter()
            .find(|resource| resource.name == "rg")
            .and_then(|resource| resource.identity_marker.as_deref()),
        _ => None,
    };
    if required_marker.is_some_and(|marker| !contains_bytes(bytes, marker.as_bytes())) {
        return Err(ContractRefreshError::Package(format!(
            "{path:?} lacks the authenticated identity marker"
        )));
    }
    Ok(())
}

fn safe_relative_path(raw: &[u8]) -> Result<String, ContractRefreshError> {
    let value = std::str::from_utf8(raw)
        .map_err(|_| ContractRefreshError::Package("package path is not UTF-8".to_owned()))?
        .strip_suffix('/')
        .unwrap_or_else(|| std::str::from_utf8(raw).unwrap_or_default());
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('/')
        || value
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || matches!(byte, b'\\' | b':' | 0))
        || value.split('/').count() > 64
        || value.split('/').any(|component| {
            component.is_empty() || matches!(component, "." | "..") || component.len() > 255
        })
    {
        return Err(ContractRefreshError::Package(
            "package path is not safe bounded relative ASCII".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn validate_request(request: &ContractRefreshRequest) -> Result<(), ContractRefreshError> {
    for (path, label) in [
        (&request.stage, "stage"),
        (&request.codex_package, "Codex package"),
        (&request.output, "output"),
    ] {
        validate_absolute_normal_path(path, label)?;
    }
    if request.output.starts_with(&request.stage)
        || request.stage.starts_with(&request.output)
        || request.output.starts_with(&request.codex_package)
        || request.codex_package.starts_with(&request.output)
    {
        return Err(ContractRefreshError::Request(
            "output must not alias or contain an input".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absolute_normal_path(path: &Path, label: &str) -> Result<(), ContractRefreshError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components.clone().count() < 1
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ContractRefreshError::Request(format!(
            "{label} path must be absolute and lexically normalized"
        )));
    }
    Ok(())
}

fn validate_revision(value: &str, label: &str) -> Result<(), ContractRefreshError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractRefreshError::Request(format!(
            "{label} is not canonical 40-character lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn validate_release_identity(value: &str, label: &str) -> Result<(), ContractRefreshError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_digit()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(ContractRefreshError::Source(format!(
            "{label} is not a bounded release identity"
        )));
    }
    Ok(())
}

fn publish_no_replace(path: &Path, bytes: &[u8]) -> Result<(), ContractRefreshError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| ContractRefreshError::Publication("output has no parent".to_owned()))?;
    let name = path
        .file_name()
        .ok_or_else(|| ContractRefreshError::Publication("output has no filename".to_owned()))?;
    if name.as_bytes().is_empty() {
        return Err(ContractRefreshError::Publication(
            "output filename is empty".to_owned(),
        ));
    }
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ContractRefreshError::Publication(format!(
            "open output parent without following a final symlink: {error}"
        ))
    })?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o644),
    )
    .map_err(|error| {
        ContractRefreshError::Publication(format!("create contract without replacement: {error}"))
    })?;
    let metadata = fstat(&descriptor).map_err(|error| {
        ContractRefreshError::Publication(format!(
            "inspect newly created contract: {error}; safe cleanup was refused"
        ))
    })?;
    let identity = (metadata.st_dev, metadata.st_ino);
    let mut file = File::from(descriptor);
    let result = (|| -> Result<(), ContractRefreshError> {
        fchmod(&file, Mode::from_raw_mode(0o644)).map_err(|error| {
            ContractRefreshError::Publication(format!("set contract mode: {error}"))
        })?;
        file.write_all(bytes).map_err(|error| {
            ContractRefreshError::Publication(format!("write contract: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            ContractRefreshError::Publication(format!("fsync contract: {error}"))
        })?;
        fsync(&parent).map_err(|error| {
            ContractRefreshError::Publication(format!("fsync contract parent: {error}"))
        })
    })();
    if let Err(error) = result {
        let cleanup = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|cleanup| {
                ContractRefreshError::Publication(format!(
                    "{error}; inspect safe cleanup: {cleanup}"
                ))
            })
            .and_then(|current| {
                if FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
                    || (current.st_dev, current.st_ino) != identity
                {
                    return Err(ContractRefreshError::Publication(format!(
                        "{error}; incomplete output was substituted and was not removed"
                    )));
                }
                unlinkat(&parent, name, AtFlags::empty()).map_err(|cleanup| {
                    ContractRefreshError::Publication(format!(
                        "{error}; remove incomplete output: {cleanup}"
                    ))
                })
            });
        return cleanup.and(Err(error));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{derive_codex_version, derive_ripgrep_identity};

    #[test]
    fn derives_bounded_source_markers_without_accepting_near_matches() {
        let codex = b"prefix&0.147.0-alpha.1Welcome to Codex [vsuffix";
        assert_eq!(
            derive_codex_version(codex).expect("Codex marker"),
            "0.147.0-alpha.1"
        );

        let ripgrep = b"\x00noise\x0015.3.1abcdef0123invalid size\x00";
        let (version, revision, marker) = derive_ripgrep_identity(ripgrep).expect("ripgrep marker");
        assert_eq!(version, "15.3.1");
        assert_eq!(revision, "abcdef0123");
        assert_eq!(marker, "15.3.1abcdef0123");
    }

    #[test]
    fn rejects_ambiguous_source_markers() {
        let codex = b"1.0.0Welcome to Codex [v2.0.0Welcome to Codex [v";
        assert!(derive_codex_version(codex).is_err());

        let ripgrep = b"\x0015.2.0abcdef0123x\x0015.3.0abcdef0124x";
        assert!(derive_ripgrep_identity(ripgrep).is_err());
    }
}
