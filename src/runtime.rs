//! Version-matched Linux x86_64 runtime assembly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive};

use crate::asar::AsarStorage;
use crate::extract::{ExtractionError, TreePublisher};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::native::{NativeManifest, NativeOutput, native_contract};
use crate::staging::{StagingError, ValidatedStage, validate_stage};

const CONTRACT_JSON: &str = include_str!("../data/runtime-contract.json");
const MAX_ELECTRON_ZIP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CODEX_PACKAGE_BYTES: u64 = 160 * 1024 * 1024;
const MAX_CODEX_COMPONENT_BYTES: u64 = 384 * 1024 * 1024;
const MAX_UNPACKED_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NATIVE_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_NATIVE_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ELECTRON_ENTRIES: usize = 2_048;
const MAX_ELECTRON_UNCOMPRESSED_BYTES: u64 = 768 * 1024 * 1024;
const MAX_CODEX_PACKAGE_ENTRIES: usize = 32;
const MAX_RUNTIME_ENTRIES: usize = 20_000;
const PUBLICATION_SCOPE: &str = "bytes_at_durable_commit_boundary_under_documented_threat_model";

/// Fixed target identity for a runtime contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTarget {
    /// Required operating system.
    pub os: String,
    /// Required machine architecture.
    pub architecture: String,
}

/// Authenticated application identity accepted by this runtime contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApplicationContract {
    /// Exact desktop application version.
    pub version: String,
    /// Exact desktop application build.
    pub build: String,
    /// Exact authenticated application ASAR SHA-256.
    pub app_asar_sha256: String,
}

/// Exact Electron runtime input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeElectronContract {
    /// Exact Electron version.
    pub version: String,
    /// Official Linux x64 ZIP SHA-256.
    pub linux_x64_zip_sha256: String,
}

/// One exact file in the official Codex release package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexComponentContract {
    /// Safe path in the release tarball.
    pub archive_path: String,
    /// Normalized runtime path, absent for an intentionally omitted component.
    pub runtime_path: Option<String>,
    /// Truthful inclusion or omission disposition.
    pub disposition: String,
    /// Exact uncompressed SHA-256.
    pub sha256: String,
    /// Exact uncompressed bytes.
    pub bytes: u64,
    /// Normalized output mode, absent for an omitted component.
    pub mode: Option<String>,
}

/// Official version-matched Codex release package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexRuntimeContract {
    /// Exact CLI version observed in the authenticated desktop source.
    pub version: String,
    /// Official release tag.
    pub release_tag: String,
    /// Exact official source revision.
    pub revision: String,
    /// Exact Linux build target.
    pub target: String,
    /// SHA-256 of the complete official package tarball.
    pub package_archive_sha256: String,
    /// Exact complete package tarball bytes.
    pub package_archive_bytes: u64,
    /// Complete package file policy.
    pub components: Vec<CodexComponentContract>,
}

/// Exact ripgrep identity observed in both desktop and Linux inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RipgrepRuntimeContract {
    /// Exact ripgrep version.
    pub version: String,
    /// Full upstream revision.
    pub revision: String,
    /// SHA-256 of the exact Linux x86_64 musl executable.
    pub linux_x64_musl_sha256: String,
}

/// One platform-specific resource retained only for authenticated correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedSourceResource {
    /// Flat resource basename.
    pub name: String,
    /// SHA-256 inside the signed desktop artifact.
    pub sha256: String,
    /// Exact bytes inside the signed desktop artifact.
    pub bytes: u64,
    /// Required source binary format.
    pub format: String,
    /// Version/revision marker when the binary truthfully embeds one.
    pub identity_marker: Option<String>,
}

/// Embedded exact runtime-assembly contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContract {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Only supported target.
    pub target: RuntimeTarget,
    /// Exact authenticated application.
    pub application: RuntimeApplicationContract,
    /// Exact Electron runtime.
    pub electron: RuntimeElectronContract,
    /// Exact official Codex package.
    pub codex: CodexRuntimeContract,
    /// Exact bundled ripgrep.
    pub ripgrep: RipgrepRuntimeContract,
    /// Authenticated foreign source resources used for version correlation.
    pub authenticated_source_resources: Vec<AuthenticatedSourceResource>,
}

/// Explicit inputs for one runtime assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAssemblyRequest {
    /// Authenticated schema-1 stage generation.
    pub stage: PathBuf,
    /// Verified native output generation.
    pub native: PathBuf,
    /// Independently recorded SHA-256 of `native/manifest.json`.
    pub native_manifest_sha256: String,
    /// Official Electron Linux x64 ZIP.
    pub electron_zip: PathBuf,
    /// Official version-matched Codex package tarball.
    pub codex_package: PathBuf,
    /// New no-replace runtime generation.
    pub output: PathBuf,
}

/// One included or intentionally omitted file considered during assembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeInventoryEntry {
    /// Stable input class.
    pub source: String,
    /// Validated path within that input.
    pub source_path: String,
    /// Normalized runtime path when included.
    pub output_path: Option<String>,
    /// Exact inclusion or omission reason.
    pub disposition: String,
    /// SHA-256 of the complete file bytes.
    pub sha256: String,
    /// Exact file bytes.
    pub bytes: u64,
    /// Normalized output mode when included.
    pub mode: Option<String>,
    /// Detected data or executable format.
    pub format: String,
}

/// Deterministic complete runtime-assembly manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Truthful publication guarantee scope.
    pub publication_scope: String,
    /// Exact application version.
    pub application_version: String,
    /// Exact application build.
    pub application_build: String,
    /// Authenticated source archive SHA-256.
    pub source_archive_sha256: String,
    /// Authenticated ASAR SHA-256.
    pub app_asar_sha256: String,
    /// Independently supplied native-manifest SHA-256.
    pub native_manifest_sha256: String,
    /// Official Electron ZIP SHA-256.
    pub electron_zip_sha256: String,
    /// Official Codex package SHA-256.
    pub codex_package_sha256: String,
    /// Exact target Electron version.
    pub electron_version: String,
    /// Exact target Codex CLI version.
    pub codex_version: String,
    /// Exact ripgrep version and revision.
    pub ripgrep_version: String,
    /// Complete sorted file inventory; `manifest.json` itself is excluded.
    pub entries: Vec<RuntimeInventoryEntry>,
}

/// Contract, input, binary, or no-replace publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// Embedded or supplied runtime contract is invalid.
    #[error("invalid runtime contract: {0}")]
    Contract(String),
    /// Authenticated stage validation failed.
    #[error(transparent)]
    Stage(#[from] StagingError),
    /// A required input or archive is invalid.
    #[error("invalid runtime input: {0}")]
    Input(String),
    /// A binary has an unsafe or foreign identity.
    #[error("invalid runtime executable: {0}")]
    Executable(String),
    /// Private output construction failed.
    #[error("runtime assembly transaction failed: {0}")]
    Transaction(String),
    /// No-replace publication failed before commit.
    #[error("runtime assembly publication failed before commit: {0}")]
    Publication(String),
    /// The name committed but parent durability is uncertain.
    #[error("runtime assembly committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

#[derive(Debug)]
struct ValidatedNative {
    manifest_sha256: String,
    outputs: Vec<(NativeOutput, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BinaryFormat {
    Data,
    Script,
    ElfX86_64,
    ElfForeign(u16),
    MachO,
    Pe(u16),
}

impl BinaryFormat {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Data => "data".to_owned(),
            Self::Script => "script".to_owned(),
            Self::ElfX86_64 => "elf_x86_64".to_owned(),
            Self::ElfForeign(machine) => format!("elf_foreign_machine_{machine}"),
            Self::MachO => "macho".to_owned(),
            Self::Pe(machine) => format!("pe_machine_{machine}"),
        }
    }
}

/// Parses and validates the embedded exact runtime contract.
pub fn runtime_contract() -> Result<RuntimeContract, RuntimeError> {
    let contract: RuntimeContract = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| RuntimeError::Contract(error.to_string()))?;
    if contract.schema != SCHEMA_VERSION || contract.producer != PRODUCER_IDENTIFIER {
        return Err(RuntimeError::Contract(
            "schema or producer differs from this Rust implementation".to_owned(),
        ));
    }
    if contract.target.os != "linux" || contract.target.architecture != "x86_64" {
        return Err(RuntimeError::Contract(
            "target is not exactly Linux x86_64".to_owned(),
        ));
    }
    if contract.application.version != "26.721.81911"
        || contract.application.build != "5973"
        || contract.electron.version != "42.3.0"
        || contract.codex.version != "0.146.0-alpha.3.1"
        || contract.codex.release_tag != "rust-v0.146.0-alpha.3.1"
        || contract.codex.revision != "ff75c5b939c477c49eb1bd5248da6dab71b109d1"
        || contract.codex.target != "x86_64-unknown-linux-musl"
        || contract.ripgrep.version != "15.2.0"
        || contract.ripgrep.revision != "e89fff89ac9af12e8d4ce9d5fd07beb408ca730f"
    {
        return Err(RuntimeError::Contract(
            "reviewed application/Electron/Codex/ripgrep identities differ".to_owned(),
        ));
    }
    for (value, label) in [
        (
            contract.application.app_asar_sha256.as_str(),
            "application ASAR",
        ),
        (
            contract.electron.linux_x64_zip_sha256.as_str(),
            "Electron ZIP",
        ),
        (
            contract.codex.package_archive_sha256.as_str(),
            "Codex package",
        ),
        (
            contract.ripgrep.linux_x64_musl_sha256.as_str(),
            "ripgrep executable",
        ),
    ] {
        validate_digest(value, label)?;
    }
    if contract.codex.package_archive_bytes != 131_526_287 || contract.codex.components.len() != 6 {
        return Err(RuntimeError::Contract(
            "Codex package envelope differs from the reviewed release".to_owned(),
        ));
    }
    let mut archive_paths = BTreeSet::new();
    let mut runtime_paths = BTreeSet::new();
    for component in &contract.codex.components {
        validate_relative_path(&component.archive_path)?;
        if !archive_paths.insert(component.archive_path.as_str()) {
            return Err(RuntimeError::Contract(
                "duplicate Codex package component".to_owned(),
            ));
        }
        validate_digest(&component.sha256, "Codex package component")?;
        if component.bytes > MAX_CODEX_COMPONENT_BYTES {
            return Err(RuntimeError::Contract(
                "Codex package component exceeds its bound".to_owned(),
            ));
        }
        match (
            component.disposition.as_str(),
            component.runtime_path.as_deref(),
            component.mode.as_deref(),
        ) {
            ("included", Some(path), Some("0644" | "0755")) => {
                validate_relative_path(path)?;
                if !runtime_paths.insert(path) {
                    return Err(RuntimeError::Contract(
                        "duplicate Codex runtime path".to_owned(),
                    ));
                }
            }
            ("omitted_glibc_2_38_optional_zsh", None, None) => {}
            _ => {
                return Err(RuntimeError::Contract(
                    "invalid Codex component disposition/path/mode".to_owned(),
                ));
            }
        }
    }
    if contract.authenticated_source_resources.len() != 3 {
        return Err(RuntimeError::Contract(
            "authenticated source resource set must contain three files".to_owned(),
        ));
    }
    let mut source_names = BTreeSet::new();
    for source in &contract.authenticated_source_resources {
        if !matches!(
            source.name.as_str(),
            "codex" | "codex-code-mode-host" | "rg"
        ) || !source_names.insert(source.name.as_str())
            || source.format != "macho_x86_64"
            || source
                .identity_marker
                .as_ref()
                .is_some_and(|marker| marker.is_empty() || !marker.is_ascii())
        {
            return Err(RuntimeError::Contract(
                "invalid authenticated source resource contract".to_owned(),
            ));
        }
        validate_digest(&source.sha256, "authenticated source resource")?;
    }
    let marker_policy: BTreeMap<&str, Option<&str>> = contract
        .authenticated_source_resources
        .iter()
        .map(|source| (source.name.as_str(), source.identity_marker.as_deref()))
        .collect();
    if marker_policy.get("codex") != Some(&Some("0.146.0-alpha.3.1"))
        || marker_policy.get("rg") != Some(&Some("15.2.0e89fff89ac"))
        || marker_policy.get("codex-code-mode-host") != Some(&None)
    {
        return Err(RuntimeError::Contract(
            "authenticated source marker policy differs from observed bytes".to_owned(),
        ));
    }
    let ripgrep = contract
        .codex
        .components
        .iter()
        .find(|component| component.archive_path == "codex-path/rg")
        .ok_or_else(|| RuntimeError::Contract("Codex package lost ripgrep".to_owned()))?;
    if ripgrep.sha256 != contract.ripgrep.linux_x64_musl_sha256 {
        return Err(RuntimeError::Contract(
            "Codex package ripgrep digest conflicts with its independent contract".to_owned(),
        ));
    }
    Ok(contract)
}

/// Re-authenticates every input and publishes a deterministic runtime tree.
pub fn assemble_runtime(request: &RuntimeAssemblyRequest) -> Result<RuntimeManifest, RuntimeError> {
    validate_request(request)?;
    let contract = runtime_contract()?;
    let stage = validate_stage(&request.stage)?;
    validate_stage_contract(&stage, &contract)?;
    let native = validate_native_output(request, &stage, &contract)?;
    let electron_zip = read_regular_input(&request.electron_zip, MAX_ELECTRON_ZIP_BYTES)?;
    verify_sha256(
        &electron_zip,
        &contract.electron.linux_x64_zip_sha256,
        "Electron Linux x64 ZIP",
    )?;
    let codex_package = read_regular_input(&request.codex_package, MAX_CODEX_PACKAGE_BYTES)?;
    if u64::try_from(codex_package.len())
        .map_err(|_| RuntimeError::Input("Codex package length does not fit u64".to_owned()))?
        != contract.codex.package_archive_bytes
    {
        return Err(RuntimeError::Input(
            "Codex package length differs from the exact contract".to_owned(),
        ));
    }
    verify_sha256(
        &codex_package,
        &contract.codex.package_archive_sha256,
        "Codex package archive",
    )?;

    let source_archive_sha256 = stage
        .provenance
        .files
        .iter()
        .find(|file| file.path == "source.zip")
        .map(|file| file.sha256.clone())
        .ok_or_else(|| RuntimeError::Input("stage lost source archive identity".to_owned()))?;
    let mut publisher = TreePublisher::new(&request.output)
        .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
    let mut entries = Vec::new();
    let build = (|| -> Result<(), RuntimeError> {
        write_electron_runtime(&mut publisher, &electron_zip, &mut entries)?;
        write_stage_application(&mut publisher, &stage, &mut entries)?;
        write_authenticated_unpacked(&mut publisher, &stage, &contract, &mut entries)?;
        write_native_outputs(&mut publisher, &native, &mut entries)?;
        write_codex_package(&mut publisher, &codex_package, &contract, &mut entries)?;
        entries.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then_with(|| left.source_path.cmp(&right.source_path))
        });
        if entries.len() > MAX_RUNTIME_ENTRIES {
            return Err(RuntimeError::Transaction(format!(
                "runtime manifest exceeds {MAX_RUNTIME_ENTRIES} entries"
            )));
        }
        validate_output_inventory(&entries)?;
        let manifest = RuntimeManifest {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER.to_owned(),
            kind: "linux_x86_64_runtime".to_owned(),
            publication_scope: PUBLICATION_SCOPE.to_owned(),
            application_version: contract.application.version.clone(),
            application_build: contract.application.build.clone(),
            source_archive_sha256: source_archive_sha256.clone(),
            app_asar_sha256: contract.application.app_asar_sha256.clone(),
            native_manifest_sha256: native.manifest_sha256.clone(),
            electron_zip_sha256: contract.electron.linux_x64_zip_sha256.clone(),
            codex_package_sha256: contract.codex.package_archive_sha256.clone(),
            electron_version: contract.electron.version.clone(),
            codex_version: contract.codex.version.clone(),
            ripgrep_version: format!(
                "{} ({})",
                contract.ripgrep.version, contract.ripgrep.revision
            ),
            entries: entries.clone(),
        };
        let encoded = to_json_line(&manifest)
            .map_err(|error| RuntimeError::Transaction(format!("encode manifest: {error}")))?;
        publisher
            .write_file("manifest.json", encoded.as_bytes(), 0o644)
            .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
        Ok(())
    })();
    if let Err(error) = build {
        return Err(cleanup_error(&mut publisher, error));
    }

    let manifest = RuntimeManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_runtime".to_owned(),
        publication_scope: PUBLICATION_SCOPE.to_owned(),
        application_version: contract.application.version,
        application_build: contract.application.build,
        source_archive_sha256,
        app_asar_sha256: contract.application.app_asar_sha256,
        native_manifest_sha256: native.manifest_sha256,
        electron_zip_sha256: contract.electron.linux_x64_zip_sha256,
        codex_package_sha256: contract.codex.package_archive_sha256,
        electron_version: contract.electron.version,
        codex_version: contract.codex.version,
        ripgrep_version: format!(
            "{} ({})",
            contract.ripgrep.version, contract.ripgrep.revision
        ),
        entries,
    };
    match publisher.commit() {
        Ok(()) => Ok(manifest),
        Err(ExtractionError::PostCommitDurability(message)) => {
            Err(RuntimeError::PostCommitDurability(message))
        }
        Err(error) => Err(cleanup_error(
            &mut publisher,
            RuntimeError::Publication(error.to_string()),
        )),
    }
}

fn validate_request(request: &RuntimeAssemblyRequest) -> Result<(), RuntimeError> {
    for (label, path) in [
        ("stage", &request.stage),
        ("native output", &request.native),
        ("Electron ZIP", &request.electron_zip),
        ("Codex package", &request.codex_package),
        ("output", &request.output),
    ] {
        if !path.is_absolute() {
            return Err(RuntimeError::Contract(format!(
                "{label} path must be absolute"
            )));
        }
    }
    validate_digest(&request.native_manifest_sha256, "supplied native manifest")?;
    for input in [
        &request.stage,
        &request.native,
        &request.electron_zip,
        &request.codex_package,
    ] {
        if input.starts_with(&request.output) || request.output.starts_with(input) {
            return Err(RuntimeError::Contract(
                "runtime output must not alias or contain an input".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_stage_contract(
    stage: &ValidatedStage,
    contract: &RuntimeContract,
) -> Result<(), RuntimeError> {
    if stage.provenance.bundle.version != contract.application.version
        || stage.provenance.bundle.build != contract.application.build
        || stage.asar.inspection.asar_sha256 != contract.application.app_asar_sha256
    {
        return Err(RuntimeError::Contract(
            "authenticated stage differs from the exact runtime contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_native_output(
    request: &RuntimeAssemblyRequest,
    stage: &ValidatedStage,
    contract: &RuntimeContract,
) -> Result<ValidatedNative, RuntimeError> {
    let native_contract = native_contract()
        .map_err(|error| RuntimeError::Contract(format!("load native contract: {error}")))?;
    let root_metadata = std::fs::symlink_metadata(&request.native)
        .map_err(|error| RuntimeError::Input(format!("inspect native output root: {error}")))?;
    if !root_metadata.file_type().is_dir() || root_metadata.permissions().mode() & 0o7777 != 0o755 {
        return Err(RuntimeError::Input(
            "native output root is not a mode-0755 real directory".to_owned(),
        ));
    }
    let manifest_bytes = read_relative_regular(
        &request.native,
        "manifest.json",
        MAX_NATIVE_MANIFEST_BYTES,
        0o644,
    )?;
    verify_sha256(
        &manifest_bytes,
        &request.native_manifest_sha256,
        "independently pinned native manifest",
    )?;
    let manifest: NativeManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| RuntimeError::Input(format!("parse native manifest: {error}")))?;
    let canonical = to_json_line(&manifest)
        .map_err(|error| RuntimeError::Input(format!("canonicalize native manifest: {error}")))?;
    if canonical.as_bytes() != manifest_bytes {
        return Err(RuntimeError::Input(
            "native manifest is not canonical schema-1 JSON".to_owned(),
        ));
    }
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "native_build"
        || manifest.application_version != contract.application.version
        || manifest.application_build != contract.application.build
        || manifest.source_asar_sha256 != stage.asar.inspection.asar_sha256
        || manifest.runtime.electron != contract.electron.version
        || manifest.runtime.modules != 146
        || manifest.runtime.arch != "x64"
        || manifest.runtime.platform != "linux"
        || manifest.electron_zip_sha256 != native_contract.electron.linux_x64_zip_sha256
        || manifest.electron_headers_sha256 != native_contract.electron.headers_tar_sha256
        || manifest.source_patches != native_contract.source_patches
        || manifest.build_image != native_contract.build_image
        || manifest.build_node_version != native_contract.build_image.node_version
        || manifest.build_npm_version != native_contract.build_image.npm_version
        || manifest.build_glibc_version != native_contract.build_image.glibc_version
        || manifest.build_gcc_version != native_contract.build_image.gcc_version
        || manifest.network_allowed
        || !manifest.sqlite_probe_passed
        || !manifest.pty_probe_passed
    {
        return Err(RuntimeError::Input(
            "native manifest identity or real probes differ from the runtime contract".to_owned(),
        ));
    }
    if manifest.outputs.len() != 2 {
        return Err(RuntimeError::Input(
            "native manifest must contain exactly two outputs".to_owned(),
        ));
    }
    let expected_paths = BTreeSet::from([
        "app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
        "app.asar.unpacked/node_modules/node-pty/build/Release/pty.node",
    ]);
    let observed_paths: BTreeSet<&str> = manifest
        .outputs
        .iter()
        .map(|output| output.path.as_str())
        .collect();
    if observed_paths != expected_paths {
        return Err(RuntimeError::Input(
            "native output path set differs from the runtime contract".to_owned(),
        ));
    }
    let expected_files: BTreeSet<String> = manifest
        .outputs
        .iter()
        .map(|output| output.path.clone())
        .chain(std::iter::once("manifest.json".to_owned()))
        .collect();
    validate_exact_tree(&request.native, &expected_files)?;

    let mut outputs = Vec::with_capacity(manifest.outputs.len());
    for output in &manifest.outputs {
        if output.mode != "0644" || output.elf_machine != "x86_64" {
            return Err(RuntimeError::Input(format!(
                "native output metadata differs for {:?}",
                output.path
            )));
        }
        validate_native_glibc(
            output,
            &native_contract.build_image.maximum_output_glibc_version,
        )?;
        let bytes = read_relative_regular(
            &request.native,
            &output.path,
            MAX_NATIVE_OUTPUT_BYTES,
            0o644,
        )?;
        verify_identity(&bytes, output.bytes, &output.sha256, &output.path)?;
        if classify_binary(&bytes)? != BinaryFormat::ElfX86_64 {
            return Err(RuntimeError::Executable(format!(
                "native output {:?} is not Linux x86_64 ELF",
                output.path
            )));
        }
        outputs.push((output.clone(), bytes));
    }
    Ok(ValidatedNative {
        manifest_sha256: request.native_manifest_sha256.clone(),
        outputs,
    })
}

fn validate_native_glibc(output: &NativeOutput, maximum: &str) -> Result<(), RuntimeError> {
    let permitted = parse_glibc_version(maximum).ok_or_else(|| {
        RuntimeError::Contract("native maximum GLIBC contract is invalid".to_owned())
    })?;
    let mut observed = BTreeSet::new();
    for name in &output.glibc_versions {
        let version = name.strip_prefix("GLIBC_").ok_or_else(|| {
            RuntimeError::Input(format!(
                "native output {:?} has an invalid GLIBC version",
                output.path
            ))
        })?;
        let parsed = parse_glibc_version(version).ok_or_else(|| {
            RuntimeError::Input(format!(
                "native output {:?} has an invalid GLIBC version",
                output.path
            ))
        })?;
        if parsed > permitted || !observed.insert((parsed, name.as_str())) {
            return Err(RuntimeError::Input(format!(
                "native output {:?} exceeds or duplicates its GLIBC contract",
                output.path
            )));
        }
    }
    let greatest = observed.iter().map(|(_, name)| *name).next_back();
    if greatest != output.maximum_glibc.as_deref() {
        return Err(RuntimeError::Input(format!(
            "native output {:?} maximum GLIBC version is inconsistent",
            output.path
        )));
    }
    Ok(())
}

fn parse_glibc_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().map(str::parse).transpose().ok()?.unwrap_or(0);
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn write_electron_runtime(
    publisher: &mut TreePublisher,
    bytes: &[u8],
    inventory: &mut Vec<RuntimeInventoryEntry>,
) -> Result<(), RuntimeError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| RuntimeError::Input(format!("parse Electron ZIP: {error}")))?;
    if archive.is_empty() || archive.len() > MAX_ELECTRON_ENTRIES {
        return Err(RuntimeError::Input(format!(
            "Electron ZIP entry count is outside 1..={MAX_ELECTRON_ENTRIES}"
        )));
    }
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| RuntimeError::Input(format!("open Electron member: {error}")))?;
        if entry.is_dir() || entry.is_symlink() {
            return Err(RuntimeError::Input(
                "Electron ZIP contains a directory entry or symlink".to_owned(),
            ));
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(RuntimeError::Input(
                "Electron ZIP uses unsupported compression".to_owned(),
            ));
        }
        validate_compression_ratio(entry.compressed_size(), entry.size(), "Electron member")?;
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| RuntimeError::Input("Electron size sum overflowed".to_owned()))?;
        if total > MAX_ELECTRON_UNCOMPRESSED_BYTES {
            return Err(RuntimeError::Input(format!(
                "Electron ZIP exceeds {MAX_ELECTRON_UNCOMPRESSED_BYTES} bytes"
            )));
        }
        let path = validate_relative_path_bytes(entry.name_raw())?;
        if !paths.insert(path.clone()) {
            return Err(RuntimeError::Input(format!(
                "duplicate Electron member {path:?}"
            )));
        }
        let entry_size = entry.size();
        let capacity = usize::try_from(entry_size)
            .map_err(|_| RuntimeError::Input("Electron member is too large".to_owned()))?;
        let mut content = Vec::with_capacity(capacity);
        Read::by_ref(&mut entry)
            .take(entry_size.saturating_add(1))
            .read_to_end(&mut content)
            .map_err(|error| RuntimeError::Input(format!("read Electron member: {error}")))?;
        if content.len() != capacity {
            return Err(RuntimeError::Input(format!(
                "Electron member length changed for {path:?}"
            )));
        }
        let executable = entry.unix_mode().is_some_and(|mode| mode & 0o111 != 0);
        let mode = if executable { 0o755 } else { 0o644 };
        let format = classify_binary(&content).map_err(|error| {
            RuntimeError::Executable(format!("classify Electron member {path:?}: {error}"))
        })?;
        if executable {
            validate_included_executable(&format, &path)?;
        }
        publisher
            .write_file(&path, &content, mode)
            .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
        inventory.push(included_entry(
            "electron_zip",
            &path,
            &path,
            &content,
            mode,
            format.label(),
        )?);
    }
    Ok(())
}

fn write_stage_application(
    publisher: &mut TreePublisher,
    stage: &ValidatedStage,
    inventory: &mut Vec<RuntimeInventoryEntry>,
) -> Result<(), RuntimeError> {
    let path = "resources/app.asar";
    publisher
        .write_file(path, &stage.app_asar, 0o644)
        .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
    inventory.push(included_entry(
        "authenticated_stage",
        "app.asar",
        path,
        &stage.app_asar,
        0o644,
        "asar".to_owned(),
    )?);
    Ok(())
}

fn write_authenticated_unpacked(
    publisher: &mut TreePublisher,
    stage: &ValidatedStage,
    contract: &RuntimeContract,
    inventory: &mut Vec<RuntimeInventoryEntry>,
) -> Result<(), RuntimeError> {
    let mut archive =
        ZipArchive::new(Cursor::new(stage.source_archive.as_slice())).map_err(|error| {
            RuntimeError::Input(format!("reopen authenticated source ZIP: {error}"))
        })?;
    for source in &contract.authenticated_source_resources {
        let source_path = format!(
            "{}/Contents/Resources/{}",
            stage.provenance.bundle.root, source.name
        );
        let content = read_zip_member(&mut archive, &source_path, source.bytes)?;
        verify_identity(&content, source.bytes, &source.sha256, &source_path)?;
        if let Some(marker) = &source.identity_marker {
            if !contains_bytes(&content, marker.as_bytes()) {
                return Err(RuntimeError::Input(format!(
                    "authenticated source resource {:?} lacks its version marker",
                    source.name
                )));
            }
        }
        validate_macho_x86_64(&content, &source.name)?;
        inventory.push(RuntimeInventoryEntry {
            source: "authenticated_source_zip".to_owned(),
            source_path,
            output_path: None,
            disposition: "authenticated_source_identity_only".to_owned(),
            sha256: source.sha256.clone(),
            bytes: source.bytes,
            mode: None,
            format: source.format.clone(),
        });
    }

    for entry in stage
        .asar
        .entries
        .iter()
        .filter(|entry| entry.storage == AsarStorage::Unpacked)
    {
        let source_path = format!(
            "{}/Contents/Resources/app.asar.unpacked/{}",
            stage.provenance.bundle.root, entry.path
        );
        let content =
            read_zip_member_bounded(&mut archive, &source_path, MAX_UNPACKED_MEMBER_BYTES)?;
        let format = classify_binary(&content).map_err(|error| {
            RuntimeError::Executable(format!("classify source member {source_path:?}: {error}"))
        })?;
        let integrity_matches = u64::try_from(content.len())
            .is_ok_and(|bytes| bytes == entry.bytes)
            && hex_lower(&Sha256::digest(&content)) == entry.sha256;
        if !integrity_matches && !allow_authenticated_unpacked_identity_mismatch(&format) {
            return Err(RuntimeError::Input(format!(
                "source member {source_path:?} differs from its pre-signing ASAR integrity"
            )));
        }
        let output_path = format!("resources/app.asar.unpacked/{}", entry.path);
        let replaces_native = matches!(
            entry.path.as_str(),
            "node_modules/better-sqlite3/build/Release/better_sqlite3.node"
                | "node_modules/node-pty/build/Release/pty.node"
        );
        let (disposition, included) = if replaces_native {
            ("replaced_by_verified_linux_native", false)
        } else {
            match format {
                BinaryFormat::MachO if integrity_matches => ("omitted_foreign_macho", false),
                BinaryFormat::MachO => ("omitted_foreign_macho_post_signing_identity", false),
                BinaryFormat::Pe(_) => ("omitted_foreign_pe", false),
                BinaryFormat::ElfForeign(_) => ("omitted_foreign_arch_elf", false),
                _ => ("included", true),
            }
        };
        if included {
            let mode = 0o644;
            publisher
                .write_file(&output_path, &content, mode)
                .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
            inventory.push(included_entry(
                "authenticated_source_zip",
                &source_path,
                &output_path,
                &content,
                mode,
                format.label(),
            )?);
        } else {
            inventory.push(RuntimeInventoryEntry {
                source: "authenticated_source_zip".to_owned(),
                source_path,
                output_path: None,
                disposition: disposition.to_owned(),
                sha256: hex_lower(&Sha256::digest(&content)),
                bytes: u64::try_from(content.len()).map_err(|_| {
                    RuntimeError::Input("unpacked member length does not fit u64".to_owned())
                })?,
                mode: None,
                format: format.label(),
            });
        }
    }
    Ok(())
}

fn write_native_outputs(
    publisher: &mut TreePublisher,
    native: &ValidatedNative,
    inventory: &mut Vec<RuntimeInventoryEntry>,
) -> Result<(), RuntimeError> {
    for (output, bytes) in &native.outputs {
        let path = format!("resources/{}", output.path);
        publisher
            .write_file(&path, bytes, 0o644)
            .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
        inventory.push(included_entry(
            "verified_native_output",
            &output.path,
            &path,
            bytes,
            0o644,
            "elf_x86_64".to_owned(),
        )?);
    }
    Ok(())
}

fn write_codex_package(
    publisher: &mut TreePublisher,
    bytes: &[u8],
    contract: &RuntimeContract,
    inventory: &mut Vec<RuntimeInventoryEntry>,
) -> Result<(), RuntimeError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| RuntimeError::Input(format!("parse Codex package: {error}")))?;
    let contracts: BTreeMap<&str, &CodexComponentContract> = contract
        .codex
        .components
        .iter()
        .map(|component| (component.archive_path.as_str(), component))
        .collect();
    let expected_directories = BTreeSet::from([
        "bin".to_owned(),
        "codex-path".to_owned(),
        "codex-resources".to_owned(),
        "codex-resources/zsh".to_owned(),
        "codex-resources/zsh/bin".to_owned(),
    ]);
    let mut observed_files = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    let mut count = 0_usize;
    for entry in entries {
        count = count
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Input("Codex package count overflowed".to_owned()))?;
        if count > MAX_CODEX_PACKAGE_ENTRIES {
            return Err(RuntimeError::Input(format!(
                "Codex package exceeds {MAX_CODEX_PACKAGE_ENTRIES} entries"
            )));
        }
        let mut entry =
            entry.map_err(|error| RuntimeError::Input(format!("read Codex entry: {error}")))?;
        let entry_type = entry.header().entry_type();
        let directory = entry_type.is_dir();
        if !directory && !entry_type.is_file() {
            return Err(RuntimeError::Input(
                "Codex package contains a link or special file".to_owned(),
            ));
        }
        let path = validate_relative_path_bytes(&entry.path_bytes())?;
        if directory {
            if !observed_directories.insert(path) {
                return Err(RuntimeError::Input(
                    "Codex package contains a duplicate directory".to_owned(),
                ));
            }
            continue;
        }
        if !observed_files.insert(path.clone()) {
            return Err(RuntimeError::Input(format!(
                "Codex package contains duplicate file {path:?}"
            )));
        }
        let component = contracts.get(path.as_str()).ok_or_else(|| {
            RuntimeError::Input(format!("unexpected Codex package file {path:?}"))
        })?;
        let size = entry.size();
        if size != component.bytes || size > MAX_CODEX_COMPONENT_BYTES {
            return Err(RuntimeError::Input(format!(
                "Codex component length differs for {path:?}"
            )));
        }
        let capacity = usize::try_from(size)
            .map_err(|_| RuntimeError::Input("Codex component is too large".to_owned()))?;
        let mut content = Vec::with_capacity(capacity);
        Read::by_ref(&mut entry)
            .take(size.saturating_add(1))
            .read_to_end(&mut content)
            .map_err(|error| RuntimeError::Input(format!("read Codex component: {error}")))?;
        if content.len() != capacity {
            return Err(RuntimeError::Input(format!(
                "Codex component length changed for {path:?}"
            )));
        }
        verify_sha256(&content, &component.sha256, &path)?;
        let format = classify_binary(&content)?;
        if component.disposition == "included" {
            let output = component.runtime_path.as_deref().ok_or_else(|| {
                RuntimeError::Contract("included Codex component has no output".to_owned())
            })?;
            let mode = parse_mode(component.mode.as_deref())?;
            if mode == 0o755 {
                validate_included_executable(&format, output)?;
            }
            if path == "codex-package.json" {
                validate_codex_package_json(&content, contract)?;
            }
            publisher
                .write_file(output, &content, mode)
                .map_err(|error| RuntimeError::Transaction(error.to_string()))?;
            inventory.push(included_entry(
                "codex_package",
                &path,
                output,
                &content,
                mode,
                format.label(),
            )?);
        } else {
            inventory.push(RuntimeInventoryEntry {
                source: "codex_package".to_owned(),
                source_path: path,
                output_path: None,
                disposition: component.disposition.clone(),
                sha256: component.sha256.clone(),
                bytes: component.bytes,
                mode: None,
                format: format.label(),
            });
        }
    }
    let expected_files: BTreeSet<String> =
        contracts.keys().map(|path| (*path).to_owned()).collect();
    if observed_files != expected_files || observed_directories != expected_directories {
        return Err(RuntimeError::Input(
            "Codex package file/directory inventory differs from its exact contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_codex_package_json(
    bytes: &[u8],
    contract: &RuntimeContract,
) -> Result<(), RuntimeError> {
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
    let package: Package = serde_json::from_slice(bytes)
        .map_err(|error| RuntimeError::Input(format!("parse Codex package metadata: {error}")))?;
    if package.layout_version != 1
        || package.version != contract.codex.version
        || package.target != contract.codex.target
        || package.variant != "codex"
        || package.entrypoint != "bin/codex"
        || package.resources_dir != "codex-resources"
        || package.path_dir != "codex-path"
    {
        return Err(RuntimeError::Input(
            "Codex package metadata differs from the exact contract".to_owned(),
        ));
    }
    Ok(())
}

fn read_zip_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    path: &str,
    expected_size: u64,
) -> Result<Vec<u8>, RuntimeError> {
    let mut entry = archive
        .by_name(path)
        .map_err(|error| RuntimeError::Input(format!("open source member {path:?}: {error}")))?;
    if entry.is_dir() || entry.is_symlink() || entry.size() != expected_size {
        return Err(RuntimeError::Input(format!(
            "source member {path:?} has the wrong type or length"
        )));
    }
    let capacity = usize::try_from(expected_size)
        .map_err(|_| RuntimeError::Input(format!("source member {path:?} is too large")))?;
    let mut content = Vec::with_capacity(capacity);
    Read::by_ref(&mut entry)
        .take(expected_size.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| RuntimeError::Input(format!("read source member {path:?}: {error}")))?;
    if content.len() != capacity {
        return Err(RuntimeError::Input(format!(
            "source member {path:?} was truncated"
        )));
    }
    Ok(content)
}

fn read_zip_member_bounded(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    path: &str,
    maximum: u64,
) -> Result<Vec<u8>, RuntimeError> {
    let mut entry = archive
        .by_name(path)
        .map_err(|error| RuntimeError::Input(format!("open source member {path:?}: {error}")))?;
    let entry_size = entry.size();
    if entry.is_dir() || entry.is_symlink() || entry_size > maximum {
        return Err(RuntimeError::Input(format!(
            "source member {path:?} has the wrong type or exceeds {maximum} bytes"
        )));
    }
    validate_compression_ratio(
        entry.compressed_size(),
        entry_size,
        "authenticated source member",
    )?;
    let capacity = usize::try_from(entry_size)
        .map_err(|_| RuntimeError::Input(format!("source member {path:?} is too large")))?;
    let mut content = Vec::with_capacity(capacity);
    Read::by_ref(&mut entry)
        .take(entry_size.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| RuntimeError::Input(format!("read source member {path:?}: {error}")))?;
    if content.len() != capacity {
        return Err(RuntimeError::Input(format!(
            "source member {path:?} was truncated"
        )));
    }
    Ok(content)
}

fn allow_authenticated_unpacked_identity_mismatch(format: &BinaryFormat) -> bool {
    *format == BinaryFormat::MachO
}

fn validate_output_inventory(entries: &[RuntimeInventoryEntry]) -> Result<(), RuntimeError> {
    let mut included = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for entry in entries {
        if !sources.insert((entry.source.as_str(), entry.source_path.as_str())) {
            return Err(RuntimeError::Transaction(
                "runtime inventory contains a duplicate source file".to_owned(),
            ));
        }
        match (&entry.output_path, &entry.mode) {
            (Some(path), Some(mode)) if entry.disposition == "included" => {
                validate_relative_path(path)?;
                if !matches!(mode.as_str(), "0644" | "0755") || !included.insert(path.as_str()) {
                    return Err(RuntimeError::Transaction(
                        "runtime inventory contains an invalid or duplicate output".to_owned(),
                    ));
                }
            }
            (None, None) if entry.disposition != "included" => {}
            _ => {
                return Err(RuntimeError::Transaction(
                    "runtime inventory disposition conflicts with its output".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn included_entry(
    source: &str,
    source_path: &str,
    output_path: &str,
    bytes: &[u8],
    mode: u32,
    format: String,
) -> Result<RuntimeInventoryEntry, RuntimeError> {
    Ok(RuntimeInventoryEntry {
        source: source.to_owned(),
        source_path: source_path.to_owned(),
        output_path: Some(output_path.to_owned()),
        disposition: "included".to_owned(),
        sha256: hex_lower(&Sha256::digest(bytes)),
        bytes: u64::try_from(bytes.len())
            .map_err(|_| RuntimeError::Transaction("file length does not fit u64".to_owned()))?,
        mode: Some(format!("{mode:04o}")),
        format,
    })
}

pub(crate) fn classify_binary(bytes: &[u8]) -> Result<BinaryFormat, RuntimeError> {
    if bytes.starts_with(b"\x7fELF") {
        let class = bytes.get(4).copied().unwrap_or_default();
        let encoding = bytes.get(5).copied().unwrap_or_default();
        let header_bytes = match class {
            1 => 52,
            2 => 64,
            _ => {
                return Err(RuntimeError::Executable(
                    "malformed ELF identity".to_owned(),
                ));
            }
        };
        if bytes.len() < header_bytes || !matches!(encoding, 1 | 2) || bytes[6] != 1 {
            return Err(RuntimeError::Executable(
                "malformed ELF identity".to_owned(),
            ));
        }
        let decode = |pair: [u8; 2]| {
            if encoding == 1 {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        };
        let file_type = decode([bytes[16], bytes[17]]);
        if !matches!(file_type, 2 | 3) {
            return Err(RuntimeError::Executable(format!(
                "unsupported ELF file type {file_type}"
            )));
        }
        let machine = decode([bytes[18], bytes[19]]);
        return Ok(if class == 2 && encoding == 1 && machine == 62 {
            BinaryFormat::ElfX86_64
        } else {
            BinaryFormat::ElfForeign(machine)
        });
    }
    if is_macho(bytes) {
        return Ok(BinaryFormat::MachO);
    }
    if bytes.starts_with(b"MZ") {
        if bytes.len() < 64 {
            return Err(RuntimeError::Executable(
                "truncated PE candidate".to_owned(),
            ));
        }
        let offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);
        let offset = usize::try_from(offset)
            .map_err(|_| RuntimeError::Executable("PE offset does not fit usize".to_owned()))?;
        let end = offset
            .checked_add(6)
            .ok_or_else(|| RuntimeError::Executable("PE offset overflowed".to_owned()))?;
        if bytes.get(offset..offset.saturating_add(4)) != Some(b"PE\0\0") || end > bytes.len() {
            return Err(RuntimeError::Executable(
                "malformed PE candidate".to_owned(),
            ));
        }
        return Ok(BinaryFormat::Pe(u16::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
        ])));
    }
    if bytes.starts_with(b"#!") {
        return Ok(BinaryFormat::Script);
    }
    Ok(BinaryFormat::Data)
}

fn is_macho(bytes: &[u8]) -> bool {
    bytes.get(..4).is_some_and(|magic| {
        matches!(
            magic,
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        )
    })
}

fn validate_macho_x86_64(bytes: &[u8], label: &str) -> Result<(), RuntimeError> {
    if bytes.len() < 32 || bytes.get(..4) != Some(b"\xcf\xfa\xed\xfe") {
        return Err(RuntimeError::Input(format!(
            "{label:?} is not thin little-endian 64-bit Mach-O"
        )));
    }
    let cpu = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cpu != 0x0100_0007 {
        return Err(RuntimeError::Input(format!(
            "{label:?} is not Mach-O x86_64"
        )));
    }
    Ok(())
}

fn validate_included_executable(format: &BinaryFormat, label: &str) -> Result<(), RuntimeError> {
    if *format != BinaryFormat::ElfX86_64 {
        return Err(RuntimeError::Executable(format!(
            "included executable {label:?} is not Linux x86_64 ELF"
        )));
    }
    Ok(())
}

fn read_regular_input(path: &Path, maximum: u64) -> Result<Vec<u8>, RuntimeError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Input(format!("open {}: {error}", path.display())))?;
    read_descriptor(descriptor, maximum, None, &path.display().to_string())
}

fn read_relative_regular(
    root: &Path,
    relative: &str,
    maximum: u64,
    expected_mode: u32,
) -> Result<Vec<u8>, RuntimeError> {
    validate_relative_path(relative)?;
    let mut current = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Input(format!("open {}: {error}", root.display())))?;
    let components: Vec<&str> = relative.split('/').collect();
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| RuntimeError::Input("relative file path is empty".to_owned()))?;
    for component in parents {
        current = rustix::fs::openat(
            &current,
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            RuntimeError::Input(format!("open native directory {component:?}: {error}"))
        })?;
    }
    let descriptor = rustix::fs::openat(
        &current,
        *name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| RuntimeError::Input(format!("open native file {relative:?}: {error}")))?;
    read_descriptor(descriptor, maximum, Some(expected_mode), relative)
}

fn read_descriptor(
    descriptor: std::os::fd::OwnedFd,
    maximum: u64,
    expected_mode: Option<u32>,
    label: &str,
) -> Result<Vec<u8>, RuntimeError> {
    let before = fstat(&descriptor)
        .map_err(|error| RuntimeError::Input(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
        return Err(RuntimeError::Input(format!(
            "{label} is not a regular file"
        )));
    }
    if expected_mode.is_some_and(|mode| before.st_mode & 0o7777 != mode) {
        return Err(RuntimeError::Input(format!(
            "{label} has the wrong Unix mode"
        )));
    }
    if before.st_size < 0 {
        return Err(RuntimeError::Input(format!("{label} has negative size")));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| RuntimeError::Input(format!("{label} size does not fit u64")))?;
    if size > maximum {
        return Err(RuntimeError::Input(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(size)
        .map_err(|_| RuntimeError::Input(format!("{label} size does not fit usize")))?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::Input(format!("read {label}: {error}")))?;
    if bytes.len() != capacity {
        return Err(RuntimeError::Input(format!(
            "{label} changed size or was truncated while reading"
        )));
    }
    let after =
        fstat(&file).map_err(|error| RuntimeError::Input(format!("reinspect {label}: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(RuntimeError::Input(format!(
            "{label} identity changed while reading"
        )));
    }
    Ok(bytes)
}

fn validate_exact_tree(root: &Path, expected: &BTreeSet<String>) -> Result<(), RuntimeError> {
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
            return Err(RuntimeError::Input(
                "native output directory depth exceeds 64".to_owned(),
            ));
        }
        let mut children = std::fs::read_dir(&directory)
            .map_err(|error| RuntimeError::Input(format!("enumerate native output: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RuntimeError::Input(format!("enumerate native output: {error}")))?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            count = count
                .checked_add(1)
                .ok_or_else(|| RuntimeError::Input("native inventory overflowed".to_owned()))?;
            if count > 128 {
                return Err(RuntimeError::Input(
                    "native output exceeds 128 entries".to_owned(),
                ));
            }
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| RuntimeError::Input("native output name is not UTF-8".to_owned()))?;
            validate_component(&name)?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = std::fs::symlink_metadata(child.path()).map_err(|error| {
                RuntimeError::Input(format!("inspect native output {path:?}: {error}"))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(RuntimeError::Input(
                    "native output contains a symlink".to_owned(),
                ));
            }
            if metadata.file_type().is_dir() {
                if metadata.permissions().mode() & 0o7777 != 0o755 {
                    return Err(RuntimeError::Input(format!(
                        "native directory {path:?} mode is not 0755"
                    )));
                }
                directories.insert(path.clone());
                stack.push((child.path(), path, depth + 1));
            } else if metadata.file_type().is_file() {
                files.insert(path);
            } else {
                return Err(RuntimeError::Input(
                    "native output contains a special file".to_owned(),
                ));
            }
        }
    }
    if &files != expected || directories != expected_directories {
        return Err(RuntimeError::Input(
            "native generation has missing or unexpected paths".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path_bytes(raw: &[u8]) -> Result<String, RuntimeError> {
    let path = std::str::from_utf8(raw)
        .map_err(|_| RuntimeError::Input("archive path is not UTF-8".to_owned()))?;
    let path = path.strip_suffix('/').unwrap_or(path);
    validate_relative_path(path)?;
    Ok(path.to_owned())
}

fn validate_relative_path(path: &str) -> Result<(), RuntimeError> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || matches!(byte, b'\\' | b':' | 0))
    {
        return Err(RuntimeError::Input(
            "path is not bounded safe printable relative ASCII".to_owned(),
        ));
    }
    let mut depth = 0_usize;
    for component in path.split('/') {
        validate_component(component)?;
        depth = depth
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Input("path depth overflowed".to_owned()))?;
        if depth > 64 {
            return Err(RuntimeError::Input("path exceeds 64 components".to_owned()));
        }
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), RuntimeError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > 255
        || component.as_bytes().contains(&0)
    {
        return Err(RuntimeError::Input(
            "path contains an unsafe component".to_owned(),
        ));
    }
    Ok(())
}

fn validate_compression_ratio(
    compressed: u64,
    uncompressed: u64,
    label: &str,
) -> Result<(), RuntimeError> {
    if compressed == 0 {
        if uncompressed != 0 {
            return Err(RuntimeError::Input(format!(
                "{label} has zero compressed bytes for nonempty data"
            )));
        }
    } else if uncompressed > compressed.saturating_mul(100) {
        return Err(RuntimeError::Input(format!(
            "{label} exceeds a 100:1 compression ratio"
        )));
    }
    Ok(())
}

fn verify_identity(
    bytes: &[u8],
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<(), RuntimeError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| RuntimeError::Input(format!("{label} length does not fit u64")))?;
    if length != expected_bytes {
        return Err(RuntimeError::Input(format!(
            "{label} length differs from its contract"
        )));
    }
    verify_sha256(bytes, expected_sha256, label)
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), RuntimeError> {
    if hex_lower(&Sha256::digest(bytes)) != expected {
        return Err(RuntimeError::Input(format!(
            "{label} does not match its pinned SHA-256"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), RuntimeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeError::Contract(format!(
            "{label} SHA-256 is not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn parse_mode(value: Option<&str>) -> Result<u32, RuntimeError> {
    match value {
        Some("0644") => Ok(0o644),
        Some("0755") => Ok(0o755),
        _ => Err(RuntimeError::Contract(
            "included component has an invalid mode".to_owned(),
        )),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn cleanup_error(publisher: &mut TreePublisher, original: RuntimeError) -> RuntimeError {
    match publisher.cleanup() {
        Ok(()) => original,
        Err(cleanup) => RuntimeError::Transaction(format!(
            "{original}; private runtime cleanup was intentionally incomplete: {cleanup}"
        )),
    }
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

#[cfg(test)]
mod tests {
    use super::{
        BinaryFormat, RuntimeError, allow_authenticated_unpacked_identity_mismatch,
        classify_binary, validate_relative_path,
    };

    #[test]
    fn rejects_unsafe_runtime_paths() {
        for path in ["", "/absolute", "../escape", "a//b", "a\\b", "a:b"] {
            assert!(validate_relative_path(path).is_err(), "{path:?}");
        }
        assert!(validate_relative_path("resources/app.asar").is_ok());
    }

    #[test]
    fn recognizes_a_minimal_x86_64_elf_header() {
        let mut bytes = vec![0_u8; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert_eq!(
            classify_binary(&bytes).expect("valid fixture"),
            BinaryFormat::ElfX86_64
        );
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        assert_eq!(
            classify_binary(&bytes).expect("valid foreign fixture"),
            BinaryFormat::ElfForeign(183)
        );
        bytes[4] = 1;
        bytes[18..20].copy_from_slice(&40_u16.to_le_bytes());
        assert_eq!(
            classify_binary(&bytes).expect("valid 32-bit ARM fixture"),
            BinaryFormat::ElfForeign(40)
        );
        bytes[4] = 0;
        assert!(matches!(
            classify_binary(&bytes),
            Err(RuntimeError::Executable(_))
        ));
    }

    #[test]
    fn only_authenticated_macho_may_differ_from_pre_signing_asar_integrity() {
        assert!(allow_authenticated_unpacked_identity_mismatch(
            &BinaryFormat::MachO
        ));
        for format in [
            BinaryFormat::Data,
            BinaryFormat::Script,
            BinaryFormat::ElfX86_64,
            BinaryFormat::ElfForeign(183),
            BinaryFormat::Pe(0x8664),
        ] {
            assert!(!allow_authenticated_unpacked_identity_mismatch(&format));
        }
    }
}
