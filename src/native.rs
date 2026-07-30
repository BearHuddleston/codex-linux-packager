//! Exact Linux x86_64 Electron native-module contracts and build pipeline.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use flate2::read::GzDecoder;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive};

use crate::asar::{AsarEntry, AsarStorage};
use crate::extract::{ExtractionError, TreePublisher};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::process::{ProcessError, ProcessOutput, ProcessSpec, run_bounded};
use crate::staging::{StagingError, ValidatedStage, validate_stage};

const CONTRACT_JSON: &str = include_str!("../data/native-contract.json");
const NATIVE_PACKAGE_JSON: &[u8] = include_bytes!("../native/package.json");
const NATIVE_PACKAGE_LOCK: &[u8] = include_bytes!("../native/package-lock.json");
const BETTER_SQLITE3_ELECTRON_42_PATCH: &[u8] =
    include_bytes!("../patches/better-sqlite3-12.9.0-electron-42.patch");
const MAX_ELECTRON_ZIP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HEADERS_TAR_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_UNCOMPRESSED_BYTES: u64 = 768 * 1024 * 1024;
const MAX_RUNTIME_ENTRIES: usize = 2_048;
const MAX_HEADER_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HEADER_ENTRIES: usize = 4_096;
const MAX_NATIVE_BINARY_BYTES: u64 = 128 * 1024 * 1024;

/// Fixed Linux target identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTarget {
    /// Required kernel platform.
    pub os: String,
    /// Public architecture spelling.
    pub architecture: String,
    /// npm/node-gyp architecture spelling.
    pub npm_architecture: String,
}

/// Exact Electron, Node, ABI, and independently pinned archive inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectronNativeContract {
    /// Exact Electron version.
    pub version: String,
    /// Node version embedded by that Electron build.
    pub node_version: String,
    /// `NODE_MODULE_VERSION`.
    pub module_abi: u32,
    /// Node-API version.
    pub napi: u32,
    /// SHA-256 of the official Linux x64 Electron ZIP.
    pub linux_x64_zip_sha256: String,
    /// SHA-256 of the official Electron header tarball.
    pub headers_tar_sha256: String,
}

/// Host tooling floor required by the locked rebuild tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeHostContract {
    /// Minimum accepted host Node.js version.
    pub minimum_node_version: String,
}

/// Exact, digest-addressed OCI build environment used to cap glibc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildImageContract {
    /// Immutable OCI image reference.
    pub reference: String,
    /// OCI architecture spelling.
    pub architecture: String,
    /// OCI operating-system spelling.
    pub operating_system: String,
    /// Exact Node.js version in the image.
    pub node_version: String,
    /// Exact npm version in the image.
    pub npm_version: String,
    /// Exact glibc baseline in the image.
    pub glibc_version: String,
    /// Exact GCC version in the image.
    pub gcc_version: String,
    /// Maximum permitted GLIBC symbol version in native outputs.
    pub maximum_output_glibc_version: String,
}

/// One application-declared native source package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePackageContract {
    /// Exact npm package name.
    pub name: String,
    /// Exact npm package version.
    pub version: String,
    /// Integrity-verified source `package.json` digest in the ASAR.
    pub source_asar_package_json_sha256: String,
    /// Exact npm registry tarball SHA-512 payload, standard base64.
    pub npm_tarball_sha512: String,
}

/// One file changed by a pinned native-source compatibility patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePatchFileContract {
    /// Package-relative safe path.
    pub path: String,
    /// SHA-256 required before applying the patch.
    pub before_sha256: String,
    /// SHA-256 required after applying the patch.
    pub after_sha256: String,
}

/// A reviewed upstream source patch required by the exact target ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSourcePatchContract {
    /// Exact package name.
    pub package: String,
    /// Exact package version to which the patch applies.
    pub package_version: String,
    /// Canonical upstream repository URL.
    pub upstream_repository: String,
    /// Full reviewed upstream Git commit.
    pub upstream_commit: String,
    /// SHA-256 of the repository-carried unified patch.
    pub patch_sha256: String,
    /// Exact before/after file identities.
    pub files: Vec<NativePatchFileContract>,
}

/// Embedded, versioned native build contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeContract {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Only supported target.
    pub target: NativeTarget,
    /// Exact target runtime ABI.
    pub electron: ElectronNativeContract,
    /// Host tooling floor.
    pub host: NativeHostContract,
    /// Immutable controlled native compilation environment.
    pub build_image: NativeBuildImageContract,
    /// Exact application native packages.
    pub packages: Vec<NativePackageContract>,
    /// Exact reviewed source transformations needed by the target ABI.
    pub source_patches: Vec<NativeSourcePatchContract>,
}

/// Inputs and explicitly authorized network policy for one native build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBuildRequest {
    /// Authenticated schema-1 stage generation.
    pub stage: PathBuf,
    /// Official Electron Linux x64 ZIP matching the embedded digest.
    pub electron_zip: PathBuf,
    /// Official Electron header tarball matching the embedded digest.
    pub electron_headers: PathBuf,
    /// npm content-addressed cache.
    pub npm_cache: PathBuf,
    /// New private build directory; retained for audit on failure.
    pub work_directory: PathBuf,
    /// New verified native output generation.
    pub output: PathBuf,
    /// Whether `npm ci` may contact the registry. False enforces offline mode.
    pub allow_network: bool,
    /// Absolute host Node.js executable.
    pub node_program: PathBuf,
    /// Absolute host npm executable.
    pub npm_program: PathBuf,
    /// Absolute OCI runtime executable.
    pub oci_runtime: PathBuf,
    /// Independently recorded SHA-256 of the OCI runtime executable.
    pub oci_runtime_sha256: String,
    /// Optional absolute noninteractive sudo executable used only to launch the
    /// OCI runtime.
    pub sudo_program: Option<PathBuf>,
    /// Independently recorded SHA-256 of the optional sudo executable.
    pub sudo_sha256: Option<String>,
}

/// One verified native output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOutput {
    /// Fixed runtime-relative path.
    pub path: String,
    /// SHA-256 in lowercase hexadecimal.
    pub sha256: String,
    /// Exact byte count.
    pub bytes: u64,
    /// Exact committed Unix mode.
    pub mode: String,
    /// Parsed ELF machine.
    pub elf_machine: String,
    /// Required GLIBC symbol versions in lexical order.
    pub glibc_versions: Vec<String>,
    /// Greatest required GLIBC symbol version.
    pub maximum_glibc: Option<String>,
}

/// Exact target runtime identity observed by executing Electron as Node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectronRuntimeIdentity {
    /// Electron version.
    pub electron: String,
    /// Embedded Node.js version.
    pub node: String,
    /// Node module ABI.
    pub modules: u32,
    /// Node-API version.
    pub napi: u32,
    /// Runtime architecture spelling.
    pub arch: String,
    /// Runtime operating system spelling.
    pub platform: String,
}

/// Deterministic manifest for verified Linux x86_64 native modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Reconciled Codex application version.
    pub application_version: String,
    /// Reconciled Codex application build.
    pub application_build: String,
    /// Authenticated stage ASAR digest.
    pub source_asar_sha256: String,
    /// Exact Electron runtime observed by a real process.
    pub runtime: ElectronRuntimeIdentity,
    /// Official Electron ZIP digest.
    pub electron_zip_sha256: String,
    /// Official Electron header tar digest.
    pub electron_headers_sha256: String,
    /// SHA-256 of the complete npm lockfile.
    pub npm_lock_sha256: String,
    /// Reviewed source patches actually applied to exact base files.
    pub source_patches: Vec<NativeSourcePatchContract>,
    /// Host Node version that ran the locked build graph.
    pub host_node_version: String,
    /// Host npm version.
    pub host_npm_version: String,
    /// Exact immutable OCI image used for compilation.
    pub build_image: NativeBuildImageContract,
    /// SHA-256 of the OCI runtime executable.
    pub oci_runtime_sha256: String,
    /// SHA-256 of the optional noninteractive sudo executable.
    pub sudo_sha256: Option<String>,
    /// Node.js version observed inside the build image.
    pub build_node_version: String,
    /// npm version observed inside the build image.
    pub build_npm_version: String,
    /// glibc version observed inside the build image.
    pub build_glibc_version: String,
    /// GCC version observed inside the build image.
    pub build_gcc_version: String,
    /// Whether registry network access was explicitly allowed.
    pub network_allowed: bool,
    /// True only after a real in-memory SQLite round trip.
    pub sqlite_probe_passed: bool,
    /// True only after a real PTY spawn and byte round trip.
    pub pty_probe_passed: bool,
    /// Complete verified output inventory in lexical order.
    pub outputs: Vec<NativeOutput>,
}

/// Contract, build, binary, or runtime-probe failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NativeError {
    /// Embedded or staged contract is invalid.
    #[error("invalid native build contract: {0}")]
    Contract(String),
    /// Authenticated stage validation failed.
    #[error(transparent)]
    Stage(#[from] StagingError),
    /// A bounded subprocess failed.
    #[error(transparent)]
    Process(#[from] ProcessError),
    /// A required input or private build operation failed.
    #[error("native build input/output failure: {0}")]
    Io(String),
    /// A command exited unsuccessfully.
    #[error("native build command failed: {0}")]
    Command(String),
    /// Runtime identity or real compatibility probe failed.
    #[error("native runtime verification failed: {0}")]
    Runtime(String),
    /// Native output is not the required Linux x86_64 ELF.
    #[error("invalid native ELF output: {0}")]
    Elf(String),
    /// Verified output publication failed.
    #[error("native output publication failed: {0}")]
    Publication(String),
}

/// Parses and validates the exact embedded native-build contract.
pub fn native_contract() -> Result<NativeContract, NativeError> {
    let contract: NativeContract = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| NativeError::Contract(error.to_string()))?;
    if contract.schema != SCHEMA_VERSION {
        return Err(NativeError::Contract(format!(
            "schema {} is not exactly {SCHEMA_VERSION}",
            contract.schema
        )));
    }
    if contract.producer != PRODUCER_IDENTIFIER {
        return Err(NativeError::Contract(
            "producer identifier differs from this Rust implementation".to_owned(),
        ));
    }
    if contract.target.os != "linux"
        || contract.target.architecture != "x86_64"
        || contract.target.npm_architecture != "x64"
    {
        return Err(NativeError::Contract(
            "target is not exactly Linux x86_64".to_owned(),
        ));
    }
    if contract.electron.version != "42.3.0"
        || contract.electron.node_version != "24.15.0"
        || contract.electron.module_abi != 146
        || contract.electron.napi != 10
    {
        return Err(NativeError::Contract(
            "Electron/Node ABI values differ from the reviewed contract".to_owned(),
        ));
    }
    validate_digest(&contract.electron.linux_x64_zip_sha256, "Electron ZIP")?;
    validate_digest(&contract.electron.headers_tar_sha256, "Electron headers")?;
    if contract.host.minimum_node_version != "22.12.0" {
        return Err(NativeError::Contract(
            "host Node.js floor differs from the rebuild requirement".to_owned(),
        ));
    }
    if contract.build_image.reference
        != "docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c"
        || contract.build_image.architecture != "amd64"
        || contract.build_image.operating_system != "linux"
        || contract.build_image.node_version != "22.22.0"
        || contract.build_image.npm_version != "10.9.4"
        || contract.build_image.glibc_version != "2.36"
        || contract.build_image.gcc_version != "12.2.0"
        || contract.build_image.maximum_output_glibc_version != "2.36"
    {
        return Err(NativeError::Contract(
            "native build image differs from the reviewed digest-addressed baseline".to_owned(),
        ));
    }
    if contract.packages.len() != 2 {
        return Err(NativeError::Contract(
            "native package contract must contain exactly two packages".to_owned(),
        ));
    }
    let mut packages = BTreeSet::new();
    for package in &contract.packages {
        if !packages.insert(package.name.as_str()) {
            return Err(NativeError::Contract(
                "duplicate native package contract".to_owned(),
            ));
        }
        validate_digest(
            &package.source_asar_package_json_sha256,
            "source package.json",
        )?;
        validate_base64_sha512(&package.npm_tarball_sha512)?;
    }
    if !packages.contains("better-sqlite3") || !packages.contains("node-pty") {
        return Err(NativeError::Contract(
            "native packages are not exactly better-sqlite3 and node-pty".to_owned(),
        ));
    }
    validate_source_patch_contract(&contract)?;
    Ok(contract)
}

/// Builds, validates, probes, and publishes the exact native outputs required
/// by the embedded Electron contract.
pub fn build_native(request: &NativeBuildRequest) -> Result<NativeManifest, NativeError> {
    validate_request_paths(request)?;
    let contract = native_contract()?;
    verify_sha256(
        &read_regular_input(&request.oci_runtime, 128 * 1024 * 1024)?,
        &request.oci_runtime_sha256,
        "OCI runtime executable",
    )?;
    match (&request.sudo_program, &request.sudo_sha256) {
        (Some(program), Some(expected)) => verify_sha256(
            &read_regular_input(program, 128 * 1024 * 1024)?,
            expected,
            "sudo executable",
        )?,
        (None, None) => {}
        _ => {
            return Err(NativeError::Contract(
                "sudo program and digest must either both be supplied or both be absent".to_owned(),
            ));
        }
    }
    let stage = validate_stage(&request.stage)?;
    validate_stage_package_contracts(&stage, &contract)?;

    let electron_zip = read_regular_input(&request.electron_zip, MAX_ELECTRON_ZIP_BYTES)?;
    verify_sha256(
        &electron_zip,
        &contract.electron.linux_x64_zip_sha256,
        "Electron Linux x64 ZIP",
    )?;
    let headers = read_regular_input(&request.electron_headers, MAX_HEADERS_TAR_BYTES)?;
    verify_sha256(
        &headers,
        &contract.electron.headers_tar_sha256,
        "Electron headers tarball",
    )?;

    create_private_work_directory(&request.work_directory)?;
    let runtime_directory = request.work_directory.join("electron-runtime");
    let headers_directory = request.work_directory.join("electron-headers");
    let project_directory = request.work_directory.join("native-project");
    let container_home = request.work_directory.join("container-home");
    create_directory(&runtime_directory, 0o700)?;
    create_directory(&headers_directory, 0o700)?;
    create_directory(&project_directory, 0o700)?;
    create_directory(&container_home, 0o700)?;
    extract_electron_runtime(&electron_zip, &runtime_directory)?;
    extract_electron_headers(&headers, &headers_directory)?;
    write_new_file(
        &project_directory.join("package.json"),
        NATIVE_PACKAGE_JSON,
        0o600,
    )?;
    write_new_file(
        &project_directory.join("package-lock.json"),
        NATIVE_PACKAGE_LOCK,
        0o600,
    )?;

    let host_tool_environment = host_tool_environment(&request.node_program)?;
    let host_node_version = command_version(
        &request.node_program,
        &["--version"],
        &request.work_directory,
        host_tool_environment.clone(),
    )?;
    require_minimum_version(
        host_node_version.trim_start_matches('v'),
        &contract.host.minimum_node_version,
        "host Node.js",
    )?;
    let host_npm_version = command_version(
        &request.npm_program,
        &["--version"],
        &request.work_directory,
        host_tool_environment,
    )?;
    let observed_build_environment =
        inspect_build_environment(request, &contract, &project_directory, &container_home)?;
    let runtime_program = runtime_directory.join("electron");
    let runtime = inspect_electron_runtime(&runtime_program, &request.work_directory)?;
    validate_runtime_identity(&runtime, &contract)?;

    let header_root = headers_directory.join("node_headers");
    if !header_root.join("include/node/node.h").is_file() {
        return Err(NativeError::Io(
            "Electron header tarball did not produce node_headers/include/node/node.h".to_owned(),
        ));
    }
    std::fs::create_dir_all(&request.npm_cache)
        .map_err(|error| NativeError::Io(format!("create npm cache: {error}")))?;
    let environment = native_environment(
        request,
        &contract,
        &header_root,
        &project_directory,
        &container_home,
    );
    let mut install_arguments = vec![
        OsString::from("ci"),
        OsString::from("--ignore-scripts"),
        OsString::from("--no-audit"),
        OsString::from("--no-fund"),
        OsString::from("--include=dev"),
    ];
    if !request.allow_network {
        install_arguments.push(OsString::from("--offline"));
    }
    run_container_successful(
        request,
        &contract,
        &project_directory,
        &container_home,
        environment.clone(),
        std::iter::once(OsString::from("/usr/local/bin/npm"))
            .chain(install_arguments)
            .collect(),
        Duration::from_secs(10 * 60),
        8 * 1024 * 1024,
        request.allow_network,
        "npm ci",
    )?;
    apply_native_source_patches(&project_directory, &contract)?;

    let rebuild_cli = project_directory.join("node_modules/@electron/rebuild/lib/cli.js");
    if !rebuild_cli.is_file() {
        return Err(NativeError::Io(
            "locked @electron/rebuild CLI is absent after npm ci".to_owned(),
        ));
    }
    run_container_successful(
        request,
        &contract,
        &project_directory,
        &container_home,
        environment.clone(),
        vec![
            OsString::from("/usr/local/bin/node"),
            rebuild_cli.into_os_string(),
            OsString::from("--version"),
            OsString::from(&contract.electron.version),
            OsString::from("--arch"),
            OsString::from("x64"),
            OsString::from("--module-dir"),
            project_directory.as_os_str().to_owned(),
            OsString::from("--force"),
            OsString::from("--which-module"),
            OsString::from("better-sqlite3,node-pty"),
        ],
        Duration::from_secs(20 * 60),
        16 * 1024 * 1024,
        request.allow_network,
        "electron-rebuild",
    )?;

    let built_outputs = [
        (
            "app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
            project_directory.join("node_modules/better-sqlite3/build/Release/better_sqlite3.node"),
            0o644,
        ),
        (
            "app.asar.unpacked/node_modules/node-pty/build/Release/pty.node",
            project_directory.join("node_modules/node-pty/build/Release/pty.node"),
            0o644,
        ),
    ];
    let mut output_bytes = Vec::with_capacity(built_outputs.len());
    let mut outputs = Vec::with_capacity(built_outputs.len());
    for (relative_path, path, mode) in built_outputs {
        let bytes = read_regular_input(&path, MAX_NATIVE_BINARY_BYTES)?;
        validate_linux_x86_64_elf(&bytes, relative_path)?;
        let (glibc_versions, maximum_glibc) = audit_native_glibc(
            request,
            &contract,
            &path,
            &project_directory,
            &container_home,
        )?;
        outputs.push(NativeOutput {
            path: relative_path.to_owned(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
            bytes: u64::try_from(bytes.len()).map_err(|_| {
                NativeError::Elf("native output length does not fit u64".to_owned())
            })?,
            mode: format!("{mode:04o}"),
            elf_machine: "x86_64".to_owned(),
            glibc_versions,
            maximum_glibc,
        });
        output_bytes.push((relative_path, bytes, mode));
    }
    outputs.sort_by(|left, right| left.path.cmp(&right.path));

    run_native_probes(
        &runtime_program,
        &project_directory,
        &request.work_directory,
    )?;
    let manifest = NativeManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "native_build".to_owned(),
        application_version: stage.provenance.bundle.version.clone(),
        application_build: stage.provenance.bundle.build.clone(),
        source_asar_sha256: stage.asar.inspection.asar_sha256.clone(),
        runtime,
        electron_zip_sha256: contract.electron.linux_x64_zip_sha256.clone(),
        electron_headers_sha256: contract.electron.headers_tar_sha256.clone(),
        npm_lock_sha256: hex_lower(&Sha256::digest(NATIVE_PACKAGE_LOCK)),
        source_patches: contract.source_patches.clone(),
        host_node_version,
        host_npm_version,
        build_image: contract.build_image.clone(),
        oci_runtime_sha256: request.oci_runtime_sha256.clone(),
        sudo_sha256: request.sudo_sha256.clone(),
        build_node_version: observed_build_environment.node_version,
        build_npm_version: observed_build_environment.npm_version,
        build_glibc_version: observed_build_environment.glibc_version,
        build_gcc_version: observed_build_environment.gcc_version,
        network_allowed: request.allow_network,
        sqlite_probe_passed: true,
        pty_probe_passed: true,
        outputs,
    };
    publish_native_outputs(&request.output, &output_bytes, &manifest)?;
    Ok(manifest)
}

fn validate_source_patch_contract(contract: &NativeContract) -> Result<(), NativeError> {
    if contract.source_patches.len() != 1 {
        return Err(NativeError::Contract(
            "native source patch contract must contain exactly one patch".to_owned(),
        ));
    }
    let patch = &contract.source_patches[0];
    if patch.package != "better-sqlite3"
        || patch.package_version != "12.9.0"
        || patch.upstream_repository != "https://github.com/WiseLibs/better-sqlite3"
        || patch.upstream_commit != "5bb63a2f4c5aa34de2c292b983d2b6c4fcfc6f94"
    {
        return Err(NativeError::Contract(
            "better-sqlite3 Electron 42 patch identity differs from the reviewed contract"
                .to_owned(),
        ));
    }
    validate_digest(&patch.patch_sha256, "native source patch")?;
    verify_sha256(
        BETTER_SQLITE3_ELECTRON_42_PATCH,
        &patch.patch_sha256,
        "repository-carried native source patch",
    )?;
    if patch.files.len() != 3 {
        return Err(NativeError::Contract(
            "native source patch must identify exactly three files".to_owned(),
        ));
    }
    let mut paths = BTreeSet::new();
    for file in &patch.files {
        let (safe, directory) = safe_archive_path(file.path.as_bytes(), false)?;
        if directory || safe != file.path || !paths.insert(file.path.as_str()) {
            return Err(NativeError::Contract(
                "native source patch has an unsafe or duplicate file path".to_owned(),
            ));
        }
        validate_digest(&file.before_sha256, "native source file before patch")?;
        validate_digest(&file.after_sha256, "native source file after patch")?;
        if file.before_sha256 == file.after_sha256 {
            return Err(NativeError::Contract(
                "native source patch does not change a declared file".to_owned(),
            ));
        }
    }
    let expected = BTreeSet::from([
        "src/better_sqlite3.cpp",
        "src/util/helpers.cpp",
        "src/util/macros.cpp",
    ]);
    if paths != expected {
        return Err(NativeError::Contract(
            "native source patch file set differs from the reviewed contract".to_owned(),
        ));
    }
    Ok(())
}

fn apply_native_source_patches(
    project_directory: &Path,
    contract: &NativeContract,
) -> Result<(), NativeError> {
    let patch = contract
        .source_patches
        .first()
        .ok_or_else(|| NativeError::Contract("native source patch is absent".to_owned()))?;
    let package_root = project_directory.join("node_modules").join(&patch.package);
    let mut transformed = Vec::with_capacity(patch.files.len());
    for file in &patch.files {
        let path = package_root.join(&file.path);
        let before = read_regular_input(&path, 16 * 1024 * 1024)?;
        verify_sha256(
            &before,
            &file.before_sha256,
            &format!("{} before source patch", file.path),
        )?;
        let after = match file.path.as_str() {
            "src/better_sqlite3.cpp" => replace_exact_once(
                &before,
                b"v8::Local<v8::External> data = v8::External::New(isolate, addon);",
                b"v8::Local<v8::External> data = EXTERNAL_NEW(isolate, addon);",
                &file.path,
            )?,
            "src/util/helpers.cpp" => replace_exact_once(
                &before,
                b"\t\tfunc,\n\t\t0,\n\t\tdata",
                b"\t\tfunc,\n\t\tnullptr,\n\t\tdata",
                &file.path,
            )?,
            "src/util/macros.cpp" => replace_exact_once(
                &before,
                b"#define OnlyAddon static_cast<Addon*>(info.Data().As<v8::External>()->Value())",
                concat!(
                    "#if defined(NODE_MODULE_VERSION) && NODE_MODULE_VERSION >= 146\n",
                    "#define EXTERNAL_NEW(isolate, value) v8::External::New((isolate), (value), 0)\n",
                    "#define EXTERNAL_VALUE(value) (value)->Value(0)\n",
                    "#else\n",
                    "#define EXTERNAL_NEW(isolate, value) v8::External::New((isolate), (value))\n",
                    "#define EXTERNAL_VALUE(value) (value)->Value()\n",
                    "#endif\n",
                    "#define OnlyAddon static_cast<Addon*>(EXTERNAL_VALUE(info.Data().As<v8::External>()))"
                )
                .as_bytes(),
                &file.path,
            )?,
            _ => {
                return Err(NativeError::Contract(format!(
                    "no reviewed transformation exists for {:?}",
                    file.path
                )));
            }
        };
        verify_sha256(
            &after,
            &file.after_sha256,
            &format!("{} after source patch", file.path),
        )?;
        transformed.push((path, after));
    }

    for (path, bytes) in transformed {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                NativeError::Io("native source patch path has no safe filename".to_owned())
            })?;
        let temporary = path.with_file_name(format!(".{file_name}.codex-linux-packager-new"));
        write_new_file(&temporary, &bytes, 0o644)?;
        std::fs::rename(&temporary, &path).map_err(|error| {
            NativeError::Io(format!(
                "replace patched native source {}: {error}",
                path.display()
            ))
        })?;
        let observed = read_regular_input(&path, 16 * 1024 * 1024)?;
        let declared = patch
            .files
            .iter()
            .find(|file| package_root.join(&file.path) == path)
            .ok_or_else(|| NativeError::Contract("patched file lost its contract".to_owned()))?;
        verify_sha256(
            &observed,
            &declared.after_sha256,
            &format!("{} committed source patch", declared.path),
        )?;
    }
    Ok(())
}

fn replace_exact_once(
    input: &[u8],
    before: &[u8],
    after: &[u8],
    label: &str,
) -> Result<Vec<u8>, NativeError> {
    if before.is_empty() {
        return Err(NativeError::Contract(
            "source patch search text is empty".to_owned(),
        ));
    }
    let mut matches = input
        .windows(before.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == before).then_some(index));
    let Some(position) = matches.next() else {
        return Err(NativeError::Contract(format!(
            "source patch for {label:?} did not match exactly once"
        )));
    };
    if matches.next().is_some() {
        return Err(NativeError::Contract(format!(
            "source patch for {label:?} did not match exactly once"
        )));
    }
    let capacity = input
        .len()
        .checked_sub(before.len())
        .and_then(|length| length.checked_add(after.len()))
        .ok_or_else(|| NativeError::Contract("patched source length overflowed".to_owned()))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&input[..position]);
    output.extend_from_slice(after);
    output.extend_from_slice(&input[position + before.len()..]);
    Ok(output)
}

fn validate_request_paths(request: &NativeBuildRequest) -> Result<(), NativeError> {
    for (label, path) in [
        ("stage", &request.stage),
        ("Electron ZIP", &request.electron_zip),
        ("Electron headers", &request.electron_headers),
        ("npm cache", &request.npm_cache),
        ("work directory", &request.work_directory),
        ("output", &request.output),
        ("Node program", &request.node_program),
        ("npm program", &request.npm_program),
        ("OCI runtime", &request.oci_runtime),
    ] {
        if !path.is_absolute() {
            return Err(NativeError::Contract(format!(
                "{label} path must be absolute"
            )));
        }
    }
    if let Some(sudo) = &request.sudo_program {
        if !sudo.is_absolute() {
            return Err(NativeError::Contract(
                "sudo program path must be absolute".to_owned(),
            ));
        }
    }
    validate_digest(&request.oci_runtime_sha256, "OCI runtime executable")?;
    if let Some(digest) = &request.sudo_sha256 {
        validate_digest(digest, "sudo executable")?;
    }
    if request.output.starts_with(&request.work_directory)
        || request.work_directory.starts_with(&request.output)
    {
        return Err(NativeError::Contract(
            "work and output paths must not alias or contain each other".to_owned(),
        ));
    }
    for input in [
        &request.stage,
        &request.electron_zip,
        &request.electron_headers,
        &request.npm_cache,
        &request.node_program,
        &request.npm_program,
        &request.oci_runtime,
    ] {
        if request.work_directory.starts_with(input)
            || input.starts_with(&request.work_directory)
            || request.output.starts_with(input)
            || input.starts_with(&request.output)
        {
            return Err(NativeError::Contract(
                "native work/output paths must not alias or contain an input".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_stage_package_contracts(
    stage: &ValidatedStage,
    contract: &NativeContract,
) -> Result<(), NativeError> {
    let root = parse_package_json(asar_file_bytes(stage, "package.json")?)?;
    if root.name.as_deref() != Some("openai-codex-electron")
        || root.version.as_deref() != Some(stage.provenance.bundle.version.as_str())
    {
        return Err(NativeError::Contract(
            "root application package name/version conflicts with the stage".to_owned(),
        ));
    }
    let dependencies = root.dependencies.ok_or_else(|| {
        NativeError::Contract("root application dependencies are absent".to_owned())
    })?;
    let development = root.development_dependencies.ok_or_else(|| {
        NativeError::Contract("root application devDependencies are absent".to_owned())
    })?;
    if dependencies.get("better-sqlite3").map(String::as_str) != Some("^12.9.0")
        || dependencies.get("node-pty").map(String::as_str) != Some("^1.1.0")
        || development.get("electron").map(String::as_str)
            != Some(contract.electron.version.as_str())
    {
        return Err(NativeError::Contract(
            "root application native/Electron dependency declarations differ".to_owned(),
        ));
    }

    for package in &contract.packages {
        let path = format!("node_modules/{}/package.json", package.name);
        let entry = stage
            .asar
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .ok_or_else(|| NativeError::Contract(format!("source ASAR is missing {path:?}")))?;
        if entry.storage != AsarStorage::Packed
            || entry.sha256 != package.source_asar_package_json_sha256
        {
            return Err(NativeError::Contract(format!(
                "source ASAR identity differs for {path:?}"
            )));
        }
        let identity = parse_package_json(asar_entry_bytes(stage, entry)?)?;
        if identity.name.as_deref() != Some(package.name.as_str())
            || identity.version.as_deref() != Some(package.version.as_str())
        {
            return Err(NativeError::Contract(format!(
                "source package name/version differs for {:?}",
                package.name
            )));
        }
    }
    Ok(())
}

fn asar_file_bytes<'a>(stage: &'a ValidatedStage, path: &str) -> Result<&'a [u8], NativeError> {
    let entry = stage
        .asar
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| NativeError::Contract(format!("source ASAR is missing {path:?}")))?;
    asar_entry_bytes(stage, entry)
}

fn asar_entry_bytes<'a>(
    stage: &'a ValidatedStage,
    entry: &AsarEntry,
) -> Result<&'a [u8], NativeError> {
    if entry.storage != AsarStorage::Packed {
        return Err(NativeError::Contract(format!(
            "required source entry {:?} is unpacked",
            entry.path
        )));
    }
    let offset = usize::try_from(
        entry
            .offset
            .ok_or_else(|| NativeError::Contract("packed entry has no offset".to_owned()))?,
    )
    .map_err(|_| NativeError::Contract("packed entry offset does not fit usize".to_owned()))?;
    let start = stage
        .asar
        .data_offset
        .checked_add(offset)
        .ok_or_else(|| NativeError::Contract("packed entry start overflowed".to_owned()))?;
    let size = usize::try_from(entry.bytes)
        .map_err(|_| NativeError::Contract("packed entry size does not fit usize".to_owned()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| NativeError::Contract("packed entry end overflowed".to_owned()))?;
    stage
        .app_asar
        .get(start..end)
        .ok_or_else(|| NativeError::Contract("packed entry crosses app.asar".to_owned()))
}

#[derive(Debug, Default)]
struct PackageIdentity {
    name: Option<String>,
    version: Option<String>,
    dependencies: Option<BTreeMap<String, String>>,
    development_dependencies: Option<BTreeMap<String, String>>,
}

fn parse_package_json(bytes: &[u8]) -> Result<PackageIdentity, NativeError> {
    serde_json::from_slice(bytes)
        .map_err(|error| NativeError::Contract(format!("invalid package.json: {error}")))
}

impl<'de> Deserialize<'de> for PackageIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(PackageIdentityVisitor)
    }
}

struct PackageIdentityVisitor;

impl<'de> Visitor<'de> for PackageIdentityVisitor {
    type Value = PackageIdentity;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a duplicate-free package.json object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = PackageIdentity::default();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate package.json key {key:?}"
                )));
            }
            match key.as_str() {
                "name" => result.name = Some(map.next_value()?),
                "version" => result.version = Some(map.next_value()?),
                "dependencies" => {
                    result.dependencies = Some(map.next_value::<StrictStringMap>()?.0);
                }
                "devDependencies" => {
                    result.development_dependencies = Some(map.next_value::<StrictStringMap>()?.0);
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(result)
    }
}

struct StrictStringMap(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for StrictStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(StrictStringMapVisitor)
    }
}

struct StrictStringMapVisitor;

impl<'de> Visitor<'de> for StrictStringMapVisitor {
    type Value = StrictStringMap;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a duplicate-free string map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, String>()? {
            if result.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!(
                    "duplicate dependency key {key:?}"
                )));
            }
        }
        Ok(StrictStringMap(result))
    }
}

fn read_regular_input(path: &Path, maximum: u64) -> Result<Vec<u8>, NativeError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| NativeError::Io(format!("open {}: {error}", path.display())))?;
    let before = fstat(&descriptor)
        .map_err(|error| NativeError::Io(format!("inspect {}: {error}", path.display())))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
        return Err(NativeError::Io(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if before.st_size < 0 {
        return Err(NativeError::Io(format!(
            "{} has a negative size",
            path.display()
        )));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| NativeError::Io(format!("{} size does not fit u64", path.display())))?;
    if size > maximum {
        return Err(NativeError::Io(format!(
            "{} exceeds {maximum} bytes",
            path.display()
        )));
    }
    let capacity = usize::try_from(size)
        .map_err(|_| NativeError::Io(format!("{} size does not fit usize", path.display())))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(descriptor);
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| NativeError::Io(format!("read {}: {error}", path.display())))?;
    if bytes.len() != capacity {
        return Err(NativeError::Io(format!(
            "{} changed size or was truncated while reading",
            path.display()
        )));
    }
    let after = fstat(&file)
        .map_err(|error| NativeError::Io(format!("reinspect {}: {error}", path.display())))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(NativeError::Io(format!(
            "{} identity changed while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), NativeError> {
    if hex_lower(&Sha256::digest(bytes)) != expected {
        return Err(NativeError::Contract(format!(
            "{label} does not match its pinned SHA-256"
        )));
    }
    Ok(())
}

fn create_private_work_directory(path: &Path) -> Result<(), NativeError> {
    let mut builder = std::fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(path)
        .map_err(|error| NativeError::Io(format!("create private work directory: {error}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| NativeError::Io(format!("set private work mode: {error}")))
}

fn create_directory(path: &Path, mode: u32) -> Result<(), NativeError> {
    let mut builder = std::fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, mode);
    builder
        .create(path)
        .map_err(|error| NativeError::Io(format!("create {}: {error}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| NativeError::Io(format!("set mode on {}: {error}", path.display())))
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), NativeError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options
        .open(path)
        .map_err(|error| NativeError::Io(format!("create {}: {error}", path.display())))?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|error| NativeError::Io(format!("set mode on {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| NativeError::Io(format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| NativeError::Io(format!("fsync {}: {error}", path.display())))
}

fn extract_electron_runtime(bytes: &[u8], output: &Path) -> Result<(), NativeError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| NativeError::Io(format!("parse pinned Electron ZIP: {error}")))?;
    if archive.is_empty() || archive.len() > MAX_RUNTIME_ENTRIES {
        return Err(NativeError::Io(format!(
            "Electron ZIP entry count is outside 1..={MAX_RUNTIME_ENTRIES}"
        )));
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| NativeError::Io(format!("open Electron ZIP entry: {error}")))?;
        if entry.is_symlink() {
            return Err(NativeError::Io(
                "Electron ZIP contains a symlink".to_owned(),
            ));
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(NativeError::Io(
                "Electron ZIP uses unsupported compression".to_owned(),
            ));
        }
        if entry.compressed_size() == 0 {
            if entry.size() != 0 {
                return Err(NativeError::Io(
                    "Electron ZIP declares zero compressed bytes for nonempty data".to_owned(),
                ));
            }
        } else if entry.size() > entry.compressed_size().saturating_mul(100) {
            return Err(NativeError::Io(
                "Electron ZIP member exceeds 100:1 compression ratio".to_owned(),
            ));
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| NativeError::Io("Electron ZIP size sum overflowed".to_owned()))?;
        if total > MAX_RUNTIME_UNCOMPRESSED_BYTES {
            return Err(NativeError::Io(format!(
                "Electron ZIP exceeds {MAX_RUNTIME_UNCOMPRESSED_BYTES} uncompressed bytes"
            )));
        }
        let (relative, directory) = safe_archive_path(entry.name_raw(), entry.is_dir())?;
        if !names.insert(relative.clone()) {
            return Err(NativeError::Io(format!(
                "duplicate Electron ZIP path {relative:?}"
            )));
        }
        let destination = output.join(&relative);
        if directory {
            create_all_directories(&destination, output)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            create_all_directories(parent, output)?;
        }
        let mode = entry
            .unix_mode()
            .map_or(0o644, |mode| if mode & 0o111 != 0 { 0o755 } else { 0o644 });
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(mode);
        let mut file = options.open(&destination).map_err(|error| {
            NativeError::Io(format!("create runtime {}: {error}", destination.display()))
        })?;
        let copied = std::io::copy(&mut entry, &mut file).map_err(|error| {
            NativeError::Io(format!(
                "extract runtime {}: {error}",
                destination.display()
            ))
        })?;
        if copied != entry.size() {
            return Err(NativeError::Io(format!(
                "runtime member length changed for {}",
                destination.display()
            )));
        }
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|error| {
                NativeError::Io(format!(
                    "set runtime mode {}: {error}",
                    destination.display()
                ))
            })?;
        file.sync_all().map_err(|error| {
            NativeError::Io(format!("fsync runtime {}: {error}", destination.display()))
        })?;
    }
    Ok(())
}

fn extract_electron_headers(bytes: &[u8], output: &Path) -> Result<(), NativeError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| NativeError::Io(format!("parse pinned Electron headers: {error}")))?;
    let mut names = BTreeSet::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    for entry in entries {
        let mut entry = entry
            .map_err(|error| NativeError::Io(format!("read Electron header entry: {error}")))?;
        count = count
            .checked_add(1)
            .ok_or_else(|| NativeError::Io("header entry count overflowed".to_owned()))?;
        if count > MAX_HEADER_ENTRIES {
            return Err(NativeError::Io(format!(
                "Electron headers exceed {MAX_HEADER_ENTRIES} entries"
            )));
        }
        let entry_type = entry.header().entry_type();
        let directory = entry_type.is_dir();
        if !directory && !entry_type.is_file() {
            return Err(NativeError::Io(
                "Electron headers contain a link or special file".to_owned(),
            ));
        }
        let size = entry.size();
        total = total
            .checked_add(size)
            .ok_or_else(|| NativeError::Io("header size sum overflowed".to_owned()))?;
        if total > MAX_HEADER_UNCOMPRESSED_BYTES {
            return Err(NativeError::Io(format!(
                "Electron headers exceed {MAX_HEADER_UNCOMPRESSED_BYTES} bytes"
            )));
        }
        let path_bytes = entry.path_bytes();
        let (relative, _) = safe_archive_path(&path_bytes, directory)?;
        if !names.insert(relative.clone()) {
            return Err(NativeError::Io(format!(
                "duplicate Electron header path {relative:?}"
            )));
        }
        let destination = output.join(&relative);
        if directory {
            create_all_directories(&destination, output)?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            create_all_directories(parent, output)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o644);
        let mut file = options.open(&destination).map_err(|error| {
            NativeError::Io(format!("create header {}: {error}", destination.display()))
        })?;
        let copied = std::io::copy(&mut entry, &mut file).map_err(|error| {
            NativeError::Io(format!("extract header {}: {error}", destination.display()))
        })?;
        if copied != size {
            return Err(NativeError::Io(format!(
                "header length changed for {}",
                destination.display()
            )));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .map_err(|error| {
                NativeError::Io(format!(
                    "set header mode {}: {error}",
                    destination.display()
                ))
            })?;
    }
    Ok(())
}

fn safe_archive_path(raw: &[u8], directory: bool) -> Result<(String, bool), NativeError> {
    if raw.is_empty()
        || raw.len() > 4096
        || raw
            .iter()
            .any(|byte| !(0x20..=0x7e).contains(byte) || matches!(*byte, b'\\' | b':' | 0))
    {
        return Err(NativeError::Io(
            "archive path is not bounded safe printable ASCII".to_owned(),
        ));
    }
    let name = std::str::from_utf8(raw)
        .map_err(|_| NativeError::Io("archive path is not UTF-8".to_owned()))?;
    if name.starts_with('/') {
        return Err(NativeError::Io("absolute archive path".to_owned()));
    }
    let core = name.strip_suffix('/').unwrap_or(name);
    if core.is_empty()
        || core
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(NativeError::Io(
            "archive path contains traversal or an empty component".to_owned(),
        ));
    }
    if name.ends_with('/') != directory {
        return Err(NativeError::Io(
            "archive path/type directory conflict".to_owned(),
        ));
    }
    Ok((core.to_owned(), directory))
}

fn create_all_directories(path: &Path, root: &Path) -> Result<(), NativeError> {
    if !path.starts_with(root) {
        return Err(NativeError::Io(
            "refused to create a directory outside the private root".to_owned(),
        ));
    }
    std::fs::create_dir_all(path)
        .map_err(|error| NativeError::Io(format!("create {}: {error}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| NativeError::Io(format!("set mode on {}: {error}", path.display())))
}

fn command_version(
    program: &Path,
    arguments: &[&str],
    working_directory: &Path,
    environment: BTreeMap<OsString, OsString>,
) -> Result<String, NativeError> {
    let output = run_successful(
        ProcessSpec {
            program: program.to_owned(),
            arguments: arguments.iter().map(OsString::from).collect(),
            working_directory: working_directory.to_owned(),
            environment,
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 64 * 1024,
        },
        &format!("{} version", program.display()),
    )?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| NativeError::Command("version output is not UTF-8".to_owned()))?
        .trim();
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(NativeError::Command(
            "version output violates ASCII/size bounds".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn host_tool_environment(node_program: &Path) -> Result<BTreeMap<OsString, OsString>, NativeError> {
    let parent = node_program.parent().ok_or_else(|| {
        NativeError::Contract("host Node.js program has no parent directory".to_owned())
    })?;
    let parent = parent.to_str().ok_or_else(|| {
        NativeError::Contract("host Node.js parent directory is not UTF-8".to_owned())
    })?;
    if parent.contains([':', '\n', '\r', '\0']) {
        return Err(NativeError::Contract(
            "host Node.js parent directory cannot be represented safely in PATH".to_owned(),
        ));
    }
    let mut environment = base_environment();
    environment.insert(
        OsString::from("PATH"),
        OsString::from(format!("{parent}:/usr/bin:/bin")),
    );
    Ok(environment)
}

fn inspect_electron_runtime(
    program: &Path,
    working_directory: &Path,
) -> Result<ElectronRuntimeIdentity, NativeError> {
    let mut environment = base_environment();
    environment.insert(OsString::from("ELECTRON_RUN_AS_NODE"), OsString::from("1"));
    let expression = concat!(
        "JSON.stringify({electron:process.versions.electron,",
        "node:process.versions.node,modules:Number(process.versions.modules),",
        "napi:Number(process.versions.napi),arch:process.arch,",
        "platform:process.platform})"
    );
    let output = run_successful(
        ProcessSpec {
            program: program.to_owned(),
            arguments: vec![OsString::from("-p"), OsString::from(expression)],
            working_directory: working_directory.to_owned(),
            environment,
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 64 * 1024,
        },
        "Electron runtime identity probe",
    )?;
    serde_json::from_slice(&output.stdout)
        .map_err(|error| NativeError::Runtime(format!("parse Electron identity: {error}")))
}

fn validate_runtime_identity(
    runtime: &ElectronRuntimeIdentity,
    contract: &NativeContract,
) -> Result<(), NativeError> {
    if runtime.electron != contract.electron.version
        || runtime.node != contract.electron.node_version
        || runtime.modules != contract.electron.module_abi
        || runtime.napi != contract.electron.napi
        || runtime.arch != "x64"
        || runtime.platform != "linux"
    {
        return Err(NativeError::Runtime(format!(
            "observed runtime identity {runtime:?} differs from the exact contract"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct ObservedBuildEnvironment {
    node_version: String,
    npm_version: String,
    glibc_version: String,
    gcc_version: String,
}

fn inspect_build_environment(
    request: &NativeBuildRequest,
    contract: &NativeContract,
    working_directory: &Path,
    container_home: &Path,
) -> Result<ObservedBuildEnvironment, NativeError> {
    let inspection = run_oci_successful(
        request,
        vec![
            OsString::from("image"),
            OsString::from("inspect"),
            OsString::from("--format={{.Architecture}}|{{.Os}}"),
            OsString::from(&contract.build_image.reference),
        ],
        &request.work_directory,
        Duration::from_secs(30),
        64 * 1024,
        "inspect native build image",
    )?;
    let identity = single_ascii_line(&inspection.stdout, "OCI image identity")?;
    if identity
        != format!(
            "{}|{}",
            contract.build_image.architecture, contract.build_image.operating_system
        )
    {
        return Err(NativeError::Contract(format!(
            "native build image platform is {identity:?}, not the pinned Linux amd64 platform"
        )));
    }

    let environment = container_base_environment(container_home);
    let node_version = container_version(
        request,
        contract,
        working_directory,
        container_home,
        environment.clone(),
        ["/usr/local/bin/node", "--version"],
        "build-image Node.js",
    )?
    .trim_start_matches('v')
    .to_owned();
    let npm_version = container_version(
        request,
        contract,
        working_directory,
        container_home,
        environment.clone(),
        ["/usr/local/bin/npm", "--version"],
        "build-image npm",
    )?;
    let glibc_report = container_version(
        request,
        contract,
        working_directory,
        container_home,
        environment.clone(),
        ["/usr/bin/getconf", "GNU_LIBC_VERSION"],
        "build-image glibc",
    )?;
    let glibc_version = glibc_report
        .strip_prefix("glibc ")
        .ok_or_else(|| {
            NativeError::Contract("build-image glibc report has an unexpected format".to_owned())
        })?
        .to_owned();
    let gcc_version = container_version(
        request,
        contract,
        working_directory,
        container_home,
        environment,
        ["/usr/bin/gcc", "-dumpfullversion"],
        "build-image GCC",
    )?;
    let observed = ObservedBuildEnvironment {
        node_version,
        npm_version,
        glibc_version,
        gcc_version,
    };
    if observed.node_version != contract.build_image.node_version
        || observed.npm_version != contract.build_image.npm_version
        || observed.glibc_version != contract.build_image.glibc_version
        || observed.gcc_version != contract.build_image.gcc_version
    {
        return Err(NativeError::Contract(format!(
            "observed build image tooling {observed:?} differs from its exact contract"
        )));
    }
    Ok(observed)
}

fn container_version<const N: usize>(
    request: &NativeBuildRequest,
    contract: &NativeContract,
    working_directory: &Path,
    container_home: &Path,
    environment: BTreeMap<OsString, OsString>,
    command: [&str; N],
    label: &str,
) -> Result<String, NativeError> {
    let output = run_container_successful(
        request,
        contract,
        working_directory,
        container_home,
        environment,
        command.into_iter().map(OsString::from).collect(),
        Duration::from_secs(30),
        64 * 1024,
        false,
        label,
    )?;
    single_ascii_line(&output.stdout, label)
}

fn single_ascii_line(bytes: &[u8], label: &str) -> Result<String, NativeError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| NativeError::Command(format!("{label} output is not UTF-8")))?
        .trim();
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(NativeError::Command(format!(
            "{label} output violates the single-line ASCII contract"
        )));
    }
    Ok(value.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn run_container_successful(
    request: &NativeBuildRequest,
    contract: &NativeContract,
    working_directory: &Path,
    container_home: &Path,
    environment: BTreeMap<OsString, OsString>,
    command: Vec<OsString>,
    timeout: Duration,
    maximum_output_bytes: usize,
    allow_network: bool,
    label: &str,
) -> Result<ProcessOutput, NativeError> {
    if command.is_empty() {
        return Err(NativeError::Contract(
            "native container command is empty".to_owned(),
        ));
    }
    let work = safe_container_path(&request.work_directory, "native work directory")?;
    let cache = safe_container_path(&request.npm_cache, "npm cache")?;
    let current = safe_container_path(working_directory, "container working directory")?;
    let _home = safe_container_path(container_home, "container home")?;
    if !working_directory.starts_with(&request.work_directory)
        || !container_home.starts_with(&request.work_directory)
    {
        return Err(NativeError::Contract(
            "container paths must remain beneath the private native work directory".to_owned(),
        ));
    }
    let metadata = std::fs::symlink_metadata(&request.work_directory)
        .map_err(|error| NativeError::Io(format!("inspect native work owner: {error}")))?;
    if !metadata.file_type().is_dir() {
        return Err(NativeError::Io(
            "native work root is not a real directory".to_owned(),
        ));
    }
    let mut arguments = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--platform=linux/amd64"),
        OsString::from("--init"),
        OsString::from("--read-only"),
        OsString::from("--cap-drop=ALL"),
        OsString::from("--security-opt=no-new-privileges"),
        OsString::from("--pids-limit=512"),
        OsString::from(format!(
            "--network={}",
            if allow_network { "bridge" } else { "none" }
        )),
        OsString::from("--user"),
        OsString::from(format!("{}:{}", metadata.uid(), metadata.gid())),
        OsString::from("--tmpfs=/tmp:rw,nosuid,nodev,size=536870912,mode=1777"),
        OsString::from("--mount"),
        OsString::from(format!("type=bind,src={work},dst={work}")),
        OsString::from("--mount"),
        OsString::from(format!("type=bind,src={cache},dst={cache}")),
        OsString::from("--workdir"),
        OsString::from(current),
    ];
    for (key, value) in environment {
        let key = key.into_string().map_err(|_| {
            NativeError::Contract("container environment key is not UTF-8".to_owned())
        })?;
        let value = value.into_string().map_err(|_| {
            NativeError::Contract("container environment value is not UTF-8".to_owned())
        })?;
        if key.contains('=') || key.is_empty() || value.contains('\0') {
            return Err(NativeError::Contract(
                "container environment contains an unsafe key or value".to_owned(),
            ));
        }
        arguments.push(OsString::from("--env"));
        arguments.push(OsString::from(format!("{key}={value}")));
    }
    arguments.push(OsString::from(&contract.build_image.reference));
    arguments.extend(command);
    run_oci_successful(
        request,
        arguments,
        &request.work_directory,
        timeout,
        maximum_output_bytes,
        label,
    )
}

fn safe_container_path(path: &Path, label: &str) -> Result<String, NativeError> {
    let value = path
        .to_str()
        .ok_or_else(|| NativeError::Contract(format!("{label} is not UTF-8")))?;
    if value.contains([',', ':', '\n', '\r', '\0']) {
        return Err(NativeError::Contract(format!(
            "{label} cannot be represented safely as an OCI bind mount"
        )));
    }
    Ok(value.to_owned())
}

fn run_oci_successful(
    request: &NativeBuildRequest,
    mut arguments: Vec<OsString>,
    working_directory: &Path,
    timeout: Duration,
    maximum_output_bytes: usize,
    label: &str,
) -> Result<ProcessOutput, NativeError> {
    let (program, arguments) = if let Some(sudo) = &request.sudo_program {
        let mut wrapped = vec![
            OsString::from("-n"),
            request.oci_runtime.as_os_str().to_owned(),
        ];
        wrapped.append(&mut arguments);
        (sudo.clone(), wrapped)
    } else {
        (request.oci_runtime.clone(), arguments)
    };
    run_successful(
        ProcessSpec {
            program,
            arguments,
            working_directory: working_directory.to_owned(),
            environment: base_environment(),
            timeout,
            maximum_output_bytes,
        },
        label,
    )
}

fn container_base_environment(container_home: &Path) -> BTreeMap<OsString, OsString> {
    let mut environment = base_environment();
    environment.insert(
        OsString::from("PATH"),
        OsString::from("/usr/local/bin:/usr/bin:/bin"),
    );
    environment.insert(
        OsString::from("HOME"),
        container_home.as_os_str().to_owned(),
    );
    environment
}

fn native_environment(
    request: &NativeBuildRequest,
    contract: &NativeContract,
    header_root: &Path,
    project_directory: &Path,
    container_home: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut environment = container_base_environment(container_home);
    for (key, value) in [
        ("CC", OsString::from("/usr/bin/gcc")),
        ("CXX", OsString::from("/usr/bin/g++")),
        ("AR", OsString::from("/usr/bin/ar")),
        ("npm_config_python", OsString::from("/usr/bin/python3")),
        ("npm_config_cache", request.npm_cache.as_os_str().to_owned()),
        ("npm_config_nodedir", header_root.as_os_str().to_owned()),
        (
            "npm_config_target",
            OsString::from(&contract.electron.version),
        ),
        ("npm_config_arch", OsString::from("x64")),
        ("npm_config_target_arch", OsString::from("x64")),
        ("npm_config_runtime", OsString::from("electron")),
        ("npm_config_build_from_source", OsString::from("true")),
        ("npm_config_jobs", OsString::from("1")),
        ("npm_config_audit", OsString::from("false")),
        ("npm_config_fund", OsString::from("false")),
        ("npm_config_update_notifier", OsString::from("false")),
        ("npm_config_progress", OsString::from("false")),
        ("npm_config_loglevel", OsString::from("warn")),
        ("ELECTRON_SKIP_BINARY_DOWNLOAD", OsString::from("1")),
        (
            "NATIVE_PROJECT_DIR",
            project_directory.as_os_str().to_owned(),
        ),
        ("HOME", container_home.as_os_str().to_owned()),
    ] {
        environment.insert(OsString::from(key), value);
    }
    environment
}

fn base_environment() -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (OsString::from("LC_ALL"), OsString::from("C.UTF-8")),
        (OsString::from("TZ"), OsString::from("UTC")),
        (OsString::from("SOURCE_DATE_EPOCH"), OsString::from("0")),
    ])
}

fn run_successful(specification: ProcessSpec, label: &str) -> Result<ProcessOutput, NativeError> {
    let output = run_bounded(&specification)
        .map_err(|error| NativeError::Command(format!("{label}: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(NativeError::Command(format!(
            "{label} exited with {}; stdout={stdout:?}; stderr={stderr:?}",
            output.status
        )));
    }
    Ok(output)
}

fn require_minimum_version(actual: &str, minimum: &str, label: &str) -> Result<(), NativeError> {
    let actual = parse_three_part_version(actual, label)?;
    let minimum = parse_three_part_version(minimum, label)?;
    if actual < minimum {
        return Err(NativeError::Contract(format!(
            "{label} is below required {minimum:?}"
        )));
    }
    Ok(())
}

fn parse_three_part_version(value: &str, label: &str) -> Result<(u64, u64, u64), NativeError> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(NativeError::Contract(format!(
            "{label} version is not three-part numeric"
        )));
    }
    let parse = |part: &str| {
        part.parse::<u64>().map_err(|_| {
            NativeError::Contract(format!("{label} version is not three-part numeric"))
        })
    };
    Ok((parse(parts[0])?, parse(parts[1])?, parse(parts[2])?))
}

fn audit_native_glibc(
    request: &NativeBuildRequest,
    contract: &NativeContract,
    path: &Path,
    working_directory: &Path,
    container_home: &Path,
) -> Result<(Vec<String>, Option<String>), NativeError> {
    let output = run_container_successful(
        request,
        contract,
        working_directory,
        container_home,
        container_base_environment(container_home),
        vec![
            OsString::from("/usr/bin/readelf"),
            OsString::from("--wide"),
            OsString::from("--version-info"),
            path.as_os_str().to_owned(),
        ],
        Duration::from_secs(30),
        2 * 1024 * 1024,
        false,
        "audit native GLIBC requirements",
    )?;
    let report = std::str::from_utf8(&output.stdout)
        .map_err(|_| NativeError::Elf("readelf output is not UTF-8".to_owned()))?;
    let mut versions = BTreeSet::new();
    for line in report.lines() {
        for token in line.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
        }) {
            if let Some(version) = token.strip_prefix("GLIBC_") {
                if parse_glibc_version(version).is_some() {
                    versions.insert(token.to_owned());
                }
            }
        }
    }
    let maximum = versions
        .iter()
        .max_by_key(|value| {
            parse_glibc_version(value.trim_start_matches("GLIBC_")).unwrap_or((0, 0, 0))
        })
        .cloned();
    let allowed = parse_glibc_version(&contract.build_image.maximum_output_glibc_version)
        .ok_or_else(|| NativeError::Contract("invalid maximum output glibc version".to_owned()))?;
    if maximum
        .as_deref()
        .and_then(|value| parse_glibc_version(value.trim_start_matches("GLIBC_")))
        .is_some_and(|observed| observed > allowed)
    {
        return Err(NativeError::Elf(format!(
            "{} requires {:?}, newer than the controlled GLIBC_{} baseline",
            path.display(),
            maximum,
            contract.build_image.maximum_output_glibc_version
        )));
    }
    Ok((versions.into_iter().collect(), maximum))
}

fn parse_glibc_version(value: &str) -> Option<(u32, u32, u32)> {
    let mut components = value.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components
        .next()
        .map(str::parse)
        .transpose()
        .ok()?
        .unwrap_or(0);
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn run_native_probes(
    runtime_program: &Path,
    project_directory: &Path,
    work_directory: &Path,
) -> Result<(), NativeError> {
    let sqlite_script = work_directory.join("probe-sqlite.cjs");
    let pty_script = work_directory.join("probe-pty.cjs");
    write_new_file(
        &sqlite_script,
        br#"const path = require("node:path");
const Database = require(path.join(process.env.NATIVE_PROJECT_DIR, "node_modules", "better-sqlite3"));
const db = new Database(":memory:");
db.exec("CREATE TABLE proof(value TEXT NOT NULL)");
db.prepare("INSERT INTO proof(value) VALUES (?)").run("sqlite-ok");
const value = db.prepare("SELECT value FROM proof").pluck().get();
db.close();
if (value !== "sqlite-ok") throw new Error("SQLite round trip differed");
process.stdout.write("sqlite-ok\n");
"#,
        0o600,
    )?;
    write_new_file(
        &pty_script,
        br#"const path = require("node:path");
const pty = require(path.join(process.env.NATIVE_PROJECT_DIR, "node_modules", "node-pty"));
const child = pty.spawn("/usr/bin/printf", ["pty-ok"], {
  name: "xterm-256color", cols: 80, rows: 24, cwd: "/", env: { LANG: "C.UTF-8" }
});
let output = "";
const timer = setTimeout(() => { child.kill(); throw new Error("PTY probe timed out"); }, 5000);
child.onData(data => { output += data; });
child.onExit(() => {
  clearTimeout(timer);
  if (!output.includes("pty-ok")) throw new Error("PTY round trip differed");
  process.stdout.write("pty-ok\n");
});
"#,
        0o600,
    )?;
    let mut environment = base_environment();
    environment.insert(OsString::from("ELECTRON_RUN_AS_NODE"), OsString::from("1"));
    environment.insert(
        OsString::from("NATIVE_PROJECT_DIR"),
        project_directory.as_os_str().to_owned(),
    );
    let sqlite = run_successful(
        ProcessSpec {
            program: runtime_program.to_owned(),
            arguments: vec![sqlite_script.into_os_string()],
            working_directory: work_directory.to_owned(),
            environment: environment.clone(),
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 1024 * 1024,
        },
        "SQLite Electron probe",
    )?;
    if sqlite.stdout != b"sqlite-ok\n" {
        return Err(NativeError::Runtime(
            "SQLite probe emitted unexpected stdout".to_owned(),
        ));
    }
    let pty = run_successful(
        ProcessSpec {
            program: runtime_program.to_owned(),
            arguments: vec![pty_script.into_os_string()],
            working_directory: work_directory.to_owned(),
            environment,
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 1024 * 1024,
        },
        "PTY Electron probe",
    )?;
    if pty.stdout != b"pty-ok\n" {
        return Err(NativeError::Runtime(
            "PTY probe emitted unexpected stdout".to_owned(),
        ));
    }
    Ok(())
}

fn validate_linux_x86_64_elf(bytes: &[u8], label: &str) -> Result<(), NativeError> {
    if bytes.len() < 64 || bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(NativeError::Elf(format!("{label:?} is not an ELF file")));
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(NativeError::Elf(format!(
            "{label:?} is not 64-bit little-endian ELF version 1"
        )));
    }
    if !matches!(bytes[7], 0 | 3) {
        return Err(NativeError::Elf(format!(
            "{label:?} has an unsupported ELF OS ABI"
        )));
    }
    let file_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 62 {
        return Err(NativeError::Elf(format!(
            "{label:?} is not x86_64 (e_machine={machine})"
        )));
    }
    if label.ends_with(".node") {
        if file_type != 3 {
            return Err(NativeError::Elf(format!(
                "{label:?} is not a shared-object ELF"
            )));
        }
    } else if !matches!(file_type, 2 | 3) {
        return Err(NativeError::Elf(format!(
            "{label:?} is not an executable or position-independent ELF"
        )));
    }
    Ok(())
}

fn publish_native_outputs(
    output: &Path,
    binaries: &[(&str, Vec<u8>, u32)],
    manifest: &NativeManifest,
) -> Result<(), NativeError> {
    let manifest_bytes = to_json_line(manifest)
        .map_err(|error| NativeError::Publication(format!("encode manifest: {error}")))?;
    let mut publisher =
        TreePublisher::new(output).map_err(|error| NativeError::Publication(error.to_string()))?;
    let preparation = (|| -> Result<(), ExtractionError> {
        for (path, bytes, mode) in binaries {
            publisher.write_file(path, bytes, *mode)?;
        }
        publisher.write_file("manifest.json", manifest_bytes.as_bytes(), 0o644)?;
        Ok(())
    })();
    if let Err(error) = preparation {
        return Err(publisher_cleanup_error(
            &mut publisher,
            NativeError::Publication(error.to_string()),
        ));
    }
    if let Err(error) = publisher.commit() {
        if matches!(error, ExtractionError::PostCommitDurability(_)) {
            return Err(NativeError::Publication(error.to_string()));
        }
        return Err(publisher_cleanup_error(
            &mut publisher,
            NativeError::Publication(error.to_string()),
        ));
    }
    Ok(())
}

fn publisher_cleanup_error(publisher: &mut TreePublisher, original: NativeError) -> NativeError {
    match publisher.cleanup() {
        Ok(()) => original,
        Err(cleanup) => NativeError::Publication(format!(
            "{original}; private output cleanup was intentionally incomplete: {cleanup}"
        )),
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), NativeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NativeError::Contract(format!(
            "{label} SHA-256 is not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn validate_base64_sha512(value: &str) -> Result<(), NativeError> {
    let decoded = BASE64_STANDARD
        .decode(value.as_bytes())
        .map_err(|_| NativeError::Contract("npm SHA-512 is not valid base64".to_owned()))?;
    if decoded.len() != 64 || BASE64_STANDARD.encode(&decoded) != value {
        return Err(NativeError::Contract(
            "npm SHA-512 is not canonical standard base64".to_owned(),
        ));
    }
    Ok(())
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
    use super::{NativeError, replace_exact_once};

    #[test]
    fn exact_source_replacement_requires_one_match() {
        assert_eq!(
            replace_exact_once(b"before middle after", b"middle", b"patched", "fixture")
                .expect("one exact match"),
            b"before patched after"
        );
        assert!(matches!(
            replace_exact_once(b"same same", b"same", b"new", "fixture"),
            Err(NativeError::Contract(message)) if message.contains("exactly once")
        ));
        assert!(matches!(
            replace_exact_once(b"absent", b"same", b"new", "fixture"),
            Err(NativeError::Contract(message)) if message.contains("exactly once")
        ));
    }
}
