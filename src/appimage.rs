//! Deterministic, network-isolated Type-2 AppImage construction and audit.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::appdir::{
    AppDirError, AppDirManifest, validate_appdir_generation, validate_extracted_appdir_generation,
};
use crate::extract::{ExtractionError, TreePublisher};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::process::{ProcessError, ProcessSpec, run_bounded, run_bounded_observing_timeout};

const CONTRACT_JSON: &str = include_str!("../data/appimage-contract.json");
const BASELINE_DOCKERFILE: &[u8] = include_bytes!("../containers/appimage-baseline.Dockerfile");
const BASELINE_SNAPSHOT_SOURCES: &[u8] = include_bytes!("../containers/debian-snapshot.sources");
const PUBLICATION_SCOPE: &str = "bytes_at_durable_commit_boundary_under_documented_threat_model";
const MAX_TOOL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_SYSTEM_TOOL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_APPIMAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROVENANCE_BYTES: usize = 4 * 1024 * 1024;
const PROVENANCE_NAME: &str = "provenance.json";

/// Exact tagged appimagetool input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppImageToolContract {
    /// Stable release tag.
    pub release: String,
    /// Exact source revision.
    pub revision: String,
    /// Exact release-asset SHA-256.
    pub sha256: String,
    /// Exact release-asset bytes.
    pub bytes: u64,
}

/// Independently tagged and signed Type-2 runtime input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Type2RuntimeContract {
    /// Stable release tag.
    pub release: String,
    /// Exact source revision.
    pub revision: String,
    /// Exact release-asset SHA-256.
    pub sha256: String,
    /// Exact release-asset bytes.
    pub bytes: u64,
    /// Independently recorded upstream signing-key fingerprint.
    pub signing_fingerprint: String,
    /// Only runtime byte range appimagetool may fill in the final artifact.
    pub digest_mutation_offset: u64,
    /// Exact MD5 section size.
    pub digest_mutation_bytes: u64,
}

/// Deterministic SquashFS settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SquashfsContract {
    /// Compression algorithm.
    pub algorithm: String,
    /// Data block bytes.
    pub block_bytes: u64,
    /// Fixed compressor worker count.
    pub processors: u32,
    /// Whether filesystem xattrs are retained.
    pub xattrs: bool,
}

/// Controlled older-glibc X11 launch environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OlderGlibcBaselineContract {
    /// Required image identity label.
    pub identity_label: String,
    /// Digest-addressed base image recorded in the image label.
    pub base_image: String,
    /// Exact Debian snapshot labels.
    pub debian_snapshots: String,
    /// OCI architecture.
    pub architecture: String,
    /// OCI operating system.
    pub operating_system: String,
    /// Non-root image user.
    pub user: String,
    /// Exact glibc version observed at test time.
    pub glibc_version: String,
    /// Repository baseline Dockerfile identity.
    pub dockerfile_sha256: String,
    /// Repository Debian sources identity.
    pub snapshot_sources_sha256: String,
    /// Sorted installed package/version inventory identity.
    pub package_manifest_sha256: String,
    /// Exact installed package count.
    pub package_count: u32,
    /// Bounded healthy-launch observation window.
    pub launch_timeout_seconds: u64,
}

/// Exact AppImage construction contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppImageContract {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Only supported target.
    pub target: String,
    /// Fixed artifact filename inside the published generation.
    pub artifact_filename: String,
    /// Exact appimagetool.
    pub appimagetool: AppImageToolContract,
    /// Exact Type-2 runtime.
    pub type2_runtime: Type2RuntimeContract,
    /// Exact filesystem-image settings.
    pub compression: SquashfsContract,
    /// Exact controlled older-glibc test environment.
    pub older_glibc_baseline: OlderGlibcBaselineContract,
}

/// Display backend exercised by a genuine packaged launch test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchBackend {
    /// Native Wayland launch.
    Wayland,
    /// X11/XWayland launch.
    X11,
}

/// Inputs for one twice-built, network-isolated AppImage generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppImageRequest {
    /// First deterministic AppDir.
    pub appdir: PathBuf,
    /// Independently recorded first AppDir manifest SHA-256.
    pub appdir_manifest_sha256: String,
    /// Independently constructed AppDir under another root.
    pub reproduction_appdir: PathBuf,
    /// Independently recorded second AppDir manifest SHA-256.
    pub reproduction_appdir_manifest_sha256: String,
    /// Exact stable-tag appimagetool release asset.
    pub appimagetool: PathBuf,
    /// Exact stable-tag Type-2 runtime release asset.
    pub type2_runtime: PathBuf,
    /// Bubblewrap executable used to remove network access.
    pub bubblewrap: PathBuf,
    /// Independently recorded bubblewrap executable SHA-256.
    pub bubblewrap_sha256: String,
    /// GNU readelf executable used for complete ELF audits.
    pub readelf: PathBuf,
    /// Independently recorded readelf executable SHA-256.
    pub readelf_sha256: String,
    /// OCI runtime used for the controlled older-glibc launch.
    pub oci_runtime: PathBuf,
    /// Independently recorded SHA-256 of the OCI runtime.
    pub oci_runtime_sha256: String,
    /// Optional noninteractive sudo executable used only to launch the OCI runtime.
    pub sudo_program: Option<PathBuf>,
    /// Independently recorded SHA-256 of the optional sudo executable.
    pub sudo_sha256: Option<String>,
    /// Independently pinned local OCI image ID (`sha256:<64 lowercase hex>`).
    pub older_glibc_image_id: String,
    /// Genuine launch backends required before publication.
    pub launch_backends: Vec<LaunchBackend>,
    /// New output generation containing the AppImage and provenance.
    pub output: PathBuf,
}

/// Final AppImage file identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppImageArtifact {
    /// Stable path in the output generation.
    pub path: String,
    /// Exact complete SHA-256.
    pub sha256: String,
    /// Exact complete bytes.
    pub bytes: u64,
    /// Published mode.
    pub mode: String,
}

/// Parsed dynamic-link and glibc requirements for one extracted ELF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfAuditEntry {
    /// AppDir-relative path.
    pub path: String,
    /// Exact file SHA-256 from AppDir provenance.
    pub sha256: String,
    /// Required ELF interpreter, when present.
    pub interpreter: Option<String>,
    /// Sorted DT_NEEDED library names.
    pub needed: Vec<String>,
    /// Sorted GLIBC symbol versions.
    pub glibc_versions: Vec<String>,
    /// Highest required GLIBC symbol version.
    pub maximum_glibc: Option<String>,
    /// SHA-256 of the bounded `readelf` report used for parsing.
    pub readelf_report_sha256: String,
}

/// Evidence from one genuine network-disabled AppImage launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAudit {
    /// Backend selected through AppRun.
    pub backend: LaunchBackend,
    /// Whether the healthy GUI remained live until the bounded deadline.
    pub timed_out_after_success: bool,
    /// Packaged-mode marker was observed.
    pub packaged_mode: bool,
    /// Exact Codex app-server handshake marker was observed.
    pub app_server_handshake: bool,
    /// Window-ready marker was observed.
    pub window_ready: bool,
    /// SHA-256 of bounded stdout plus stderr, without embedding user logs.
    pub log_sha256: String,
    /// Total retained log bytes.
    pub log_bytes: u64,
}

/// Evidence from a network-disabled launch in the controlled older baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OlderGlibcAudit {
    /// Independently pinned exact local OCI image ID.
    pub image_id: String,
    /// SHA-256 of the OCI runtime executable.
    pub oci_runtime_sha256: String,
    /// SHA-256 of the optional noninteractive sudo executable.
    pub sudo_sha256: Option<String>,
    /// Exact glibc version observed inside the image.
    pub glibc_version: String,
    /// SHA-256 of sorted `package<TAB>version` inventory.
    pub package_manifest_sha256: String,
    /// Installed package count.
    pub package_count: u32,
    /// True after the X11/Xvfb AppImage remained healthy until timeout.
    pub timed_out_after_success: bool,
    /// Packaged mode marker was observed.
    pub packaged_mode: bool,
    /// Exact app-server handshake marker was observed.
    pub app_server_handshake: bool,
    /// Window-ready marker was observed.
    pub window_ready: bool,
    /// Chromium user-namespace sandbox policy exercised.
    pub sandbox_policy: String,
    /// SHA-256 of bounded test logs.
    pub log_sha256: String,
    /// Retained test log bytes.
    pub log_bytes: u64,
}

/// Truthful final AppImage provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppImageManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Truthful publication guarantee scope.
    pub publication_scope: String,
    /// Codex desktop application version carried by this AppImage.
    pub application_version: String,
    /// Codex desktop application build carried by this AppImage.
    pub application_build: String,
    /// Final AppImage identity.
    pub artifact: AppImageArtifact,
    /// Exact equal digest produced by the independent second build.
    pub reproduction_sha256: String,
    /// First AppDir manifest digest.
    pub appdir_manifest_sha256: String,
    /// Second AppDir manifest digest.
    pub reproduction_appdir_manifest_sha256: String,
    /// Explicit normalized timestamp.
    pub source_date_epoch: i64,
    /// Exact appimagetool release and digest.
    pub appimagetool: AppImageToolContract,
    /// Exact Type-2 runtime release and digest.
    pub type2_runtime: Type2RuntimeContract,
    /// Digest of the local network-isolation executable.
    pub bubblewrap_sha256: String,
    /// Digest of the ELF-audit executable.
    pub readelf_sha256: String,
    /// Exact SquashFS settings.
    pub compression: SquashfsContract,
    /// Network isolation actually used for both builds, extraction, and launch.
    pub network_isolation: String,
    /// Launch-descendant containment used for bounded process cleanup.
    pub process_containment: String,
    /// True only after byte equality from independent AppDir roots.
    pub twice_built_byte_identical: bool,
    /// True only after the final filesystem was extracted and revalidated.
    pub extracted_tree_verified: bool,
    /// Type-2 runtime derivation rule.
    pub runtime_derivation: String,
    /// Complete extracted ELF audit.
    pub elf_audit: Vec<ElfAuditEntry>,
    /// Requested real-launch evidence.
    pub launch_audits: Vec<LaunchAudit>,
    /// Controlled older-glibc X11 launch evidence.
    pub older_glibc_audit: OlderGlibcAudit,
    /// Deliberately truthful release status.
    pub release_status: String,
}

/// Invalid embedded contract or AppImage pipeline input.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AppImageError {
    /// Embedded contract is invalid.
    #[error("invalid AppImage contract: {0}")]
    Contract(String),
    /// AppDir validation failed.
    #[error("invalid AppImage input: {0}")]
    Input(String),
    /// A subprocess failed.
    #[error("AppImage subprocess failed: {0}")]
    Process(String),
    /// Reproducibility or extracted-artifact verification failed.
    #[error("AppImage verification failed: {0}")]
    Verification(String),
    /// Private work or output construction failed.
    #[error("AppImage transaction failed: {0}")]
    Transaction(String),
    /// No-replace publication failed before commit.
    #[error("AppImage publication failed before commit: {0}")]
    Publication(String),
    /// The name committed but parent durability is uncertain.
    #[error("AppImage generation committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

impl From<AppDirError> for AppImageError {
    fn from(error: AppDirError) -> Self {
        Self::Input(error.to_string())
    }
}

impl From<ProcessError> for AppImageError {
    fn from(error: ProcessError) -> Self {
        Self::Process(error.to_string())
    }
}

/// Parses and validates the embedded tagged-tool contract.
pub fn appimage_contract() -> Result<AppImageContract, AppImageError> {
    let contract: AppImageContract = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| AppImageError::Contract(error.to_string()))?;
    if contract.schema != SCHEMA_VERSION
        || contract.producer != PRODUCER_IDENTIFIER
        || contract.target != "linux-x86_64"
        || contract.artifact_filename != "codex-desktop-unofficial-x86_64.AppImage"
        || contract.appimagetool.release != "1.9.1"
        || contract.appimagetool.revision != "8c8c91f762b412a19f4e8d2c4b35afb98f2d7c81"
        || contract.appimagetool.sha256
            != "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
        || contract.appimagetool.bytes != 15_092_216
        || contract.type2_runtime.release != "20251108"
        || contract.type2_runtime.revision != "dd6cebedcbddde9c82f89b011e8e1d40b6e43868"
        || contract.type2_runtime.sha256
            != "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
        || contract.type2_runtime.bytes != 944_632
        || contract.type2_runtime.signing_fingerprint != "570C77ACEA40C0F1B758902CBF96CCA56490F695"
        || contract.type2_runtime.digest_mutation_offset != 932_096
        || contract.type2_runtime.digest_mutation_bytes != 16
        || contract.compression.algorithm != "zstd"
        || contract.compression.block_bytes != 131_072
        || contract.compression.processors != 1
        || contract.compression.xattrs
        || contract.older_glibc_baseline.identity_label != "bookworm-glibc-2.36-x11-v1"
        || contract.older_glibc_baseline.base_image
            != "docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c"
        || contract.older_glibc_baseline.debian_snapshots
            != "debian:20260730T082136Z,debian-security:20260730T083809Z"
        || contract.older_glibc_baseline.architecture != "amd64"
        || contract.older_glibc_baseline.operating_system != "linux"
        || contract.older_glibc_baseline.user != "node"
        || contract.older_glibc_baseline.glibc_version != "2.36"
        || contract.older_glibc_baseline.dockerfile_sha256
            != "1e7226769d1d71350d8d8b06ec796cd8cca164c16c9239ae8b04f363333ee4bd"
        || contract.older_glibc_baseline.snapshot_sources_sha256
            != "46bd640ebfad1490195a5837a8775eec93a5cb78f9ead22b9df5fe8b63537d7b"
        || contract.older_glibc_baseline.package_manifest_sha256
            != "cc2af6b523e352cee54afcfa4b0027f07bf2045d09c2cdd89ac3e5cd21b43bd7"
        || contract.older_glibc_baseline.package_count != 494
        || contract.older_glibc_baseline.launch_timeout_seconds != 25
        || hex_lower(&Sha256::digest(BASELINE_DOCKERFILE))
            != contract.older_glibc_baseline.dockerfile_sha256
        || hex_lower(&Sha256::digest(BASELINE_SNAPSHOT_SOURCES))
            != contract.older_glibc_baseline.snapshot_sources_sha256
    {
        return Err(AppImageError::Contract(
            "embedded values differ from the reviewed stable-tag contract".to_owned(),
        ));
    }
    for (value, label) in [
        (&contract.appimagetool.sha256, "appimagetool"),
        (&contract.type2_runtime.sha256, "Type-2 runtime"),
        (
            &contract.older_glibc_baseline.dockerfile_sha256,
            "older-glibc baseline Dockerfile",
        ),
        (
            &contract.older_glibc_baseline.snapshot_sources_sha256,
            "older-glibc snapshot sources",
        ),
        (
            &contract.older_glibc_baseline.package_manifest_sha256,
            "older-glibc package manifest",
        ),
    ] {
        validate_digest(value, label)?;
    }
    Ok(contract)
}

fn validate_digest(value: &str, label: &str) -> Result<(), AppImageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppImageError::Contract(format!(
            "{label} SHA-256 is not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

/// Builds twice without networking, requires equality, extracts and audits the
/// result, performs requested real launches, and atomically publishes one
/// AppImage with its provenance.
pub fn pack_appimage(request: &AppImageRequest) -> Result<AppImageManifest, AppImageError> {
    validate_request(request)?;
    let contract = appimage_contract()?;
    let first_appdir =
        validate_appdir_generation(&request.appdir, &request.appdir_manifest_sha256)?;
    let second_appdir = validate_appdir_generation(
        &request.reproduction_appdir,
        &request.reproduction_appdir_manifest_sha256,
    )?;
    if first_appdir != second_appdir
        || request.appdir_manifest_sha256 != request.reproduction_appdir_manifest_sha256
    {
        return Err(AppImageError::Verification(
            "independently rooted AppDirs are not represented by the same exact manifest"
                .to_owned(),
        ));
    }

    let appimagetool = read_regular_input(&request.appimagetool, MAX_TOOL_BYTES, Some(0o755))?;
    verify_identity(
        &appimagetool,
        contract.appimagetool.bytes,
        &contract.appimagetool.sha256,
        "appimagetool",
    )?;
    require_x86_64_elf(&appimagetool, "appimagetool")?;
    let runtime = read_regular_input(&request.type2_runtime, MAX_TOOL_BYTES, Some(0o755))?;
    verify_identity(
        &runtime,
        contract.type2_runtime.bytes,
        &contract.type2_runtime.sha256,
        "Type-2 runtime",
    )?;
    validate_type2_runtime(&runtime)?;
    let bubblewrap = read_regular_input(&request.bubblewrap, MAX_SYSTEM_TOOL_BYTES, Some(0o755))?;
    verify_sha256(
        &bubblewrap,
        &request.bubblewrap_sha256,
        "independently pinned bubblewrap",
    )?;
    require_x86_64_elf(&bubblewrap, "bubblewrap")?;
    let readelf = read_regular_input(&request.readelf, MAX_SYSTEM_TOOL_BYTES, Some(0o755))?;
    verify_sha256(
        &readelf,
        &request.readelf_sha256,
        "independently pinned readelf",
    )?;
    require_x86_64_elf(&readelf, "readelf")?;
    let oci_runtime = read_regular_input(&request.oci_runtime, MAX_SYSTEM_TOOL_BYTES, Some(0o755))?;
    verify_sha256(
        &oci_runtime,
        &request.oci_runtime_sha256,
        "independently pinned OCI runtime",
    )?;
    require_x86_64_elf(&oci_runtime, "OCI runtime")?;
    match (&request.sudo_program, &request.sudo_sha256) {
        (Some(program), Some(expected)) => {
            // A system sudo binary is normally setuid-root (04755). Its exact
            // bytes are independently pinned and its executable semantics are
            // exercised by every OCI command, so do not require a portable
            // numeric mode here.
            let sudo = read_regular_input(program, MAX_SYSTEM_TOOL_BYTES, None)?;
            verify_sha256(&sudo, expected, "independently pinned sudo")?;
            require_x86_64_elf(&sudo, "sudo")?;
        }
        (None, None) => {}
        _ => {
            return Err(AppImageError::Input(
                "sudo program and digest must both be supplied or both be absent".to_owned(),
            ));
        }
    }

    let work = PrivateWork::new(
        request
            .output
            .parent()
            .ok_or_else(|| AppImageError::Input("output has no parent".to_owned()))?,
    )?;
    let result = build_and_verify_in_work(request, &contract, &first_appdir, &runtime, &work.path);
    let verified = match result {
        Ok(verified) => verified,
        Err(error) => return Err(work.abort(error)),
    };
    let image_bytes = read_regular_input(&verified.primary_image, MAX_APPIMAGE_BYTES, Some(0o755))
        .map_err(|error| work.abort(error))?;
    let artifact_sha256 = hex_lower(&Sha256::digest(&image_bytes));
    if artifact_sha256 != verified.sha256 {
        return Err(work.abort(AppImageError::Verification(
            "primary AppImage changed after verification".to_owned(),
        )));
    }

    let manifest = AppImageManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_appimage".to_owned(),
        publication_scope: PUBLICATION_SCOPE.to_owned(),
        application_version: first_appdir.application_version.clone(),
        application_build: first_appdir.application_build.clone(),
        artifact: AppImageArtifact {
            path: contract.artifact_filename.clone(),
            sha256: artifact_sha256,
            bytes: u64::try_from(image_bytes.len()).map_err(|_| {
                work.abort(AppImageError::Transaction(
                    "AppImage length does not fit u64".to_owned(),
                ))
            })?,
            mode: "0755".to_owned(),
        },
        reproduction_sha256: verified.reproduction_sha256,
        appdir_manifest_sha256: request.appdir_manifest_sha256.clone(),
        reproduction_appdir_manifest_sha256: request.reproduction_appdir_manifest_sha256.clone(),
        source_date_epoch: first_appdir.source_date_epoch,
        appimagetool: contract.appimagetool.clone(),
        type2_runtime: contract.type2_runtime.clone(),
        bubblewrap_sha256: request.bubblewrap_sha256.clone(),
        readelf_sha256: request.readelf_sha256.clone(),
        compression: contract.compression.clone(),
        network_isolation: "bubblewrap_unshare_net_for_both_builds_extraction_and_host_launches_plus_oci_network_none_for_older_glibc_launch".to_owned(),
        process_containment:
            "bubblewrap_unshare_pid_die_with_parent_and_process_group_timeout_cleanup".to_owned(),
        twice_built_byte_identical: true,
        extracted_tree_verified: true,
        runtime_derivation:
            "exact_pinned_runtime_except_appimagetool_filled_16_byte_digest_md5_section".to_owned(),
        elf_audit: verified.elf_audit,
        launch_audits: verified.launch_audits,
        older_glibc_audit: verified.older_glibc_audit,
        release_status:
            "engineering_candidate_only_legal_branding_signing_matrix_and_release_gates_not_implied"
                .to_owned(),
    };
    let provenance = to_json_line(&manifest)
        .map_err(|error| work.abort(AppImageError::Transaction(error.to_string())))?;
    if provenance.len() > MAX_PROVENANCE_BYTES {
        return Err(work.abort(AppImageError::Transaction(
            "AppImage provenance exceeds its bound".to_owned(),
        )));
    }
    work.finish()?;

    let mut publisher = TreePublisher::new(&request.output)
        .map_err(|error| AppImageError::Transaction(error.to_string()))?;
    let publish = (|| -> Result<(), AppImageError> {
        publisher
            .write_file(&contract.artifact_filename, &image_bytes, 0o755)
            .map_err(|error| AppImageError::Transaction(error.to_string()))?;
        publisher
            .write_file(PROVENANCE_NAME, provenance.as_bytes(), 0o644)
            .map_err(|error| AppImageError::Transaction(error.to_string()))?;
        publisher
            .normalize_timestamps(first_appdir.source_date_epoch)
            .map_err(|error| AppImageError::Transaction(error.to_string()))?;
        Ok(())
    })();
    if let Err(error) = publish {
        return Err(cleanup_publisher(&mut publisher, error));
    }
    match publisher.commit() {
        Ok(()) => Ok(manifest),
        Err(ExtractionError::PostCommitDurability(message)) => {
            Err(AppImageError::PostCommitDurability(message))
        }
        Err(error) => Err(cleanup_publisher(
            &mut publisher,
            AppImageError::Publication(error.to_string()),
        )),
    }
}

struct VerifiedBuild {
    primary_image: PathBuf,
    sha256: String,
    reproduction_sha256: String,
    elf_audit: Vec<ElfAuditEntry>,
    launch_audits: Vec<LaunchAudit>,
    older_glibc_audit: OlderGlibcAudit,
}

fn build_and_verify_in_work(
    request: &AppImageRequest,
    contract: &AppImageContract,
    appdir: &AppDirManifest,
    runtime: &[u8],
    work: &Path,
) -> Result<VerifiedBuild, AppImageError> {
    let primary_image = work.join("primary.AppImage");
    let reproduction_image = work.join("reproduction.AppImage");
    run_appimagetool(
        request,
        contract,
        &request.appdir,
        &primary_image,
        appdir.source_date_epoch,
        work,
    )?;
    validate_appdir_generation(&request.appdir, &request.appdir_manifest_sha256)?;
    run_appimagetool(
        request,
        contract,
        &request.reproduction_appdir,
        &reproduction_image,
        appdir.source_date_epoch,
        work,
    )?;
    validate_appdir_generation(
        &request.reproduction_appdir,
        &request.reproduction_appdir_manifest_sha256,
    )?;
    compare_regular_files(&primary_image, &reproduction_image)?;
    let primary_bytes = read_regular_input(&primary_image, MAX_APPIMAGE_BYTES, Some(0o755))?;
    let reproduction_bytes =
        read_regular_input(&reproduction_image, MAX_APPIMAGE_BYTES, Some(0o755))?;
    let sha256 = hex_lower(&Sha256::digest(&primary_bytes));
    let reproduction_sha256 = hex_lower(&Sha256::digest(&reproduction_bytes));
    if sha256 != reproduction_sha256 {
        return Err(AppImageError::Verification(
            "twice-built AppImages have different SHA-256 digests".to_owned(),
        ));
    }
    validate_appimage_envelope(&primary_bytes, runtime, contract)?;

    let audit_root = work.join("extraction-audit");
    create_private_directory(&audit_root)?;
    extract_appimage(request, &primary_image, &audit_root, work)?;
    let extracted = audit_root.join("squashfs-root");
    let extracted_manifest =
        validate_extracted_appdir_generation(&extracted, &request.appdir_manifest_sha256)?;
    if &extracted_manifest != appdir {
        return Err(AppImageError::Verification(
            "extracted AppImage manifest differs from its input AppDir".to_owned(),
        ));
    }
    let elf_audit = audit_elfs(request, &extracted, &extracted_manifest)?;
    let mut launch_audits = Vec::with_capacity(request.launch_backends.len());
    for backend in &request.launch_backends {
        launch_audits.push(launch_appimage(request, &primary_image, *backend, work)?);
    }
    let older_glibc_audit =
        launch_in_older_glibc_baseline(request, contract, &primary_image, work)?;
    Ok(VerifiedBuild {
        primary_image,
        sha256,
        reproduction_sha256,
        elf_audit,
        launch_audits,
        older_glibc_audit,
    })
}

fn validate_request(request: &AppImageRequest) -> Result<(), AppImageError> {
    for (label, path) in [
        ("AppDir", &request.appdir),
        ("reproduction AppDir", &request.reproduction_appdir),
        ("appimagetool", &request.appimagetool),
        ("Type-2 runtime", &request.type2_runtime),
        ("bubblewrap", &request.bubblewrap),
        ("readelf", &request.readelf),
        ("OCI runtime", &request.oci_runtime),
        ("output", &request.output),
    ] {
        if !path.is_absolute() {
            return Err(AppImageError::Input(format!(
                "{label} path must be absolute"
            )));
        }
    }
    if let Some(sudo) = &request.sudo_program {
        if !sudo.is_absolute() {
            return Err(AppImageError::Input(
                "sudo path must be absolute".to_owned(),
            ));
        }
    }
    for (digest, label) in [
        (&request.appdir_manifest_sha256, "AppDir manifest"),
        (
            &request.reproduction_appdir_manifest_sha256,
            "reproduction AppDir manifest",
        ),
        (&request.bubblewrap_sha256, "bubblewrap"),
        (&request.readelf_sha256, "readelf"),
        (&request.oci_runtime_sha256, "OCI runtime"),
    ] {
        validate_request_digest(digest, label)?;
    }
    if let Some(digest) = &request.sudo_sha256 {
        validate_request_digest(digest, "sudo")?;
    }
    let Some(image_digest) = request.older_glibc_image_id.strip_prefix("sha256:") else {
        return Err(AppImageError::Input(
            "older-glibc image ID must begin with sha256:".to_owned(),
        ));
    };
    validate_request_digest(image_digest, "older-glibc image ID")?;
    if request.appdir == request.reproduction_appdir
        || request.appdir.starts_with(&request.reproduction_appdir)
        || request.reproduction_appdir.starts_with(&request.appdir)
    {
        return Err(AppImageError::Input(
            "reproducibility AppDirs must have independent roots".to_owned(),
        ));
    }
    for input in [
        &request.appdir,
        &request.reproduction_appdir,
        &request.appimagetool,
        &request.type2_runtime,
        &request.bubblewrap,
        &request.readelf,
        &request.oci_runtime,
    ] {
        if input.starts_with(&request.output) || request.output.starts_with(input) {
            return Err(AppImageError::Input(
                "AppImage output must not alias or contain an input".to_owned(),
            ));
        }
    }
    let backends: BTreeSet<_> = request.launch_backends.iter().copied().collect();
    if backends.len() != request.launch_backends.len()
        || !backends.contains(&LaunchBackend::Wayland)
        || !backends.contains(&LaunchBackend::X11)
    {
        return Err(AppImageError::Input(
            "pack-appimage requires one Wayland and one X11 genuine launch test".to_owned(),
        ));
    }
    Ok(())
}

fn run_appimagetool(
    request: &AppImageRequest,
    contract: &AppImageContract,
    appdir: &Path,
    destination: &Path,
    source_date_epoch: i64,
    work: &Path,
) -> Result<(), AppImageError> {
    let epoch = source_date_epoch.to_string();
    let arguments = sandbox_arguments(
        work,
        work,
        false,
        [
            request.appimagetool.as_os_str(),
            std::ffi::OsStr::new("--no-appstream"),
            std::ffi::OsStr::new("--runtime-file"),
            request.type2_runtime.as_os_str(),
            std::ffi::OsStr::new("--comp"),
            std::ffi::OsStr::new("zstd"),
            std::ffi::OsStr::new("--mksquashfs-opt"),
            std::ffi::OsStr::new("-processors"),
            std::ffi::OsStr::new("--mksquashfs-opt"),
            std::ffi::OsStr::new("1"),
            std::ffi::OsStr::new("--mksquashfs-opt"),
            std::ffi::OsStr::new("-no-xattrs"),
            appdir.as_os_str(),
            destination.as_os_str(),
        ],
    );
    let mut environment = deterministic_environment(work);
    environment.insert(OsString::from("ARCH"), OsString::from("x86_64"));
    environment.insert(OsString::from("SOURCE_DATE_EPOCH"), OsString::from(epoch));
    environment.insert(
        OsString::from("APPIMAGE_EXTRACT_AND_RUN"),
        OsString::from("1"),
    );
    let output = run_bounded(&ProcessSpec {
        program: request.bubblewrap.clone(),
        arguments,
        working_directory: work.to_owned(),
        environment,
        timeout: Duration::from_secs(30 * 60),
        maximum_output_bytes: 16 * 1024 * 1024,
    })?;
    if !output.status.success() {
        return Err(AppImageError::Process(format!(
            "appimagetool {} failed: {}{}",
            contract.appimagetool.release,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn extract_appimage(
    request: &AppImageRequest,
    image: &Path,
    audit_root: &Path,
    work: &Path,
) -> Result<(), AppImageError> {
    let arguments = sandbox_arguments(
        work,
        audit_root,
        false,
        [
            image.as_os_str(),
            std::ffi::OsStr::new("--appimage-extract"),
        ],
    );
    let output = run_bounded(&ProcessSpec {
        program: request.bubblewrap.clone(),
        arguments,
        working_directory: work.to_owned(),
        environment: deterministic_environment(work),
        timeout: Duration::from_secs(10 * 60),
        maximum_output_bytes: 16 * 1024 * 1024,
    })?;
    if !output.status.success() {
        return Err(AppImageError::Process(format!(
            "AppImage extraction failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn launch_appimage(
    request: &AppImageRequest,
    image: &Path,
    backend: LaunchBackend,
    work: &Path,
) -> Result<LaunchAudit, AppImageError> {
    let label = match backend {
        LaunchBackend::Wayland => "wayland",
        LaunchBackend::X11 => "x11",
    };
    let home = work.join(format!("launch-home-{label}"));
    create_private_directory(&home)?;
    let arguments = sandbox_arguments(
        work,
        work,
        backend == LaunchBackend::X11,
        [image.as_os_str()],
    );
    let mut environment = deterministic_environment(&home);
    environment.insert(
        OsString::from("APPIMAGE_EXTRACT_AND_RUN"),
        OsString::from("1"),
    );
    environment.insert(
        OsString::from("CODEX_LINUX_DISPLAY_BACKEND"),
        OsString::from(label),
    );
    environment.insert(
        OsString::from("CODEX_LINUX_DISABLE_UPDATES"),
        OsString::from("1"),
    );
    environment.insert(OsString::from("XDG_SESSION_TYPE"), OsString::from(label));
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XAUTHORITY",
        "XDG_CURRENT_DESKTOP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            environment.insert(OsString::from(name), value);
        }
    }
    match backend {
        LaunchBackend::Wayland
            if !environment.contains_key(std::ffi::OsStr::new("WAYLAND_DISPLAY"))
                || !environment.contains_key(std::ffi::OsStr::new("XDG_RUNTIME_DIR")) =>
        {
            return Err(AppImageError::Verification(
                "Wayland launch requested without WAYLAND_DISPLAY and XDG_RUNTIME_DIR".to_owned(),
            ));
        }
        LaunchBackend::X11 if !environment.contains_key(std::ffi::OsStr::new("DISPLAY")) => {
            return Err(AppImageError::Verification(
                "X11 launch requested without DISPLAY".to_owned(),
            ));
        }
        _ => {}
    }
    let outcome = run_bounded_observing_timeout(&ProcessSpec {
        program: request.bubblewrap.clone(),
        arguments,
        working_directory: work.to_owned(),
        environment,
        timeout: Duration::from_secs(20),
        maximum_output_bytes: 4 * 1024 * 1024,
    })?;
    let mut logs = outcome.output.stdout;
    logs.push(b'\n');
    logs.extend_from_slice(&outcome.output.stderr);
    let packaged_mode = contains_bytes(&logs, b"packaged=true");
    let app_server_handshake = contains_bytes(&logs, b"initialize_handshake_result")
        && contains_bytes(&logs, b"outcome=success");
    let window_ready = contains_bytes(&logs, b"window ready-to-show");
    if !packaged_mode
        || !app_server_handshake
        || !window_ready
        || (!outcome.timed_out && !outcome.output.status.success())
    {
        return Err(AppImageError::Verification(format!(
            "{label} AppImage launch did not reach all required runtime markers"
        )));
    }
    Ok(LaunchAudit {
        backend,
        timed_out_after_success: outcome.timed_out,
        packaged_mode,
        app_server_handshake,
        window_ready,
        log_sha256: hex_lower(&Sha256::digest(&logs)),
        log_bytes: u64::try_from(logs.len())
            .map_err(|_| AppImageError::Verification("launch log is too large".to_owned()))?,
    })
}

fn launch_in_older_glibc_baseline(
    request: &AppImageRequest,
    contract: &AppImageContract,
    image: &Path,
    work: &Path,
) -> Result<OlderGlibcAudit, AppImageError> {
    let baseline = &contract.older_glibc_baseline;
    let inspection = run_oci_successful(
        request,
        vec![
            OsString::from("image"),
            OsString::from("inspect"),
            OsString::from(concat!(
                "--format={{.Id}}|{{.Architecture}}|{{.Os}}|{{.Config.User}}|",
                "{{index .Config.Labels ",
                "\"io.github.bearhuddleston.codex-linux-packager.baseline\"}}|",
                "{{index .Config.Labels ",
                "\"io.github.bearhuddleston.codex-linux-packager.debian-snapshots\"}}|",
                "{{index .Config.Labels \"org.opencontainers.image.base.name\"}}"
            )),
            OsString::from(&request.older_glibc_image_id),
        ],
        work,
        Duration::from_secs(30),
        64 * 1024,
        "inspect older-glibc image",
    )?;
    let identity = single_ascii_line(&inspection.stdout, "older-glibc image identity")?;
    let expected_identity = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        request.older_glibc_image_id,
        baseline.architecture,
        baseline.operating_system,
        baseline.user,
        baseline.identity_label,
        baseline.debian_snapshots,
        baseline.base_image
    );
    if identity != expected_identity {
        return Err(AppImageError::Verification(format!(
            "older-glibc image identity {identity:?} differs from its exact contract"
        )));
    }

    let glibc = run_oci_container(
        request,
        &request.older_glibc_image_id,
        ["/usr/bin/getconf", "GNU_LIBC_VERSION"],
        work,
        64 * 1024,
    )?;
    let glibc_report = single_ascii_line(&glibc.stdout, "older-glibc version")?;
    let glibc_version = glibc_report
        .strip_prefix("glibc ")
        .ok_or_else(|| {
            AppImageError::Verification("older-glibc version has an unexpected format".to_owned())
        })?
        .to_owned();
    if glibc_version != baseline.glibc_version {
        return Err(AppImageError::Verification(format!(
            "older baseline has glibc {glibc_version:?}, not {:?}",
            baseline.glibc_version
        )));
    }

    let packages = run_oci_container(
        request,
        &request.older_glibc_image_id,
        [
            "/usr/bin/dpkg-query",
            "--show",
            "--showformat=${binary:Package}\\t${Version}\\n",
        ],
        work,
        4 * 1024 * 1024,
    )?;
    let (package_manifest_sha256, package_count) = canonical_package_manifest(&packages.stdout)?;
    if package_manifest_sha256 != baseline.package_manifest_sha256
        || package_count != baseline.package_count
    {
        return Err(AppImageError::Verification(
            "older-glibc installed package inventory differs from its exact contract".to_owned(),
        ));
    }

    let mount = safe_oci_mount_path(work)?;
    let image_name = image
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            AppImageError::Input("private AppImage path has no UTF-8 filename".to_owned())
        })?;
    let arguments = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--network=none"),
        OsString::from("--read-only"),
        OsString::from("--init"),
        OsString::from("--tmpfs=/tmp:rw,exec,nosuid,nodev,size=2147483648,mode=1777"),
        OsString::from("--pids-limit=512"),
        OsString::from("--cap-drop=ALL"),
        OsString::from("--security-opt=no-new-privileges"),
        OsString::from("--security-opt=seccomp=unconfined"),
        OsString::from("--security-opt=apparmor=unconfined"),
        OsString::from("--mount"),
        OsString::from(format!("type=bind,src={mount},dst=/artifact,readonly")),
        OsString::from("--env"),
        OsString::from("APPIMAGE_EXTRACT_AND_RUN=1"),
        OsString::from("--env"),
        OsString::from("CODEX_LINUX_DISPLAY_BACKEND=x11"),
        OsString::from("--env"),
        OsString::from("CODEX_LINUX_DISABLE_UPDATES=1"),
        OsString::from("--env"),
        OsString::from("HOME=/tmp/home"),
        OsString::from("--env"),
        OsString::from("XDG_CACHE_HOME=/tmp/home/.cache"),
        OsString::from("--env"),
        OsString::from("XDG_CONFIG_HOME=/tmp/home/.config"),
        OsString::from("--env"),
        OsString::from("XDG_DATA_HOME=/tmp/home/.local/share"),
        OsString::from("--env"),
        OsString::from("LANG=C.UTF-8"),
        OsString::from("--env"),
        OsString::from("LC_ALL=C.UTF-8"),
        OsString::from(&request.older_glibc_image_id),
        OsString::from("/usr/bin/timeout"),
        OsString::from("--signal=TERM"),
        OsString::from("--kill-after=2s"),
        OsString::from(format!("{}s", baseline.launch_timeout_seconds)),
        OsString::from("/usr/bin/xvfb-run"),
        OsString::from("--auto-servernum"),
        OsString::from("--server-args=-screen 0 1280x800x24"),
        OsString::from(format!("/artifact/{image_name}")),
    ];
    let outcome = run_oci(
        request,
        arguments,
        work,
        Duration::from_secs(35),
        4 * 1024 * 1024,
    )?;
    let mut logs = outcome.stdout;
    logs.push(b'\n');
    logs.extend_from_slice(&outcome.stderr);
    let packaged_mode = contains_bytes(&logs, b"packaged=true");
    let app_server_handshake = contains_bytes(&logs, b"initialize_handshake_result")
        && contains_bytes(&logs, b"outcome=success");
    let window_ready = contains_bytes(&logs, b"window ready-to-show");
    let timed_out_after_success = outcome.status.code() == Some(124);
    if !timed_out_after_success
        || !packaged_mode
        || !app_server_handshake
        || !window_ready
        || contains_bytes(&logs, b"No usable sandbox")
        || contains_bytes(&logs, b"FATAL:")
    {
        return Err(AppImageError::Verification(
            "older-glibc X11 AppImage launch did not reach every required sandboxed runtime marker"
                .to_owned(),
        ));
    }
    Ok(OlderGlibcAudit {
        image_id: request.older_glibc_image_id.clone(),
        oci_runtime_sha256: request.oci_runtime_sha256.clone(),
        sudo_sha256: request.sudo_sha256.clone(),
        glibc_version,
        package_manifest_sha256,
        package_count,
        timed_out_after_success,
        packaged_mode,
        app_server_handshake,
        window_ready,
        sandbox_policy: "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox_network_disabled_capabilities_dropped".to_owned(),
        log_sha256: hex_lower(&Sha256::digest(&logs)),
        log_bytes: u64::try_from(logs.len())
            .map_err(|_| AppImageError::Verification("baseline log is too large".to_owned()))?,
    })
}

fn run_oci_container<const N: usize>(
    request: &AppImageRequest,
    image: &str,
    command: [&str; N],
    work: &Path,
    maximum_output_bytes: usize,
) -> Result<crate::process::ProcessOutput, AppImageError> {
    let mut arguments = vec![
        OsString::from("run"),
        OsString::from("--rm"),
        OsString::from("--pull=never"),
        OsString::from("--network=none"),
        OsString::from("--read-only"),
        OsString::from("--cap-drop=ALL"),
        OsString::from("--security-opt=no-new-privileges"),
        OsString::from(image),
    ];
    arguments.extend(command.into_iter().map(OsString::from));
    run_oci_successful(
        request,
        arguments,
        work,
        Duration::from_secs(30),
        maximum_output_bytes,
        "inspect older-glibc container",
    )
}

fn canonical_package_manifest(bytes: &[u8]) -> Result<(String, u32), AppImageError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        AppImageError::Verification("older-glibc package inventory is not UTF-8".to_owned())
    })?;
    let mut records = BTreeSet::new();
    for line in text.lines() {
        let Some((package, version)) = line.split_once('\t') else {
            return Err(AppImageError::Verification(
                "older-glibc package inventory has an invalid record".to_owned(),
            ));
        };
        if package.is_empty()
            || version.is_empty()
            || !package.is_ascii()
            || !version.is_ascii()
            || !records.insert((package.to_owned(), version.to_owned()))
        {
            return Err(AppImageError::Verification(
                "older-glibc package inventory has an unsafe or duplicate record".to_owned(),
            ));
        }
    }
    let package_count = u32::try_from(records.len()).map_err(|_| {
        AppImageError::Verification("older-glibc package count does not fit u32".to_owned())
    })?;
    let mut canonical = Vec::new();
    for (package, version) in records {
        canonical.extend_from_slice(package.as_bytes());
        canonical.push(b'\t');
        canonical.extend_from_slice(version.as_bytes());
        canonical.push(b'\n');
    }
    Ok((hex_lower(&Sha256::digest(&canonical)), package_count))
}

fn single_ascii_line(bytes: &[u8], label: &str) -> Result<String, AppImageError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| AppImageError::Verification(format!("{label} is not UTF-8")))?
        .trim();
    if value.is_empty()
        || value.len() > 1024
        || !value.is_ascii()
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(AppImageError::Verification(format!(
            "{label} violates its single-line ASCII contract"
        )));
    }
    Ok(value.to_owned())
}

fn safe_oci_mount_path(path: &Path) -> Result<String, AppImageError> {
    let value = path
        .to_str()
        .ok_or_else(|| AppImageError::Input("OCI mount path is not UTF-8".to_owned()))?;
    if value.contains([',', ':', '\n', '\r', '\0']) {
        return Err(AppImageError::Input(
            "OCI mount path cannot be represented safely".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn run_oci_successful(
    request: &AppImageRequest,
    arguments: Vec<OsString>,
    work: &Path,
    timeout: Duration,
    maximum_output_bytes: usize,
    label: &str,
) -> Result<crate::process::ProcessOutput, AppImageError> {
    let output = run_oci(request, arguments, work, timeout, maximum_output_bytes)?;
    if !output.status.success() {
        return Err(AppImageError::Verification(format!(
            "{label} exited unsuccessfully"
        )));
    }
    Ok(output)
}

fn run_oci(
    request: &AppImageRequest,
    mut arguments: Vec<OsString>,
    work: &Path,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<crate::process::ProcessOutput, AppImageError> {
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
    run_bounded(&ProcessSpec {
        program,
        arguments,
        working_directory: work.to_owned(),
        environment: BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ]),
        timeout,
        maximum_output_bytes,
    })
    .map_err(AppImageError::from)
}

fn sandbox_arguments<'a>(
    work: &Path,
    working_directory: &Path,
    expose_x11: bool,
    command: impl IntoIterator<Item = &'a std::ffi::OsStr>,
) -> Vec<OsString> {
    let mut arguments = [
        "--unshare-net",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--bind",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(work.as_os_str().to_owned());
    arguments.push(work.as_os_str().to_owned());
    if expose_x11 && Path::new("/tmp/.X11-unix").is_dir() {
        arguments.extend(
            ["--ro-bind", "/tmp/.X11-unix", "/tmp/.X11-unix"]
                .into_iter()
                .map(OsString::from),
        );
    }
    arguments.push(OsString::from("--chdir"));
    arguments.push(working_directory.as_os_str().to_owned());
    arguments.push(OsString::from("--"));
    arguments.extend(command.into_iter().map(std::ffi::OsStr::to_owned));
    arguments
}

fn deterministic_environment(home: &Path) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([
        (OsString::from("HOME"), home.as_os_str().to_owned()),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (OsString::from("LC_ALL"), OsString::from("C.UTF-8")),
        (OsString::from("NO_COLOR"), OsString::from("1")),
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("TMPDIR"), OsString::from("/tmp")),
    ])
}

fn validate_appimage_envelope(
    image: &[u8],
    runtime: &[u8],
    contract: &AppImageContract,
) -> Result<(), AppImageError> {
    let offset = usize::try_from(contract.type2_runtime.digest_mutation_offset)
        .map_err(|_| AppImageError::Contract("runtime mutation offset is too large".to_owned()))?;
    let mutation_bytes = usize::try_from(contract.type2_runtime.digest_mutation_bytes)
        .map_err(|_| AppImageError::Contract("runtime mutation size is too large".to_owned()))?;
    let end = offset
        .checked_add(mutation_bytes)
        .ok_or_else(|| AppImageError::Contract("runtime mutation range overflowed".to_owned()))?;
    if runtime.len() != usize::try_from(contract.type2_runtime.bytes).unwrap_or(usize::MAX)
        || end > runtime.len()
        || image.len() <= runtime.len().saturating_add(96)
        || image.get(..4) != Some(b"\x7fELF")
        || image.get(8..12) != Some(b"AI\x02\0")
        || image.get(runtime.len()..runtime.len().saturating_add(4)) != Some(b"hsqs")
    {
        return Err(AppImageError::Verification(
            "artifact is not the exact expected Type-2 AppImage envelope".to_owned(),
        ));
    }
    if runtime[offset..end].iter().any(|byte| *byte != 0)
        || image[offset..end].iter().all(|byte| *byte == 0)
        || image[..offset] != runtime[..offset]
        || image[end..runtime.len()] != runtime[end..]
    {
        return Err(AppImageError::Verification(
            "final runtime differs outside the exact 16-byte digest section".to_owned(),
        ));
    }
    Ok(())
}

fn validate_type2_runtime(bytes: &[u8]) -> Result<(), AppImageError> {
    require_x86_64_elf(bytes, "Type-2 runtime")?;
    if bytes.get(8..12) != Some(b"AI\x02\0") {
        return Err(AppImageError::Input(
            "runtime lacks the Type-2 AppImage marker".to_owned(),
        ));
    }
    Ok(())
}

fn audit_elfs(
    request: &AppImageRequest,
    root: &Path,
    manifest: &AppDirManifest,
) -> Result<Vec<ElfAuditEntry>, AppImageError> {
    let mut audits = Vec::new();
    for entry in &manifest.entries {
        let path = root.join(&entry.path);
        let mut prefix = [0_u8; 4];
        let mut file = File::open(&path)
            .map_err(|error| AppImageError::Verification(format!("open ELF candidate: {error}")))?;
        let count = file
            .read(&mut prefix)
            .map_err(|error| AppImageError::Verification(format!("read ELF candidate: {error}")))?;
        if count != prefix.len() || prefix != *b"\x7fELF" {
            continue;
        }
        let output = run_bounded(&ProcessSpec {
            program: request.readelf.clone(),
            arguments: [
                "--wide",
                "--file-header",
                "--program-headers",
                "--dynamic",
                "--version-info",
            ]
            .into_iter()
            .map(OsString::from)
            .chain(std::iter::once(path.as_os_str().to_owned()))
            .collect(),
            working_directory: root.to_owned(),
            environment: BTreeMap::from([
                (OsString::from("LANG"), OsString::from("C")),
                (OsString::from("LC_ALL"), OsString::from("C")),
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            ]),
            timeout: Duration::from_secs(30),
            maximum_output_bytes: 2 * 1024 * 1024,
        })?;
        if !output.status.success() {
            return Err(AppImageError::Verification(format!(
                "readelf failed for {:?}",
                entry.path
            )));
        }
        audits.push(parse_readelf(entry, &output.stdout)?);
    }
    if audits.is_empty() {
        return Err(AppImageError::Verification(
            "extracted AppImage contains no audited ELF files".to_owned(),
        ));
    }
    audits.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(audits)
}

fn parse_readelf(
    entry: &crate::appdir::AppDirEntry,
    report: &[u8],
) -> Result<ElfAuditEntry, AppImageError> {
    let text = std::str::from_utf8(report)
        .map_err(|_| AppImageError::Verification("readelf output is not UTF-8".to_owned()))?;
    if !text.contains("Class:                             ELF64")
        || !text.contains("Data:                              2's complement, little endian")
        || !text.contains("Machine:                           Advanced Micro Devices X86-64")
    {
        return Err(AppImageError::Verification(format!(
            "{:?} is not ELF64 little-endian x86_64 according to readelf",
            entry.path
        )));
    }
    let mut interpreter = None;
    let mut needed = BTreeSet::new();
    let mut glibc = BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line.split("Requesting program interpreter: ").nth(1) {
            interpreter = Some(rest.trim_end_matches(']').trim().to_owned());
        }
        if let Some(rest) = line.split("Shared library: [").nth(1) {
            if let Some(value) = rest.split(']').next() {
                needed.insert(value.to_owned());
            }
        }
        for token in line.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
        }) {
            if let Some(version) = token.strip_prefix("GLIBC_") {
                if parse_glibc_version(version).is_some() {
                    glibc.insert(token.to_owned());
                }
            }
        }
    }
    let maximum_glibc = glibc
        .iter()
        .max_by_key(|value| {
            parse_glibc_version(value.trim_start_matches("GLIBC_")).unwrap_or((0, 0, 0))
        })
        .cloned();
    Ok(ElfAuditEntry {
        path: entry.path.clone(),
        sha256: entry.sha256.clone(),
        interpreter,
        needed: needed.into_iter().collect(),
        glibc_versions: glibc.into_iter().collect(),
        maximum_glibc,
        readelf_report_sha256: hex_lower(&Sha256::digest(report)),
    })
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

fn require_x86_64_elf(bytes: &[u8], label: &str) -> Result<(), AppImageError> {
    if bytes.len() < 64
        || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16::from_le_bytes([bytes[18], bytes[19]]) != 62
    {
        return Err(AppImageError::Input(format!(
            "{label} is not ELF64 little-endian x86_64"
        )));
    }
    Ok(())
}

fn compare_regular_files(left: &Path, right: &Path) -> Result<(), AppImageError> {
    let left_file = File::open(left)
        .map_err(|error| AppImageError::Verification(format!("open first AppImage: {error}")))?;
    let right_file = File::open(right).map_err(|error| {
        AppImageError::Verification(format!("open reproduction AppImage: {error}"))
    })?;
    let left_size = left_file
        .metadata()
        .map_err(|error| AppImageError::Verification(format!("inspect first AppImage: {error}")))?
        .len();
    let right_size = right_file
        .metadata()
        .map_err(|error| {
            AppImageError::Verification(format!("inspect reproduction AppImage: {error}"))
        })?
        .len();
    if left_size != right_size || left_size > MAX_APPIMAGE_BYTES {
        return Err(AppImageError::Verification(
            "twice-built AppImage lengths differ or exceed the bound".to_owned(),
        ));
    }
    let mut left = BufReader::new(left_file);
    let mut right = BufReader::new(right_file);
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_count = left.read(&mut left_buffer).map_err(|error| {
            AppImageError::Verification(format!("read first AppImage: {error}"))
        })?;
        let right_count = right.read(&mut right_buffer).map_err(|error| {
            AppImageError::Verification(format!("read reproduction AppImage: {error}"))
        })?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Err(AppImageError::Verification(
                "twice-built AppImages are not byte-identical".to_owned(),
            ));
        }
        if left_count == 0 {
            return Ok(());
        }
    }
}

fn read_regular_input(
    path: &Path,
    maximum: u64,
    expected_mode: Option<u32>,
) -> Result<Vec<u8>, AppImageError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| AppImageError::Input(format!("open {}: {error}", path.display())))?;
    let before = fstat(&descriptor)
        .map_err(|error| AppImageError::Input(format!("inspect {}: {error}", path.display())))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_size < 0
        || u64::try_from(before.st_size)
            .ok()
            .is_none_or(|size| size > maximum)
        || expected_mode.is_some_and(|mode| before.st_mode & 0o7777 != mode)
    {
        return Err(AppImageError::Input(format!(
            "{} has the wrong type, size, or mode",
            path.display()
        )));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| AppImageError::Input("file size does not fit u64".to_owned()))?;
    let capacity = usize::try_from(size)
        .map_err(|_| AppImageError::Input("file size does not fit usize".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(descriptor);
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| AppImageError::Input(format!("read {}: {error}", path.display())))?;
    if bytes.len() != capacity {
        return Err(AppImageError::Input(format!(
            "{} length changed while reading",
            path.display()
        )));
    }
    let after = fstat(&file)
        .map_err(|error| AppImageError::Input(format!("reinspect {}: {error}", path.display())))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(AppImageError::Input(format!(
            "{} identity changed while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn verify_identity(
    bytes: &[u8],
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<(), AppImageError> {
    if u64::try_from(bytes.len()).ok() != Some(expected_bytes) {
        return Err(AppImageError::Input(format!(
            "{label} length differs from its contract"
        )));
    }
    verify_sha256(bytes, expected_sha256, label)
}

fn verify_sha256(bytes: &[u8], expected: &str, label: &str) -> Result<(), AppImageError> {
    if hex_lower(&Sha256::digest(bytes)) != expected {
        return Err(AppImageError::Input(format!(
            "{label} does not match its pinned SHA-256"
        )));
    }
    Ok(())
}

fn validate_request_digest(value: &str, label: &str) -> Result<(), AppImageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppImageError::Input(format!(
            "{label} SHA-256 is not canonical lowercase hexadecimal"
        )));
    }
    Ok(())
}

struct PrivateWork {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PrivateWork {
    fn new(parent: &Path) -> Result<Self, AppImageError> {
        if !parent.is_absolute() {
            return Err(AppImageError::Input(
                "output parent must be absolute".to_owned(),
            ));
        }
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|error| AppImageError::Input(format!("inspect output parent: {error}")))?;
        if !metadata.file_type().is_dir() {
            return Err(AppImageError::Input(
                "output parent is not a real directory".to_owned(),
            ));
        }
        for _ in 0..16 {
            let mut random = [0_u8; 16];
            getrandom(&mut random, GetRandomFlags::empty())
                .map_err(|error| AppImageError::Transaction(format!("obtain entropy: {error}")))?;
            let path = parent.join(format!(
                ".codex-linux-packager-appimage-work-{}",
                hex_lower(&random)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| {
                            AppImageError::Transaction(format!(
                                "set private work permissions: {error}"
                            ))
                        })?;
                    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                        AppImageError::Transaction(format!("inspect private work: {error}"))
                    })?;
                    return Ok(Self {
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(AppImageError::Transaction(format!(
                        "create private AppImage work directory: {error}"
                    )));
                }
            }
        }
        Err(AppImageError::Transaction(
            "could not allocate private AppImage work directory".to_owned(),
        ))
    }

    fn finish(self) -> Result<(), AppImageError> {
        self.cleanup()
    }

    fn abort(&self, original: AppImageError) -> AppImageError {
        match self.cleanup() {
            Ok(()) => original,
            Err(cleanup) => AppImageError::Transaction(format!(
                "{original}; private AppImage cleanup was intentionally incomplete: {cleanup}"
            )),
        }
    }

    fn cleanup(&self) -> Result<(), AppImageError> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|error| {
            AppImageError::Transaction(format!("inspect private work before cleanup: {error}"))
        })?;
        if !metadata.file_type().is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| !name.starts_with(".codex-linux-packager-appimage-work-"))
        {
            return Err(AppImageError::Transaction(
                "refused to remove a substituted private work directory".to_owned(),
            ));
        }
        std::fs::remove_dir_all(&self.path).map_err(|error| {
            AppImageError::Transaction(format!("remove private AppImage work: {error}"))
        })
    }
}

fn create_private_directory(path: &Path) -> Result<(), AppImageError> {
    std::fs::create_dir(path).map_err(|error| {
        AppImageError::Transaction(format!("create private directory: {error}"))
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| AppImageError::Transaction(format!("set private directory mode: {error}")))
}

fn cleanup_publisher(publisher: &mut TreePublisher, original: AppImageError) -> AppImageError {
    match publisher.cleanup() {
        Ok(()) => original,
        Err(cleanup) => AppImageError::Transaction(format!(
            "{original}; private output cleanup was intentionally incomplete: {cleanup}"
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
