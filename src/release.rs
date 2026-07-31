//! Truthful release-readiness assessment for one exact artifact evidence set.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::appdir::AppDirManifest;
use crate::appimage::{AppImageManifest, LaunchBackend, appimage_contract};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::native::{NativeManifest, native_contract};
use crate::runtime::{RuntimeManifest, runtime_contract};
use crate::signature::PINNED_SPARKLE_PUBLIC_KEY_SHA256;
use crate::staging::{StageProvenance, validate_stage};
use crate::update::embedded_update_contract;

const PUBLICATION_SCOPE: &str = "bytes_at_durable_commit_boundary_under_documented_threat_model";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CARGO_LOCK_BYTES: u64 = 8 * 1024 * 1024;
const MAX_APPIMAGE_BYTES: u64 = 1024 * 1024 * 1024;
const RELEASE_STATUS: &str = "automatic_engineering_publication_permitted_not_stable_approval";

/// Whether one independently applicable release gate is presently cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    /// The supplied evidence proves this gate for the assessed digest set.
    Satisfied,
    /// The supplied evidence does not clear this gate.
    NotSatisfied,
}

/// One explicit release gate and its current disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGate {
    /// Stable machine-readable gate identifier.
    pub id: String,
    /// Current disposition.
    pub status: GateStatus,
    /// Whether failure to clear this gate forbids stable publication.
    pub blocking: bool,
    /// Exact evidence or absence statement.
    pub evidence: String,
    /// Action required before this gate can be cleared.
    pub required_action: String,
}

/// Exact local evidence inputs for one read-only release assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAssessmentRequest {
    /// Authenticated stage generation; its complete source archive is
    /// re-authenticated using the independently pinned production key.
    pub stage: PathBuf,
    /// Exact native-build manifest consumed by runtime assembly.
    pub native_manifest: PathBuf,
    /// Exact runtime manifest consumed by AppDir construction.
    pub runtime_manifest: PathBuf,
    /// Exact AppDir manifest consumed by AppImage construction.
    pub appdir_manifest: PathBuf,
    /// Exact final AppImage provenance.
    pub appimage_provenance: PathBuf,
    /// Exact final AppImage bytes.
    pub artifact: PathBuf,
    /// Exact Rust dependency lockfile for the assessed source candidate.
    pub cargo_lock: PathBuf,
}

/// Digest-bound scope of a release-readiness assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAssessmentScope {
    /// Exact authenticated stage provenance SHA-256.
    pub stage_provenance_sha256: String,
    /// Exact native manifest SHA-256.
    pub native_manifest_sha256: String,
    /// Exact runtime manifest SHA-256.
    pub runtime_manifest_sha256: String,
    /// Exact AppDir manifest SHA-256.
    pub appdir_manifest_sha256: String,
    /// Exact AppImage provenance SHA-256.
    pub appimage_provenance_sha256: String,
    /// Exact AppImage SHA-256.
    pub artifact_sha256: String,
    /// Exact AppImage bytes.
    pub artifact_bytes: u64,
    /// Exact Cargo.lock SHA-256.
    pub cargo_lock_sha256: String,
}

/// Deterministic automatic-engineering and stable-readiness report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseReadinessReport {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Truthful publication guarantee scope.
    pub publication_scope: String,
    /// Exact digest set to which this assessment applies.
    pub assessment_scope: ReleaseAssessmentScope,
    /// True after the implemented engineering pipeline evidence validates.
    pub engineering_candidate: bool,
    /// True when the implemented authentication, ABI, reproducibility, ELF,
    /// and launch gates permit publication on the automatic engineering
    /// channel. This is not stable-release approval.
    pub automatic_publication_permitted: bool,
    /// True only if every cataloged technical and operational gate is
    /// satisfied. Publisher legal decisions are outside this assessment.
    pub stable_publication_permitted: bool,
    /// Every gate in stable order, including both cleared and uncleared gates.
    pub gates: Vec<ReleaseGate>,
    /// Stable identifiers of all gates that still prevent stable publication.
    pub blocking_gate_ids: Vec<String>,
    /// Explicit public-release disposition.
    pub release_status: String,
}

/// Invalid or incomplete release-readiness evidence.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReleaseError {
    /// Request shape or path policy is invalid.
    #[error("invalid release assessment request: {0}")]
    Request(String),
    /// Evidence could not be read safely and completely.
    #[error("release evidence input failure: {0}")]
    Input(String),
    /// Evidence is internally inconsistent or violates its exact contract.
    #[error("invalid release evidence: {0}")]
    Evidence(String),
}

/// Returns every machine-assessed technical and operational gate in stable
/// order. Publisher legal decisions are deliberately outside this catalog.
#[must_use]
pub fn release_gate_catalog() -> Vec<ReleaseGate> {
    [
        (
            "authenticated_artifact_chain",
            "No exact manifest chain has been assessed.",
            "Assess an exact authenticated artifact and schema-1 manifest chain.",
        ),
        (
            "pinned_supply_chain_inputs",
            "No exact pinned-input manifest set has been assessed.",
            "Assess all digest-pinned runtime and packaging inputs.",
        ),
        (
            "twice_built_reproducibility",
            "No twice-built artifact evidence has been assessed.",
            "Build twice from independent roots with the second build offline and require byte equality.",
        ),
        (
            "native_electron_abi_round_trips",
            "No exact native manifest has been assessed.",
            "Run real SQLite and PTY round trips under the exact Electron runtime.",
        ),
        (
            "complete_final_elf_audit",
            "No complete extracted-artifact ELF audit has been assessed.",
            "Extract the final artifact and audit every ELF architecture, ABI, dependency, and glibc requirement.",
        ),
        (
            "host_wayland_x11_extract_and_run",
            "No genuine host launch evidence has been assessed.",
            "Launch the built AppImage through extract-and-run on Wayland and X11.",
        ),
        (
            "controlled_older_glibc_launch",
            "No controlled older-glibc launch evidence has been assessed.",
            "Launch the exact artifact in a digest-pinned older-glibc container or VM.",
        ),
        (
            "complete_notices_and_deterministic_sbom",
            "Complete payload notices and a deterministic SBOM are not present.",
            "Produce, review, and bind complete third-party notices and a deterministic SBOM to the artifacts.",
        ),
        (
            "signed_checksums_and_protected_keys",
            "No signed checksum set or protected signing-key evidence is present.",
            "Sign exact checksums using reviewed protected-key operations.",
        ),
        (
            "signed_attestation_exact_commit_and_artifacts",
            "No signed attestation binds an exact commit, tree, lockfile, inputs, and outputs.",
            "Create and verify a signed provenance attestation for the frozen release set.",
        ),
        (
            "protected_release_automation",
            "Protected branch, tag, environment, and release automation controls are not evidenced.",
            "Configure and independently review protected release automation.",
        ),
        (
            "kde_gnome_wayland_x11_fuse_matrix",
            "The complete KDE/GNOME, Wayland/X11, FUSE/extract-and-run, and sandbox matrix is not evidenced.",
            "Run the complete controlled desktop and AppImage execution matrix.",
        ),
        (
            "publication_rollback_and_recovery",
            "No publication rollback and recovery exercise is evidenced.",
            "Exercise and review rollback and recovery for the intended publication system.",
        ),
        (
            "frozen_independent_review",
            "No independent review is frozen to this exact commit, tree, and artifact digest set.",
            "Freeze one exact candidate and obtain independent review of those exact bytes.",
        ),
    ]
    .into_iter()
    .map(|(id, evidence, required_action)| ReleaseGate {
        id: id.to_owned(),
        status: GateStatus::NotSatisfied,
        blocking: true,
        evidence: evidence.to_owned(),
        required_action: required_action.to_owned(),
    })
    .collect()
}

/// Re-authenticates and validates one exact engineering evidence chain, then
/// emits all cataloged release blockers without making a legal determination.
pub fn assess_release_readiness(
    request: &ReleaseAssessmentRequest,
) -> Result<ReleaseReadinessReport, ReleaseError> {
    validate_request(request)?;

    let stage = validate_stage(&request.stage)
        .map_err(|error| ReleaseError::Evidence(format!("authenticate stage: {error}")))?;
    let stage_bytes = to_json_line(&stage.provenance)
        .map_err(|error| ReleaseError::Evidence(format!("encode stage provenance: {error}")))?;
    let stage_provenance_sha256 = sha256(stage_bytes.as_bytes());

    let (native, native_manifest_sha256) =
        read_canonical_json::<NativeManifest>(&request.native_manifest, "native manifest")?;
    let (runtime, runtime_manifest_sha256) =
        read_canonical_json::<RuntimeManifest>(&request.runtime_manifest, "runtime manifest")?;
    let (appdir, appdir_manifest_sha256) =
        read_canonical_json::<AppDirManifest>(&request.appdir_manifest, "AppDir manifest")?;
    let (provenance, appimage_provenance_sha256) = read_canonical_json::<AppImageManifest>(
        &request.appimage_provenance,
        "AppImage provenance",
    )?;
    let (artifact_sha256, artifact_bytes, artifact_mode) =
        digest_regular_file(&request.artifact, MAX_APPIMAGE_BYTES, "AppImage")?;
    let (cargo_lock, cargo_lock_sha256) =
        read_regular_file(&request.cargo_lock, MAX_CARGO_LOCK_BYTES, "Cargo.lock")?;

    validate_cargo_lock(&cargo_lock)?;
    validate_stage_provenance(&stage.provenance)?;
    validate_native_manifest(&native, &stage.provenance)?;
    validate_runtime_manifest(
        &runtime,
        &stage.provenance,
        &native,
        &native_manifest_sha256,
    )?;
    validate_appdir_manifest(&appdir, &runtime, &runtime_manifest_sha256)?;
    validate_appimage_provenance(
        &provenance,
        &appdir,
        &appdir_manifest_sha256,
        &artifact_sha256,
        artifact_bytes,
        artifact_mode,
        request.artifact.file_name().and_then(|name| name.to_str()),
    )?;

    let scope = ReleaseAssessmentScope {
        stage_provenance_sha256,
        native_manifest_sha256,
        runtime_manifest_sha256,
        appdir_manifest_sha256,
        appimage_provenance_sha256,
        artifact_sha256,
        artifact_bytes,
        cargo_lock_sha256,
    };
    let mut gates = release_gate_catalog();
    satisfy_gate(
        &mut gates,
        "authenticated_artifact_chain",
        format!(
            "The pinned Ed25519 trust root re-authenticated stage {} and the ASAR/archive identities reconcile through runtime {}.",
            scope.stage_provenance_sha256, scope.runtime_manifest_sha256
        ),
    )?;
    satisfy_gate(
        &mut gates,
        "pinned_supply_chain_inputs",
        format!(
            "Exact native, runtime, AppDir, AppImage provenance, and Cargo.lock digests validated: {}, {}, {}, {}, {}.",
            scope.native_manifest_sha256,
            scope.runtime_manifest_sha256,
            scope.appdir_manifest_sha256,
            scope.appimage_provenance_sha256,
            scope.cargo_lock_sha256
        ),
    )?;
    satisfy_gate(
        &mut gates,
        "twice_built_reproducibility",
        format!(
            "Independent-root offline builds are byte-identical at AppImage SHA-256 {}.",
            scope.artifact_sha256
        ),
    )?;
    satisfy_gate(
        &mut gates,
        "native_electron_abi_round_trips",
        format!(
            "Native manifest {} records successful real SQLite and PTY probes under Electron {} module ABI {}.",
            scope.native_manifest_sha256, native.runtime.electron, native.runtime.modules
        ),
    )?;
    satisfy_gate(
        &mut gates,
        "complete_final_elf_audit",
        format!(
            "AppImage provenance {} records {} extracted ELF audits; the greatest observed GLIBC requirement is {}.",
            scope.appimage_provenance_sha256,
            provenance.elf_audit.len(),
            maximum_glibc(&provenance).unwrap_or_else(|| "none".to_owned())
        ),
    )?;
    satisfy_gate(
        &mut gates,
        "host_wayland_x11_extract_and_run",
        "The exact AppImage reached packaged-mode, app-server handshake, and ready-to-show markers on host Wayland and X11 via extract-and-run.".to_owned(),
    )?;
    satisfy_gate(
        &mut gates,
        "controlled_older_glibc_launch",
        format!(
            "The exact AppImage reached all runtime markers as a non-root user in OCI image {} with glibc {} and network disabled.",
            provenance.older_glibc_audit.image_id, provenance.older_glibc_audit.glibc_version
        ),
    )?;

    let blocking_gate_ids = gates
        .iter()
        .filter(|gate| gate.blocking && gate.status == GateStatus::NotSatisfied)
        .map(|gate| gate.id.clone())
        .collect::<Vec<_>>();
    let stable_publication_permitted = blocking_gate_ids.is_empty();
    if stable_publication_permitted {
        return Err(ReleaseError::Evidence(
            "release catalog unexpectedly contains no independent blockers".to_owned(),
        ));
    }

    Ok(ReleaseReadinessReport {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "release_readiness_assessment".to_owned(),
        publication_scope: PUBLICATION_SCOPE.to_owned(),
        assessment_scope: scope,
        engineering_candidate: true,
        automatic_publication_permitted: true,
        stable_publication_permitted,
        gates,
        blocking_gate_ids,
        release_status: RELEASE_STATUS.to_owned(),
    })
}

fn validate_request(request: &ReleaseAssessmentRequest) -> Result<(), ReleaseError> {
    let paths = [
        ("stage", &request.stage),
        ("native manifest", &request.native_manifest),
        ("runtime manifest", &request.runtime_manifest),
        ("AppDir manifest", &request.appdir_manifest),
        ("AppImage provenance", &request.appimage_provenance),
        ("AppImage", &request.artifact),
        ("Cargo.lock", &request.cargo_lock),
    ];
    for (label, path) in paths {
        if !path.is_absolute() {
            return Err(ReleaseError::Request(format!(
                "{label} path must be absolute"
            )));
        }
    }
    let distinct = [
        &request.native_manifest,
        &request.runtime_manifest,
        &request.appdir_manifest,
        &request.appimage_provenance,
        &request.artifact,
        &request.cargo_lock,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if distinct.len() != 6 {
        return Err(ReleaseError::Request(
            "release evidence file paths must be distinct".to_owned(),
        ));
    }
    Ok(())
}

fn validate_stage_provenance(provenance: &StageProvenance) -> Result<(), ReleaseError> {
    if provenance.schema != SCHEMA_VERSION
        || provenance.producer != PRODUCER_IDENTIFIER
        || provenance.kind != "artifact_stage"
        || provenance.publication_scope != PUBLICATION_SCOPE
        || provenance.bundle.identifier != "com.openai.codex"
        || provenance.bundle.version != provenance.contract.version
        || provenance.bundle.build != provenance.contract.build
        || provenance.bundle.sparkle_public_key_sha256 != PINNED_SPARKLE_PUBLIC_KEY_SHA256
        || provenance.files.len() != 2
    {
        return Err(ReleaseError::Evidence(
            "authenticated stage identity or policy differs".to_owned(),
        ));
    }
    let app_asar = provenance
        .files
        .iter()
        .find(|file| file.path == "app.asar")
        .ok_or_else(|| ReleaseError::Evidence("stage lacks app.asar identity".to_owned()))?;
    let source = provenance
        .files
        .iter()
        .find(|file| file.path == "source.zip")
        .ok_or_else(|| ReleaseError::Evidence("stage lacks source archive identity".to_owned()))?;
    if app_asar.sha256 != provenance.asar.sha256
        || app_asar.bytes != provenance.asar.bytes
        || source.bytes != provenance.contract.expected_length
    {
        return Err(ReleaseError::Evidence(
            "stage file identities do not reconcile".to_owned(),
        ));
    }
    validate_digest(&app_asar.sha256, "stage ASAR")?;
    validate_digest(&source.sha256, "stage source archive")
}

fn validate_native_manifest(
    manifest: &NativeManifest,
    stage: &StageProvenance,
) -> Result<(), ReleaseError> {
    let contract = native_contract()
        .map_err(|error| ReleaseError::Evidence(format!("native contract: {error}")))?;
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "native_build"
        || manifest.application_version != stage.contract.version
        || manifest.application_build != stage.contract.build
        || manifest.source_asar_sha256 != stage.asar.sha256
        || manifest.runtime.electron != contract.electron.version
        || manifest.runtime.node != contract.electron.node_version
        || manifest.runtime.modules != contract.electron.module_abi
        || manifest.runtime.napi != contract.electron.napi
        || manifest.runtime.arch != "x64"
        || manifest.runtime.platform != "linux"
        || manifest.electron_zip_sha256 != contract.electron.linux_x64_zip_sha256
        || manifest.electron_headers_sha256 != contract.electron.headers_tar_sha256
        || manifest.source_patches != contract.source_patches
        || manifest.build_image != contract.build_image
        || manifest.build_node_version != contract.build_image.node_version
        || manifest.build_npm_version != contract.build_image.npm_version
        || manifest.build_glibc_version != contract.build_image.glibc_version
        || manifest.build_gcc_version != contract.build_image.gcc_version
        || manifest.network_allowed
        || !manifest.sqlite_probe_passed
        || !manifest.pty_probe_passed
        || manifest.outputs.len() != 2
    {
        return Err(ReleaseError::Evidence(
            "native manifest identity, toolchain, or real probes differ".to_owned(),
        ));
    }
    for (value, label) in [
        (&manifest.npm_lock_sha256, "native npm lock"),
        (&manifest.oci_runtime_sha256, "native OCI runtime"),
    ] {
        validate_digest(value, label)?;
    }
    if let Some(digest) = &manifest.sudo_sha256 {
        validate_digest(digest, "native sudo")?;
    }
    let expected_paths = [
        "app.asar.unpacked/node_modules/better-sqlite3/build/Release/better_sqlite3.node",
        "app.asar.unpacked/node_modules/node-pty/build/Release/pty.node",
    ];
    let observed_paths = manifest
        .outputs
        .iter()
        .map(|output| output.path.as_str())
        .collect::<Vec<_>>();
    if observed_paths != expected_paths {
        return Err(ReleaseError::Evidence(
            "native output inventory differs".to_owned(),
        ));
    }
    for output in &manifest.outputs {
        validate_digest(&output.sha256, "native output")?;
        if output.mode != "0644"
            || output.elf_machine != "x86_64"
            || output.bytes == 0
            || !strictly_sorted(&output.glibc_versions)
            || output
                .maximum_glibc
                .as_deref()
                .is_none_or(|version| !glibc_at_most(version, "GLIBC_2.36"))
        {
            return Err(ReleaseError::Evidence(
                "native output ELF or glibc policy differs".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_runtime_manifest(
    manifest: &RuntimeManifest,
    stage: &StageProvenance,
    native: &NativeManifest,
    native_manifest_sha256: &str,
) -> Result<(), ReleaseError> {
    let contract = runtime_contract()
        .map_err(|error| ReleaseError::Evidence(format!("runtime contract: {error}")))?;
    let source = stage
        .files
        .iter()
        .find(|file| file.path == "source.zip")
        .ok_or_else(|| ReleaseError::Evidence("stage lacks source archive".to_owned()))?;
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "linux_x86_64_runtime"
        || manifest.publication_scope != PUBLICATION_SCOPE
        || manifest.application_version != contract.application.version
        || manifest.application_build != contract.application.build
        || manifest.application_version != native.application_version
        || manifest.application_build != native.application_build
        || manifest.source_archive_sha256 != source.sha256
        || manifest.app_asar_sha256 != stage.asar.sha256
        || manifest.app_asar_sha256 != native.source_asar_sha256
        || manifest.native_manifest_sha256 != native_manifest_sha256
        || manifest.electron_zip_sha256 != contract.electron.linux_x64_zip_sha256
        || manifest.electron_zip_sha256 != native.electron_zip_sha256
        || manifest.codex_package_sha256 != contract.codex.package_archive_sha256
        || manifest.electron_version != contract.electron.version
        || manifest.codex_version != contract.codex.version
        || manifest.ripgrep_version
            != format!(
                "{} ({})",
                contract.ripgrep.version, contract.ripgrep.revision
            )
        || manifest.entries.is_empty()
        || manifest.entries.len() > 20_000
    {
        return Err(ReleaseError::Evidence(
            "runtime manifest identity or provenance chain differs".to_owned(),
        ));
    }
    for entry in &manifest.entries {
        validate_digest(&entry.sha256, "runtime inventory")?;
        if entry.bytes > 512 * 1024 * 1024 {
            return Err(ReleaseError::Evidence(
                "runtime inventory entry exceeds its bound".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_appdir_manifest(
    manifest: &AppDirManifest,
    runtime: &RuntimeManifest,
    runtime_manifest_sha256: &str,
) -> Result<(), ReleaseError> {
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "linux_x86_64_appdir"
        || manifest.publication_scope != PUBLICATION_SCOPE
        || manifest.runtime_manifest_sha256 != runtime_manifest_sha256
        || manifest.application_version != runtime.application_version
        || manifest.application_build != runtime.application_build
        || manifest.packaged_executable != "usr/lib/codex-desktop/codex-desktop"
        || manifest.display_backend_policy
            != "auto_default_explicit_wayland_or_x11_via_CODEX_LINUX_DISPLAY_BACKEND"
        || manifest.sandbox_policy
            != "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox"
        || manifest.identity_notice
            != "unofficial_and_unaffiliated_tooling_no_payload_redistribution_or_trademark_rights"
        || manifest.icon_license != "original_generic_non_branding_icon_MIT"
        || manifest.update_policy
            != "background_full_download_activate_for_next_launch_keep_versioned_rollback"
        || manifest.entries.is_empty()
        || manifest.entries.len() > 20_000
    {
        return Err(ReleaseError::Evidence(
            "AppDir manifest identity or policy differs".to_owned(),
        ));
    }
    let embedded_runtime = manifest
        .entries
        .iter()
        .find(|entry| entry.path == "usr/share/codex-linux-packager/runtime-manifest.json")
        .ok_or_else(|| {
            ReleaseError::Evidence("AppDir manifest lacks embedded runtime manifest".to_owned())
        })?;
    if embedded_runtime.sha256 != runtime_manifest_sha256 {
        return Err(ReleaseError::Evidence(
            "AppDir embedded runtime digest differs".to_owned(),
        ));
    }
    for digest in [
        &manifest.updater_sha256,
        &manifest.update_config_sha256,
        &manifest.update_public_key_sha256,
    ] {
        validate_digest(digest, "AppDir updater provenance")?;
    }
    let update_contract = embedded_update_contract()
        .map_err(|error| ReleaseError::Evidence(format!("update contract: {error}")))?;
    if manifest.update_manifest_url != update_contract.manifest_url
        || manifest.update_public_key_sha256 != update_contract.public_key_sha256
        || !manifest
            .entries
            .iter()
            .any(|entry| entry.path == "usr/libexec/codex-linux-packager/codex-linux-updater")
        || !manifest
            .entries
            .iter()
            .any(|entry| entry.path == "usr/share/codex-linux-packager/update-config.json")
    {
        return Err(ReleaseError::Evidence(
            "AppDir updater trust or inventory differs".to_owned(),
        ));
    }
    for entry in &manifest.entries {
        validate_digest(&entry.sha256, "AppDir inventory")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_appimage_provenance(
    manifest: &AppImageManifest,
    appdir: &AppDirManifest,
    appdir_manifest_sha256: &str,
    artifact_sha256: &str,
    artifact_bytes: u64,
    artifact_mode: u32,
    artifact_filename: Option<&str>,
) -> Result<(), ReleaseError> {
    let contract = appimage_contract()
        .map_err(|error| ReleaseError::Evidence(format!("AppImage contract: {error}")))?;
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != "linux_x86_64_appimage"
        || manifest.publication_scope != PUBLICATION_SCOPE
        || manifest.application_version != appdir.application_version
        || manifest.application_build != appdir.application_build
        || manifest.artifact.path != contract.artifact_filename
        || artifact_filename != Some(contract.artifact_filename.as_str())
        || manifest.artifact.sha256 != artifact_sha256
        || manifest.artifact.bytes != artifact_bytes
        || manifest.artifact.mode != "0755"
        || artifact_mode != 0o755
        || manifest.reproduction_sha256 != artifact_sha256
        || manifest.appdir_manifest_sha256 != appdir_manifest_sha256
        || manifest.reproduction_appdir_manifest_sha256 != appdir_manifest_sha256
        || manifest.source_date_epoch != appdir.source_date_epoch
        || manifest.appimagetool != contract.appimagetool
        || manifest.type2_runtime != contract.type2_runtime
        || manifest.compression != contract.compression
        || manifest.network_isolation
            != "bubblewrap_unshare_net_for_both_builds_extraction_and_host_launches_plus_oci_network_none_for_older_glibc_launch"
        || manifest.process_containment
            != "bubblewrap_unshare_pid_die_with_parent_and_process_group_timeout_cleanup"
        || !manifest.twice_built_byte_identical
        || !manifest.extracted_tree_verified
        || manifest.runtime_derivation
            != "exact_pinned_runtime_except_appimagetool_filled_16_byte_digest_md5_section"
        || manifest.release_status
            != "engineering_candidate_only_legal_branding_signing_matrix_and_release_gates_not_implied"
    {
        return Err(ReleaseError::Evidence(
            "AppImage provenance identity, derivation, or reproducibility differs".to_owned(),
        ));
    }
    validate_digest(&manifest.bubblewrap_sha256, "AppImage bubblewrap")?;
    validate_digest(&manifest.readelf_sha256, "AppImage readelf")?;
    validate_launch_audits(manifest)?;
    validate_older_glibc_audit(manifest, &contract.older_glibc_baseline)?;
    validate_elf_audits(manifest, appdir)
}

fn validate_launch_audits(manifest: &AppImageManifest) -> Result<(), ReleaseError> {
    let backends = manifest
        .launch_audits
        .iter()
        .map(|audit| audit.backend)
        .collect::<Vec<_>>();
    if backends != [LaunchBackend::Wayland, LaunchBackend::X11] {
        return Err(ReleaseError::Evidence(
            "host launch backend evidence differs".to_owned(),
        ));
    }
    for audit in &manifest.launch_audits {
        validate_digest(&audit.log_sha256, "host launch log")?;
        if !audit.timed_out_after_success
            || !audit.packaged_mode
            || !audit.app_server_handshake
            || !audit.window_ready
            || audit.log_bytes == 0
            || audit.log_bytes > 4 * 1024 * 1024
        {
            return Err(ReleaseError::Evidence(
                "host launch did not satisfy every required runtime marker".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_older_glibc_audit(
    manifest: &AppImageManifest,
    baseline: &crate::appimage::OlderGlibcBaselineContract,
) -> Result<(), ReleaseError> {
    let audit = &manifest.older_glibc_audit;
    let Some(image_digest) = audit.image_id.strip_prefix("sha256:") else {
        return Err(ReleaseError::Evidence(
            "older-glibc image ID is not digest-addressed".to_owned(),
        ));
    };
    validate_digest(image_digest, "older-glibc image ID")?;
    validate_digest(&audit.oci_runtime_sha256, "older-glibc OCI runtime")?;
    if let Some(digest) = &audit.sudo_sha256 {
        validate_digest(digest, "older-glibc sudo")?;
    }
    validate_digest(
        &audit.package_manifest_sha256,
        "older-glibc package manifest",
    )?;
    validate_digest(&audit.log_sha256, "older-glibc launch log")?;
    if audit.glibc_version != baseline.glibc_version
        || audit.package_manifest_sha256 != baseline.package_manifest_sha256
        || audit.package_count != baseline.package_count
        || !audit.timed_out_after_success
        || !audit.packaged_mode
        || !audit.app_server_handshake
        || !audit.window_ready
        || audit.sandbox_policy
            != "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox_network_disabled_capabilities_dropped"
        || audit.log_bytes == 0
        || audit.log_bytes > 4 * 1024 * 1024
    {
        return Err(ReleaseError::Evidence(
            "controlled older-glibc launch evidence differs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_elf_audits(
    manifest: &AppImageManifest,
    appdir: &AppDirManifest,
) -> Result<(), ReleaseError> {
    if manifest.elf_audit.is_empty() || manifest.elf_audit.len() > appdir.entries.len() {
        return Err(ReleaseError::Evidence(
            "final AppImage ELF audit is empty or oversized".to_owned(),
        ));
    }
    let appdir_entries = appdir
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry.sha256.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut previous = None;
    for audit in &manifest.elf_audit {
        if previous.is_some_and(|path: &str| path >= audit.path.as_str()) {
            return Err(ReleaseError::Evidence(
                "final AppImage ELF audit is not strictly sorted".to_owned(),
            ));
        }
        previous = Some(audit.path.as_str());
        validate_digest(&audit.sha256, "ELF")?;
        validate_digest(&audit.readelf_report_sha256, "readelf report")?;
        if appdir_entries.get(audit.path.as_str()) != Some(&audit.sha256.as_str())
            || !strictly_sorted(&audit.needed)
            || !strictly_sorted(&audit.glibc_versions)
            || audit
                .maximum_glibc
                .as_deref()
                .is_some_and(|version| !glibc_at_most(version, "GLIBC_2.36"))
        {
            return Err(ReleaseError::Evidence(
                "final AppImage ELF audit conflicts with AppDir or glibc policy".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_cargo_lock(bytes: &[u8]) -> Result<(), ReleaseError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ReleaseError::Evidence("Cargo.lock is not UTF-8".to_owned()))?;
    if !text.starts_with(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n",
    ) || !text.contains("name = \"codex-linux-packager\"")
    {
        return Err(ReleaseError::Evidence(
            "Cargo.lock is not the expected version-4 project lockfile".to_owned(),
        ));
    }
    Ok(())
}

fn read_canonical_json<T>(path: &Path, label: &'static str) -> Result<(T, String), ReleaseError>
where
    T: DeserializeOwned + Serialize,
{
    let (bytes, digest) = read_regular_file(path, MAX_MANIFEST_BYTES, label)?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| ReleaseError::Evidence(format!("parse {label}: {error}")))?;
    let canonical = to_json_line(&value)
        .map_err(|error| ReleaseError::Evidence(format!("encode {label}: {error}")))?;
    if canonical.as_bytes() != bytes {
        return Err(ReleaseError::Evidence(format!(
            "{label} is not canonical schema-1 JSON"
        )));
    }
    Ok((value, digest))
}

fn read_regular_file(
    path: &Path,
    maximum: u64,
    label: &'static str,
) -> Result<(Vec<u8>, String), ReleaseError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ReleaseError::Input(format!("open {label}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| ReleaseError::Input(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_size < 0 {
        return Err(ReleaseError::Input(format!(
            "{label} is not a bounded regular file"
        )));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| ReleaseError::Input(format!("{label} size does not fit u64")))?;
    if size > maximum {
        return Err(ReleaseError::Input(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(size)
        .map_err(|_| ReleaseError::Input(format!("{label} size does not fit usize")))?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReleaseError::Input(format!("read {label}: {error}")))?;
    if bytes.len() != capacity {
        return Err(ReleaseError::Input(format!(
            "{label} length changed while reading"
        )));
    }
    validate_unchanged_descriptor(&file, &before, label)?;
    let digest = sha256(&bytes);
    Ok((bytes, digest))
}

fn digest_regular_file(
    path: &Path,
    maximum: u64,
    label: &'static str,
) -> Result<(String, u64, u32), ReleaseError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ReleaseError::Input(format!("open {label}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| ReleaseError::Input(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_size < 0 {
        return Err(ReleaseError::Input(format!(
            "{label} is not a bounded regular file"
        )));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| ReleaseError::Input(format!("{label} size does not fit u64")))?;
    if size > maximum {
        return Err(ReleaseError::Input(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    let mut file = File::from(descriptor);
    let mut hasher = Sha256::new();
    let mut limited = file.by_ref().take(size.saturating_add(1));
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = limited
            .read(&mut buffer)
            .map_err(|error| ReleaseError::Input(format!("read {label}: {error}")))?;
        if count == 0 {
            break;
        }
        copied =
            copied
                .checked_add(u64::try_from(count).map_err(|_| {
                    ReleaseError::Input(format!("{label} read size does not fit u64"))
                })?)
                .ok_or_else(|| ReleaseError::Input(format!("{label} read length overflowed")))?;
        hasher.update(&buffer[..count]);
    }
    if copied != size {
        return Err(ReleaseError::Input(format!(
            "{label} length changed while hashing"
        )));
    }
    validate_unchanged_descriptor(&file, &before, label)?;
    Ok((
        hex_lower(&hasher.finalize()),
        size,
        std::fs::Permissions::from_mode(before.st_mode).mode() & 0o7777,
    ))
}

fn validate_unchanged_descriptor(
    file: &File,
    before: &rustix::fs::Stat,
    label: &'static str,
) -> Result<(), ReleaseError> {
    let after =
        fstat(file).map_err(|error| ReleaseError::Input(format!("reinspect {label}: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(ReleaseError::Input(format!(
            "{label} changed while being read"
        )));
    }
    Ok(())
}

fn satisfy_gate(gates: &mut [ReleaseGate], id: &str, evidence: String) -> Result<(), ReleaseError> {
    let gate = gates
        .iter_mut()
        .find(|gate| gate.id == id)
        .ok_or_else(|| ReleaseError::Evidence(format!("release gate {id:?} is missing")))?;
    gate.status = GateStatus::Satisfied;
    gate.evidence = evidence;
    gate.required_action = "No further engineering evidence is required for this exact digest set; later byte changes require reassessment.".to_owned();
    Ok(())
}

fn maximum_glibc(manifest: &AppImageManifest) -> Option<String> {
    manifest
        .elf_audit
        .iter()
        .filter_map(|audit| audit.maximum_glibc.as_deref())
        .max_by_key(|version| parse_glibc(version).unwrap_or_default())
        .map(str::to_owned)
}

fn glibc_at_most(observed: &str, maximum: &str) -> bool {
    parse_glibc(observed)
        .zip(parse_glibc(maximum))
        .is_some_and(|(observed, maximum)| observed <= maximum)
}

fn parse_glibc(value: &str) -> Option<Vec<u64>> {
    let version = value.strip_prefix("GLIBC_")?;
    let components = version
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    if !(2..=4).contains(&components.len()) {
        return None;
    }
    Some(components)
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), ReleaseError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseError::Evidence(format!(
            "{label} SHA-256 is not 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
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
    use super::glibc_at_most;

    #[test]
    fn glibc_symbol_versions_accept_historical_three_component_names() {
        assert!(glibc_at_most("GLIBC_2.2.5", "GLIBC_2.36"));
        assert!(glibc_at_most("GLIBC_2.36", "GLIBC_2.36"));
        assert!(!glibc_at_most("GLIBC_2.37", "GLIBC_2.36"));
        assert!(!glibc_at_most("GLIBC_PRIVATE", "GLIBC_2.36"));
    }
}
