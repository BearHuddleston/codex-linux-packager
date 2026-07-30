//! Deterministic release evidence for one exact Linux x86_64 AppImage.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::fs::{FileType, Mode, OFlags, RawDir, fstat, open, openat};
use serde::de::{DeserializeOwned, Error as _, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::appdir::AppDirManifest;
use crate::appimage::AppImageManifest;
use crate::extract::{ExtractionError, TreePublisher};
use crate::manifest::{
    PRODUCER_IDENTIFIER, SCHEMA_VERSION, is_canonical_utc_timestamp, to_json_line,
};
use crate::release::{GateStatus, ReleaseReadinessReport, release_gate_catalog};
use crate::signature::verify_ed25519_bytes;
use crate::update::{UpdateContract, embedded_update_contract, verify_signed_update_manifest};

const APPDIR_KIND: &str = "linux_x86_64_appdir";
const SPDX_VERSION: &str = "SPDX-2.3";
const SPDX_DATA_LICENSE: &str = "CC0-1.0";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const RELEASE_ATTESTATION_PAYLOAD_KIND: &str = "linux_x86_64_release_attestation_payload";
const SIGNED_RELEASE_ATTESTATION_KIND: &str = "linux_x86_64_signed_release_attestation";
const RELEASE_PREDICATE_TYPE: &str =
    "https://github.com/BearHuddleston/codex-linux-packager/attestation/v1";
const RELEASE_EVIDENCE_STATUS: &str =
    "release_evidence_prepared_operational_review_and_publication_not_implied";
const MAX_ATTESTATION_BYTES: usize = 1024 * 1024;
const MAX_SMALL_RELEASE_ASSET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_APPDIR_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PROVENANCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_READINESS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CARGO_LOCK_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CARGO_LICENSE_BYTES: u64 = 1024 * 1024;

/// Inputs for a deterministic file-complete SPDX document.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseSbomRequest<'a> {
    /// Canonical AppDir manifest whose entries must all appear in the SBOM.
    pub appdir: &'a AppDirManifest,
    /// SHA-256 of the canonical AppDir manifest.
    pub appdir_manifest_sha256: &'a str,
    /// Stable AppImage release asset name.
    pub artifact_name: &'a str,
    /// Complete AppImage SHA-256.
    pub artifact_sha256: &'a str,
    /// Exact 40-character source commit.
    pub source_commit: &'a str,
    /// Exact 40-character source tree.
    pub source_tree: &'a str,
    /// Explicit canonical UTC creation time.
    pub created_at: &'a str,
    /// JSON emitted by pinned `cargo deny list --format json --layout crate`.
    pub cargo_license_report: &'a [u8],
}

/// Inputs for the deterministic embedded-notice and Rust-license inventory.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseNoticeRequest<'a> {
    /// Canonical AppDir manifest whose notice-bearing files are inventoried.
    pub appdir: &'a AppDirManifest,
    /// SHA-256 of the canonical AppDir manifest.
    pub appdir_manifest_sha256: &'a str,
    /// SHA-256 of the matching deterministic SPDX document.
    pub sbom_sha256: &'a str,
    /// JSON emitted by pinned `cargo deny list --format json --layout crate`.
    pub cargo_license_report: &'a [u8],
}

/// Exact identities and inputs used to create one deterministic release
/// evidence set.
#[derive(Debug, Clone)]
pub struct ReleaseMaterialsRequest<'a> {
    /// Canonical AppDir manifest.
    pub appdir: &'a AppDirManifest,
    /// Exact AppDir manifest digest.
    pub appdir_manifest_sha256: &'a str,
    /// Complete AppImage identity.
    pub appimage: ReleaseSubject,
    /// Canonical AppImage provenance identity.
    pub provenance: ReleaseSubject,
    /// Signed update manifest identity.
    pub update_manifest: ReleaseSubject,
    /// Exact AppDir manifest bytes.
    pub appdir_manifest_bytes: u64,
    /// Exact release-readiness assessment digest.
    pub release_readiness_sha256: &'a str,
    /// Exact release-readiness assessment bytes.
    pub release_readiness_bytes: u64,
    /// Exact Cargo.lock digest.
    pub cargo_lock_sha256: String,
    /// Exact Cargo.lock bytes.
    pub cargo_lock_bytes: u64,
    /// Exact source commit.
    pub source_commit: String,
    /// Exact source tree.
    pub source_tree: String,
    /// Explicit canonical UTC creation time.
    pub created_at: &'a str,
    /// Pinned Cargo license report.
    pub cargo_license_report: &'a [u8],
    /// Release signing seed. Callers must independently reconcile its public
    /// half with the compiled release pin.
    pub signing_seed: &'a [u8; 32],
}

/// Complete file inputs for preparing a signed release-evidence generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvidencePreparationRequest {
    /// Exact verified Type-2 AppImage.
    pub appimage: PathBuf,
    /// Canonical AppImage provenance.
    pub provenance: PathBuf,
    /// Canonical signed update manifest.
    pub update_manifest: PathBuf,
    /// Canonical engineering release-readiness report.
    pub release_readiness: PathBuf,
    /// Canonical first AppDir manifest.
    pub appdir_manifest: PathBuf,
    /// Exact source Cargo.lock.
    pub cargo_lock: PathBuf,
    /// JSON from the pinned Cargo license-policy tool.
    pub cargo_license_report: PathBuf,
    /// Raw mode-0600 release-signing seed.
    pub private_key: PathBuf,
    /// Exact 40-character source commit.
    pub source_commit: String,
    /// Exact 40-character source tree.
    pub source_tree: String,
    /// Explicit canonical UTC creation time.
    pub created_at: String,
    /// New evidence generation published without replacement.
    pub output: PathBuf,
}

/// Exact files used for keyless pre-publication verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEvidenceVerificationRequest {
    /// Four-file release-evidence generation.
    pub evidence: PathBuf,
    /// Exact verified Type-2 AppImage.
    pub appimage: PathBuf,
    /// Canonical AppImage provenance.
    pub provenance: PathBuf,
    /// Canonical signed update manifest.
    pub update_manifest: PathBuf,
    /// Canonical engineering release-readiness report.
    pub release_readiness: PathBuf,
    /// Canonical first AppDir manifest.
    pub appdir_manifest: PathBuf,
    /// Exact source Cargo.lock.
    pub cargo_lock: PathBuf,
    /// Expected exact source commit.
    pub source_commit: String,
    /// Expected exact source tree.
    pub source_tree: String,
}

/// SPDX 2.3 JSON document with exact release and file identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxDocument {
    /// SPDX format version.
    pub spdx_version: String,
    /// SPDX document license.
    pub data_license: String,
    /// SPDX document identifier.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Deterministic document name.
    pub name: String,
    /// Digest-derived namespace.
    pub document_namespace: String,
    /// Deterministic creation identity.
    pub creation_info: SpdxCreationInfo,
    /// Elements described by the document.
    pub document_describes: Vec<String>,
    /// Release and Rust package inventory.
    pub packages: Vec<SpdxPackage>,
    /// Complete AppDir file inventory.
    pub files: Vec<SpdxFile>,
    /// Exact containment relationships.
    pub relationships: Vec<SpdxRelationship>,
}

/// SPDX document creation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxCreationInfo {
    /// Tool identity.
    pub creators: Vec<String>,
    /// Explicit canonical UTC timestamp.
    pub created: String,
    /// Exact source and manifest binding.
    pub comment: String,
}

/// One package represented in the SPDX document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxPackage {
    /// Package name.
    pub name: String,
    /// Stable document-local identifier.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Exact package version.
    pub version_info: String,
    /// Reproducible source locator or `NOASSERTION`.
    pub download_location: String,
    /// Whether package-level file analysis was performed.
    pub files_analyzed: bool,
    /// Exact package checksum when one complete artifact exists.
    pub checksums: Vec<SpdxChecksum>,
    /// License conclusion from the reviewed tool report.
    pub license_concluded: String,
    /// Declared license when independently available.
    pub license_declared: String,
    /// Truthful explanation of observed identifiers and withheld conclusions.
    pub license_comments: String,
    /// Copyright conclusion.
    pub copyright_text: String,
}

/// One complete AppDir file represented in SPDX.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxFile {
    /// AppDir-relative filename with SPDX's `./` prefix.
    pub file_name: String,
    /// Stable document-local identifier.
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    /// Exact file checksum.
    pub checksums: Vec<SpdxChecksum>,
    /// Truthful license conclusion.
    pub license_concluded: String,
    /// License identifiers found in the file.
    pub license_info_in_files: Vec<String>,
    /// Truthful copyright conclusion.
    pub copyright_text: String,
}

/// SPDX checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxChecksum {
    /// Hash algorithm.
    pub algorithm: String,
    /// Lowercase hexadecimal digest.
    pub checksum_value: String,
}

/// SPDX relationship between two document elements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpdxRelationship {
    /// Source element.
    pub spdx_element_id: String,
    /// SPDX relationship type.
    pub relationship_type: String,
    /// Related element.
    pub related_spdx_element: String,
}

/// Deterministic index of notices already embedded in the AppDir and Cargo
/// license identifiers observed by the pinned policy tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseNoticeInventory {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Codex application version.
    pub application_version: String,
    /// Codex application build.
    pub application_build: String,
    /// Exact AppDir manifest digest.
    pub appdir_manifest_sha256: String,
    /// Exact matching SPDX digest.
    pub sbom_sha256: String,
    /// Every notice-like file already included in the AppDir.
    pub embedded_notice_files: Vec<EmbeddedNoticeFile>,
    /// Every Rust package and sorted observed license-identifier set.
    pub rust_packages: Vec<NoticeRustPackage>,
    /// Exact inventory coverage counts.
    pub coverage: NoticeCoverage,
    /// Truthful review disposition.
    pub review_status: String,
    /// Project identity disclaimer.
    pub publisher_notice: String,
}

/// One notice-like file embedded in the AppImage source tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedNoticeFile {
    /// AppDir-relative path.
    pub path: String,
    /// Exact file SHA-256.
    pub sha256: String,
    /// Exact file bytes.
    pub bytes: u64,
}

/// One Cargo package and its deterministic observed license identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeRustPackage {
    /// Cargo package name.
    pub name: String,
    /// Exact Cargo package version.
    pub version: String,
    /// Normalized source identity.
    pub source: String,
    /// Sorted identifiers observed by the pinned Cargo license-policy tool.
    pub license_identifiers_observed: Vec<String>,
}

/// Counts proving the scope of the generated notice inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeCoverage {
    /// Complete AppDir entry count.
    pub appdir_entries: u64,
    /// Number of embedded notice-like files.
    pub embedded_notice_files: u64,
    /// Number of Cargo packages covered by the license report.
    pub rust_packages: u64,
}

/// One exact file subject covered by the signed release attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSubject {
    /// Stable release asset name.
    pub name: String,
    /// Complete byte length.
    pub bytes: u64,
    /// Complete SHA-256.
    pub sha256: String,
}

/// Exact non-subject evidence identities covered by the release attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAttestationEvidence {
    /// Canonical AppDir manifest SHA-256.
    pub appdir_manifest_sha256: String,
    /// Canonical AppImage provenance SHA-256.
    pub appimage_provenance_sha256: String,
    /// Signed update manifest SHA-256.
    pub update_manifest_sha256: String,
    /// Release-readiness assessment SHA-256.
    pub release_readiness_sha256: String,
    /// Exact Cargo.lock SHA-256.
    pub cargo_lock_sha256: String,
    /// SPDX document SHA-256.
    pub sbom_sha256: String,
    /// Notice inventory SHA-256.
    pub notice_inventory_sha256: String,
    /// Deterministic `SHA256SUMS` SHA-256.
    pub checksums_sha256: String,
}

/// Canonical predicate covered by the release Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAttestationPayload {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable payload kind.
    pub kind: String,
    /// Stable attestation predicate URI.
    pub predicate_type: String,
    /// Release channel.
    pub channel: String,
    /// Exact supported target.
    pub target: String,
    /// Exact GitHub release repository.
    pub release_repository: String,
    /// Immutable release tag.
    pub release_tag: String,
    /// Codex application version.
    pub application_version: String,
    /// Codex application build.
    pub application_build: String,
    /// Exact source commit.
    pub source_commit: String,
    /// Exact source tree.
    pub source_tree: String,
    /// Explicit canonical UTC signing time.
    pub created_at: String,
    /// Strictly sorted complete release subjects.
    pub subjects: Vec<ReleaseSubject>,
    /// Exact supporting evidence digests.
    pub evidence: ReleaseAttestationEvidence,
    /// Truthful non-publication disposition.
    pub publication_status: String,
}

/// Ed25519-signed release attestation bound to the independently pinned key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseAttestation {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable envelope kind.
    pub kind: String,
    /// SHA-256 of the signing public key.
    pub key_fingerprint_sha256: String,
    /// Canonical signed predicate.
    pub payload: ReleaseAttestationPayload,
    /// Canonical base64 Ed25519 signature over the payload JSON plus newline.
    pub signature_base64: String,
}

/// Proof that an attestation was canonical and verified against the pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedReleaseAttestation {
    /// Strictly verified signed attestation.
    pub attestation: SignedReleaseAttestation,
    /// SHA-256 of the exact signed canonical payload bytes.
    pub signed_payload_sha256: String,
}

/// Complete small release evidence materials. The AppImage, provenance, and
/// update manifest remain external subjects and are not copied into this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseMaterials {
    /// Deterministic SPDX 2.3 document.
    pub sbom: SpdxDocument,
    /// Deterministic embedded-notice and Cargo license inventory.
    pub notices: ReleaseNoticeInventory,
    /// Sorted standard SHA-256 checksum lines for release assets.
    pub sha256sums: String,
    /// Signed attestation covering every checksum and evidence digest.
    pub attestation: SignedReleaseAttestation,
}

/// Durable receipt for one no-replace release-evidence generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseEvidencePublication {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable receipt kind.
    pub kind: &'static str,
    /// New committed evidence generation.
    pub output: PathBuf,
    /// Immutable release tag covered by the attestation.
    pub release_tag: String,
    /// Complete sorted identity of every file in the generation.
    pub files: Vec<ReleaseSubject>,
}

/// Keyless verification receipt for one exact release evidence and asset set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseEvidenceVerification {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable receipt kind.
    pub kind: &'static str,
    /// Verified evidence generation.
    pub evidence: PathBuf,
    /// Immutable release tag.
    pub release_tag: String,
    /// Exact source commit.
    pub source_commit: String,
    /// Exact source tree.
    pub source_tree: String,
    /// Complete AppImage digest.
    pub artifact_sha256: String,
    /// Complete sorted evidence-file identities.
    pub files: Vec<ReleaseSubject>,
    /// Truthful non-publication disposition.
    pub verification_status: &'static str,
}

/// Invalid or ambiguous release-evidence input.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReleaseEvidenceError {
    /// Input shape or identity is invalid.
    #[error("invalid release evidence: {0}")]
    Invalid(String),
    /// A bounded regular-file input could not be read safely and completely.
    #[error("release evidence input failure: {0}")]
    Input(String),
    /// Cargo license report is malformed.
    #[error("invalid Cargo license report: {0}")]
    CargoLicenses(String),
    /// Signed release evidence is malformed or fails authentication.
    #[error("invalid signed release attestation: {0}")]
    Attestation(String),
    /// Private evidence construction or no-replace publication failed.
    #[error("release evidence publication failed before commit: {0}")]
    Publication(String),
    /// The generation name was committed but parent durability is uncertain.
    #[error("release evidence committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoDenyLicenseEntry {
    licenses: Vec<String>,
}

struct CargoDenyLicenseReport(BTreeMap<String, CargoDenyLicenseEntry>);

impl<'de> Deserialize<'de> for CargoDenyLicenseReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReportVisitor;

        impl<'de> Visitor<'de> for ReportVisitor {
            type Value = CargoDenyLicenseReport;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one Cargo license-report object with unique package keys")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut packages = BTreeMap::new();
                while let Some((identity, entry)) =
                    access.next_entry::<String, CargoDenyLicenseEntry>()?
                {
                    if packages.insert(identity.clone(), entry).is_some() {
                        return Err(M::Error::custom(format!(
                            "duplicate Cargo package identity {identity:?}"
                        )));
                    }
                }
                Ok(CargoDenyLicenseReport(packages))
            }
        }

        deserializer.deserialize_map(ReportVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CargoPackage {
    name: String,
    version: String,
    source: CargoSource,
    licenses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CargoSource {
    CratesIo,
    Local,
}

#[derive(Debug)]
struct BoundedInput {
    bytes: Vec<u8>,
    sha256: String,
    length: u64,
    mode: u32,
}

#[derive(Debug)]
struct DigestedInput {
    sha256: String,
    length: u64,
    mode: u32,
    prefix: [u8; 20],
}

/// Builds a deterministic SPDX 2.3 document covering every AppDir file and
/// every package in the supplied pinned Cargo license report.
pub fn build_release_sbom(
    request: &ReleaseSbomRequest<'_>,
) -> Result<SpdxDocument, ReleaseEvidenceError> {
    validate_request(request)?;
    let cargo_packages = parse_cargo_license_report(request.cargo_license_report)?;

    let mut packages = Vec::with_capacity(cargo_packages.len().saturating_add(1));
    packages.push(SpdxPackage {
        name: request.artifact_name.to_owned(),
        spdx_id: "SPDXRef-Package-AppImage".to_owned(),
        version_info: format!(
            "{}-{}",
            request.appdir.application_version, request.appdir.application_build
        ),
        download_location: "NOASSERTION".to_owned(),
        files_analyzed: false,
        checksums: vec![sha256_checksum(request.artifact_sha256)],
        license_concluded: "NOASSERTION".to_owned(),
        license_declared: "NOASSERTION".to_owned(),
        license_comments:
            "no_license_identifiers_or_expression_were_concluded_for_the_complete_appimage"
                .to_owned(),
        copyright_text: "NOASSERTION".to_owned(),
    });
    for (index, package) in cargo_packages.iter().enumerate() {
        let identifier = index
            .checked_add(1)
            .ok_or_else(|| ReleaseEvidenceError::Invalid("package index overflowed".to_owned()))?;
        packages.push(SpdxPackage {
            name: package.name.clone(),
            spdx_id: format!("SPDXRef-Package-Rust-{identifier:04}"),
            version_info: package.version.clone(),
            download_location: match package.source {
                CargoSource::CratesIo => {
                    format!(
                        "https://crates.io/crates/{}/{}",
                        package.name, package.version
                    )
                }
                CargoSource::Local => "NOASSERTION".to_owned(),
            },
            files_analyzed: false,
            checksums: Vec::new(),
            license_concluded: "NOASSERTION".to_owned(),
            license_declared: "NOASSERTION".to_owned(),
            license_comments: observed_license_comment(&package.licenses),
            copyright_text: "NOASSERTION".to_owned(),
        });
    }

    let mut files = Vec::with_capacity(request.appdir.entries.len());
    for (index, entry) in request.appdir.entries.iter().enumerate() {
        let identifier = index
            .checked_add(1)
            .ok_or_else(|| ReleaseEvidenceError::Invalid("file index overflowed".to_owned()))?;
        let file_id = format!("SPDXRef-File-{identifier:06}");
        files.push(SpdxFile {
            file_name: format!("./{}", entry.path),
            spdx_id: file_id.clone(),
            checksums: vec![sha256_checksum(&entry.sha256)],
            license_concluded: "NOASSERTION".to_owned(),
            license_info_in_files: vec!["NOASSERTION".to_owned()],
            copyright_text: "NOASSERTION".to_owned(),
        });
    }
    let document_describes = packages
        .iter()
        .map(|package| package.spdx_id.clone())
        .chain(files.iter().map(|file| file.spdx_id.clone()))
        .collect();

    Ok(SpdxDocument {
        spdx_version: SPDX_VERSION.to_owned(),
        data_license: SPDX_DATA_LICENSE.to_owned(),
        spdx_id: "SPDXRef-DOCUMENT".to_owned(),
        name: format!(
            "codex-desktop-unofficial-linux-x86_64-{}-{}",
            request.appdir.application_version, request.appdir.application_build
        ),
        document_namespace: format!(
            "https://github.com/BearHuddleston/codex-linux-packager/releases/spdx/{}/{}",
            request.source_commit, request.artifact_sha256
        ),
        creation_info: SpdxCreationInfo {
            creators: vec![format!("Tool: {PRODUCER_IDENTIFIER}")],
            created: request.created_at.to_owned(),
            comment: format!(
                "source_commit={} source_tree={} appdir_manifest_sha256={}",
                request.source_commit, request.source_tree, request.appdir_manifest_sha256
            ),
        },
        document_describes,
        packages,
        files,
        relationships: Vec::new(),
    })
}

/// Builds a deterministic inventory of embedded license/notice files and Rust
/// package license identifiers observed by the pinned policy tool. The output
/// deliberately requires independent review before it can clear the release
/// notice gate.
pub fn build_notice_inventory(
    request: &ReleaseNoticeRequest<'_>,
) -> Result<ReleaseNoticeInventory, ReleaseEvidenceError> {
    validate_appdir(request.appdir)?;
    validate_digest(request.appdir_manifest_sha256, "AppDir manifest")?;
    validate_digest(request.sbom_sha256, "SPDX document")?;
    let cargo_packages = parse_cargo_license_report(request.cargo_license_report)?;

    let embedded_notice_files = request
        .appdir
        .entries
        .iter()
        .filter(|entry| is_notice_path(&entry.path))
        .map(|entry| EmbeddedNoticeFile {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            bytes: entry.bytes,
        })
        .collect::<Vec<_>>();
    let rust_packages = cargo_packages
        .iter()
        .map(|package| NoticeRustPackage {
            name: package.name.clone(),
            version: package.version.clone(),
            source: match package.source {
                CargoSource::CratesIo => "crates.io".to_owned(),
                CargoSource::Local => "local_source_tree".to_owned(),
            },
            license_identifiers_observed: package.licenses.clone(),
        })
        .collect::<Vec<_>>();
    let appdir_entries = u64::try_from(request.appdir.entries.len())
        .map_err(|_| ReleaseEvidenceError::Invalid("AppDir entry count overflowed".to_owned()))?;
    let notice_count = u64::try_from(embedded_notice_files.len()).map_err(|_| {
        ReleaseEvidenceError::Invalid("embedded notice file count overflowed".to_owned())
    })?;
    let rust_package_count = u64::try_from(rust_packages.len()).map_err(|_| {
        ReleaseEvidenceError::Invalid("Rust package license count overflowed".to_owned())
    })?;

    Ok(ReleaseNoticeInventory {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_release_notice_inventory".to_owned(),
        application_version: request.appdir.application_version.clone(),
        application_build: request.appdir.application_build.clone(),
        appdir_manifest_sha256: request.appdir_manifest_sha256.to_owned(),
        sbom_sha256: request.sbom_sha256.to_owned(),
        embedded_notice_files,
        rust_packages,
        coverage: NoticeCoverage {
            appdir_entries,
            embedded_notice_files: notice_count,
            rust_packages: rust_package_count,
        },
        review_status: "generated_inventory_requires_independent_license_review".to_owned(),
        publisher_notice:
            "unofficial_and_unaffiliated_publisher_remains_responsible_for_redistribution_and_marks"
                .to_owned(),
    })
}

/// Signs one canonical release predicate with the release key.
pub fn create_signed_release_attestation(
    payload: &ReleaseAttestationPayload,
    signing_seed: &[u8; 32],
) -> Result<SignedReleaseAttestation, ReleaseEvidenceError> {
    validate_attestation_payload(payload, None)?;
    let signing_key = SigningKey::from_bytes(signing_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload_bytes = to_json_line(payload).map_err(|error| {
        ReleaseEvidenceError::Attestation(format!("encode signed payload: {error}"))
    })?;
    let signature = signing_key.sign(payload_bytes.as_bytes()).to_bytes();
    Ok(SignedReleaseAttestation {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: SIGNED_RELEASE_ATTESTATION_KIND.to_owned(),
        key_fingerprint_sha256: hex_lower(&Sha256::digest(public_key)),
        payload: payload.clone(),
        signature_base64: BASE64_STANDARD.encode(signature),
    })
}

/// Verifies canonical release evidence against the independently supplied
/// update-release key pin. The envelope cannot supply or rotate its own key.
pub fn verify_signed_release_attestation(
    bytes: &[u8],
    contract: &UpdateContract,
) -> Result<VerifiedReleaseAttestation, ReleaseEvidenceError> {
    if bytes.is_empty() || bytes.len() > MAX_ATTESTATION_BYTES {
        return Err(ReleaseEvidenceError::Attestation(
            "attestation size is outside its bound".to_owned(),
        ));
    }
    let public_key = validate_release_contract(contract)?;
    let attestation: SignedReleaseAttestation = serde_json::from_slice(bytes)
        .map_err(|error| ReleaseEvidenceError::Attestation(format!("parse JSON: {error}")))?;
    let canonical = to_json_line(&attestation).map_err(|error| {
        ReleaseEvidenceError::Attestation(format!("canonicalize JSON: {error}"))
    })?;
    if canonical.as_bytes() != bytes {
        return Err(ReleaseEvidenceError::Attestation(
            "attestation is not canonical schema-1 JSON".to_owned(),
        ));
    }
    if attestation.schema != SCHEMA_VERSION
        || attestation.producer != PRODUCER_IDENTIFIER
        || attestation.kind != SIGNED_RELEASE_ATTESTATION_KIND
        || attestation.key_fingerprint_sha256 != contract.public_key_sha256
    {
        return Err(ReleaseEvidenceError::Attestation(
            "signed envelope identity differs from the pinned contract".to_owned(),
        ));
    }
    validate_attestation_payload(&attestation.payload, Some(contract))?;
    let payload_bytes = to_json_line(&attestation.payload).map_err(|error| {
        ReleaseEvidenceError::Attestation(format!("encode signed payload: {error}"))
    })?;
    let signature = decode_canonical::<64>(&attestation.signature_base64, "signature")?;
    verify_ed25519_bytes(payload_bytes.as_bytes(), &signature, &public_key)
        .map_err(|error| ReleaseEvidenceError::Attestation(error.to_string()))?;
    Ok(VerifiedReleaseAttestation {
        attestation,
        signed_payload_sha256: hex_lower(&Sha256::digest(payload_bytes.as_bytes())),
    })
}

/// Builds deterministic SPDX, notice, checksum, and signed-attestation
/// materials for exact externally verified release subjects.
pub fn build_release_materials(
    request: &ReleaseMaterialsRequest<'_>,
) -> Result<ReleaseMaterials, ReleaseEvidenceError> {
    validate_material_subject(
        &request.appimage,
        "codex-desktop-unofficial-x86_64.AppImage",
        1024 * 1024 * 1024,
    )?;
    validate_material_subject(
        &request.provenance,
        "provenance.json",
        MAX_SMALL_RELEASE_ASSET_BYTES,
    )?;
    validate_material_subject(
        &request.update_manifest,
        "codex-linux-x86_64-update.json",
        MAX_SMALL_RELEASE_ASSET_BYTES,
    )?;
    if request.appdir_manifest_bytes == 0
        || request.appdir_manifest_bytes > MAX_APPDIR_MANIFEST_BYTES
        || request.release_readiness_bytes == 0
        || request.release_readiness_bytes > MAX_READINESS_BYTES
        || request.cargo_lock_bytes == 0
        || request.cargo_lock_bytes > MAX_CARGO_LOCK_BYTES
    {
        return Err(ReleaseEvidenceError::Invalid(
            "supporting release document length is outside its bound".to_owned(),
        ));
    }
    validate_digest(request.release_readiness_sha256, "release readiness")?;
    validate_digest(&request.cargo_lock_sha256, "Cargo.lock")?;

    let sbom = build_release_sbom(&ReleaseSbomRequest {
        appdir: request.appdir,
        appdir_manifest_sha256: request.appdir_manifest_sha256,
        artifact_name: &request.appimage.name,
        artifact_sha256: &request.appimage.sha256,
        source_commit: &request.source_commit,
        source_tree: &request.source_tree,
        created_at: request.created_at,
        cargo_license_report: request.cargo_license_report,
    })?;
    let sbom_bytes = to_json_line(&sbom)
        .map_err(|error| ReleaseEvidenceError::Invalid(format!("encode SPDX: {error}")))?;
    let sbom_sha256 = hex_lower(&Sha256::digest(sbom_bytes.as_bytes()));
    let notices = build_notice_inventory(&ReleaseNoticeRequest {
        appdir: request.appdir,
        appdir_manifest_sha256: request.appdir_manifest_sha256,
        sbom_sha256: &sbom_sha256,
        cargo_license_report: request.cargo_license_report,
    })?;
    let notice_bytes = to_json_line(&notices).map_err(|error| {
        ReleaseEvidenceError::Invalid(format!("encode notice inventory: {error}"))
    })?;
    let notice_sha256 = hex_lower(&Sha256::digest(notice_bytes.as_bytes()));

    let mut checksum_subjects = vec![
        request.appimage.clone(),
        request.provenance.clone(),
        request.update_manifest.clone(),
        ReleaseSubject {
            name: "appdir-manifest.json".to_owned(),
            bytes: request.appdir_manifest_bytes,
            sha256: request.appdir_manifest_sha256.to_owned(),
        },
        ReleaseSubject {
            name: "release-readiness.json".to_owned(),
            bytes: request.release_readiness_bytes,
            sha256: request.release_readiness_sha256.to_owned(),
        },
        ReleaseSubject {
            name: "Cargo.lock".to_owned(),
            bytes: request.cargo_lock_bytes,
            sha256: request.cargo_lock_sha256.clone(),
        },
        subject_from_bytes("codex-linux-x86_64.spdx.json", sbom_bytes.as_bytes())?,
        subject_from_bytes("third-party-notices.json", notice_bytes.as_bytes())?,
    ];
    checksum_subjects.sort_by(|left, right| left.name.cmp(&right.name));
    let mut sha256sums = String::new();
    for subject in &checksum_subjects {
        use std::fmt::Write as _;
        writeln!(&mut sha256sums, "{}  {}", subject.sha256, subject.name)
            .map_err(|error| ReleaseEvidenceError::Invalid(format!("encode checksums: {error}")))?;
    }
    let checksums_sha256 = hex_lower(&Sha256::digest(sha256sums.as_bytes()));
    let mut subjects = checksum_subjects;
    subjects.push(subject_from_bytes("SHA256SUMS", sha256sums.as_bytes())?);
    subjects.sort_by(|left, right| left.name.cmp(&right.name));

    let payload = ReleaseAttestationPayload {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: RELEASE_ATTESTATION_PAYLOAD_KIND.to_owned(),
        predicate_type: RELEASE_PREDICATE_TYPE.to_owned(),
        channel: "stable".to_owned(),
        target: "linux-x86_64".to_owned(),
        release_repository: "BearHuddleston/codex-linux-packager".to_owned(),
        release_tag: format!(
            "codex-app-{}-{}",
            request.appdir.application_version, request.appdir.application_build
        ),
        application_version: request.appdir.application_version.clone(),
        application_build: request.appdir.application_build.clone(),
        source_commit: request.source_commit.clone(),
        source_tree: request.source_tree.clone(),
        created_at: request.created_at.to_owned(),
        subjects,
        evidence: ReleaseAttestationEvidence {
            appdir_manifest_sha256: request.appdir_manifest_sha256.to_owned(),
            appimage_provenance_sha256: request.provenance.sha256.clone(),
            update_manifest_sha256: request.update_manifest.sha256.clone(),
            release_readiness_sha256: request.release_readiness_sha256.to_owned(),
            cargo_lock_sha256: request.cargo_lock_sha256.clone(),
            sbom_sha256,
            notice_inventory_sha256: notice_sha256,
            checksums_sha256,
        },
        publication_status: RELEASE_EVIDENCE_STATUS.to_owned(),
    };
    let attestation = create_signed_release_attestation(&payload, request.signing_seed)?;
    Ok(ReleaseMaterials {
        sbom,
        notices,
        sha256sums,
        attestation,
    })
}

/// Revalidates all generated materials against the independent key pin and
/// durably publishes exactly four small evidence files without replacement.
pub fn publish_release_materials(
    materials: &ReleaseMaterials,
    output: &Path,
    contract: &UpdateContract,
) -> Result<ReleaseEvidencePublication, ReleaseEvidenceError> {
    validate_absolute_output(output)?;
    let sbom_bytes = to_json_line(&materials.sbom)
        .map_err(|error| ReleaseEvidenceError::Publication(format!("encode SPDX: {error}")))?;
    let notice_bytes = to_json_line(&materials.notices).map_err(|error| {
        ReleaseEvidenceError::Publication(format!("encode notice inventory: {error}"))
    })?;
    let attestation_bytes = to_json_line(&materials.attestation).map_err(|error| {
        ReleaseEvidenceError::Publication(format!("encode signed attestation: {error}"))
    })?;
    let verified = verify_signed_release_attestation(attestation_bytes.as_bytes(), contract)?;
    if verified.attestation != materials.attestation {
        return Err(ReleaseEvidenceError::Attestation(
            "verified attestation differs from supplied materials".to_owned(),
        ));
    }
    let expected = [
        subject_from_bytes("SHA256SUMS", materials.sha256sums.as_bytes())?,
        subject_from_bytes("codex-linux-x86_64.spdx.json", sbom_bytes.as_bytes())?,
        subject_from_bytes("third-party-notices.json", notice_bytes.as_bytes())?,
    ];
    for expected_subject in expected {
        let attested = materials
            .attestation
            .payload
            .subjects
            .iter()
            .find(|subject| subject.name == expected_subject.name);
        if attested != Some(&expected_subject) {
            return Err(ReleaseEvidenceError::Attestation(format!(
                "{} differs from its signed identity",
                expected_subject.name
            )));
        }
    }
    if materials.notices.sbom_sha256 != materials.attestation.payload.evidence.sbom_sha256
        || materials.notices.appdir_manifest_sha256
            != materials
                .attestation
                .payload
                .evidence
                .appdir_manifest_sha256
    {
        return Err(ReleaseEvidenceError::Attestation(
            "notice inventory conflicts with signed SPDX/AppDir evidence".to_owned(),
        ));
    }

    let files_to_write = [
        ("SHA256SUMS", materials.sha256sums.as_bytes()),
        ("codex-linux-x86_64.spdx.json", sbom_bytes.as_bytes()),
        ("release-attestation.json", attestation_bytes.as_bytes()),
        ("third-party-notices.json", notice_bytes.as_bytes()),
    ];
    let mut publisher = TreePublisher::new(output).map_err(map_extraction_error)?;
    for (name, bytes) in files_to_write {
        if let Err(error) = publisher.write_file(name, bytes, 0o644) {
            return Err(cleanup_publication(
                &mut publisher,
                map_extraction_error(error),
            ));
        }
    }
    match publisher.commit() {
        Ok(()) => {}
        Err(ExtractionError::PostCommitDurability(message)) => {
            return Err(ReleaseEvidenceError::PostCommitDurability(message));
        }
        Err(error) => {
            let mapped = map_extraction_error(error);
            return Err(cleanup_publication(&mut publisher, mapped));
        }
    }

    let mut files = vec![
        subject_from_bytes("SHA256SUMS", materials.sha256sums.as_bytes())?,
        subject_from_bytes("codex-linux-x86_64.spdx.json", sbom_bytes.as_bytes())?,
        subject_from_bytes("release-attestation.json", attestation_bytes.as_bytes())?,
        subject_from_bytes("third-party-notices.json", notice_bytes.as_bytes())?,
    ];
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(ReleaseEvidencePublication {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_release_evidence_publication",
        output: output.to_owned(),
        release_tag: materials.attestation.payload.release_tag.clone(),
        files,
    })
}

/// Production preparation entry point using the independently compiled release
/// trust root.
pub fn prepare_release_evidence(
    request: &ReleaseEvidencePreparationRequest,
) -> Result<ReleaseEvidencePublication, ReleaseEvidenceError> {
    let contract = embedded_update_contract()
        .map_err(|error| ReleaseEvidenceError::Invalid(error.to_string()))?;
    prepare_release_evidence_with_contract(request, &contract)
}

/// Testable preparation entry point with an explicitly supplied independent
/// release trust root.
pub fn prepare_release_evidence_with_contract(
    request: &ReleaseEvidencePreparationRequest,
    contract: &UpdateContract,
) -> Result<ReleaseEvidencePublication, ReleaseEvidenceError> {
    validate_preparation_request(request)?;
    validate_release_contract(contract)?;

    let appimage = digest_regular_input(
        &request.appimage,
        contract.max_appimage_bytes,
        "release AppImage",
    )?;
    if appimage.mode != 0o755
        || appimage.prefix.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || appimage.prefix.get(8..12) != Some(b"AI\x02\0")
        || appimage.prefix.get(18..20) != Some(&62_u16.to_le_bytes())
    {
        return Err(ReleaseEvidenceError::Invalid(
            "release AppImage is not mode-0755 Linux x86_64 Type-2".to_owned(),
        ));
    }

    let appdir_input = read_bounded_input(
        &request.appdir_manifest,
        MAX_APPDIR_MANIFEST_BYTES,
        "AppDir manifest",
    )?;
    let appdir: AppDirManifest = parse_canonical_json(&appdir_input, "AppDir manifest")?;
    validate_appdir(&appdir)?;

    let provenance_input = read_bounded_input(
        &request.provenance,
        MAX_PROVENANCE_BYTES,
        "AppImage provenance",
    )?;
    let provenance: AppImageManifest =
        parse_canonical_json(&provenance_input, "AppImage provenance")?;
    validate_preparation_provenance(
        &provenance,
        &appdir,
        &appdir_input.sha256,
        &appimage,
        contract,
    )?;

    let readiness_input = read_bounded_input(
        &request.release_readiness,
        MAX_READINESS_BYTES,
        "release readiness",
    )?;
    let readiness: ReleaseReadinessReport =
        parse_canonical_json(&readiness_input, "release readiness")?;

    let cargo_lock = read_bounded_input(&request.cargo_lock, MAX_CARGO_LOCK_BYTES, "Cargo.lock")?;
    validate_cargo_lock(&cargo_lock.bytes)?;
    validate_preparation_readiness(
        &readiness,
        &appdir_input.sha256,
        &provenance_input.sha256,
        &appimage,
        &cargo_lock.sha256,
    )?;

    let license_report = read_bounded_input(
        &request.cargo_license_report,
        MAX_CARGO_LICENSE_BYTES,
        "Cargo license report",
    )?;
    parse_cargo_license_report(&license_report.bytes)?;

    let update_limit = contract
        .max_manifest_bytes
        .min(MAX_SMALL_RELEASE_ASSET_BYTES);
    let update_input = read_bounded_input(
        &request.update_manifest,
        update_limit,
        "signed update manifest",
    )?;
    let verified_update = verify_signed_update_manifest(&update_input.bytes, contract)
        .map_err(|error| ReleaseEvidenceError::Invalid(error.to_string()))?;
    let update_payload = &verified_update.manifest.payload;
    if update_payload.application_version != appdir.application_version
        || update_payload.application_build != appdir.application_build
        || update_payload.source_commit != request.source_commit
        || update_payload.published_at != request.created_at
        || update_payload.artifact.name != contract.artifact_name
        || update_payload.artifact.sha256 != appimage.sha256
        || update_payload.artifact.bytes != appimage.length
        || update_payload.artifact.provenance_sha256 != provenance_input.sha256
    {
        return Err(ReleaseEvidenceError::Invalid(
            "signed update manifest conflicts with exact release inputs".to_owned(),
        ));
    }

    let mut private_key =
        read_bounded_input(&request.private_key, 32, "private release-signing key")?;
    if private_key.length != 32 || private_key.mode != 0o600 {
        return Err(ReleaseEvidenceError::Input(
            "private release-signing key is not exactly 32 bytes at mode 0600".to_owned(),
        ));
    }
    let mut seed: [u8; 32] = private_key.bytes.as_slice().try_into().map_err(|_| {
        ReleaseEvidenceError::Input("private release-signing key length differs".to_owned())
    })?;
    private_key.bytes.fill(0);
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if BASE64_STANDARD.encode(public_key) != contract.public_key_base64
        || hex_lower(&Sha256::digest(public_key)) != contract.public_key_sha256
    {
        seed.fill(0);
        return Err(ReleaseEvidenceError::Invalid(
            "private release-signing key does not match the compiled pin".to_owned(),
        ));
    }

    let result = (|| {
        let materials = build_release_materials(&ReleaseMaterialsRequest {
            appdir: &appdir,
            appdir_manifest_sha256: &appdir_input.sha256,
            appimage: ReleaseSubject {
                name: contract.artifact_name.clone(),
                bytes: appimage.length,
                sha256: appimage.sha256.clone(),
            },
            provenance: ReleaseSubject {
                name: "provenance.json".to_owned(),
                bytes: provenance_input.length,
                sha256: provenance_input.sha256.clone(),
            },
            update_manifest: ReleaseSubject {
                name: "codex-linux-x86_64-update.json".to_owned(),
                bytes: update_input.length,
                sha256: update_input.sha256.clone(),
            },
            appdir_manifest_bytes: appdir_input.length,
            release_readiness_sha256: &readiness_input.sha256,
            release_readiness_bytes: readiness_input.length,
            cargo_lock_sha256: cargo_lock.sha256.clone(),
            cargo_lock_bytes: cargo_lock.length,
            source_commit: request.source_commit.clone(),
            source_tree: request.source_tree.clone(),
            created_at: &request.created_at,
            cargo_license_report: &license_report.bytes,
            signing_seed: &seed,
        })?;
        publish_release_materials(&materials, &request.output, contract)
    })();
    seed.fill(0);
    result
}

/// Keylessly verifies one complete release evidence generation against the
/// independent key pin and exact external assets.
pub fn verify_release_evidence(
    request: &ReleaseEvidenceVerificationRequest,
    contract: &UpdateContract,
) -> Result<ReleaseEvidenceVerification, ReleaseEvidenceError> {
    validate_verification_request(request)?;
    validate_release_contract(contract)?;
    let appimage = digest_regular_input(
        &request.appimage,
        contract.max_appimage_bytes,
        "release AppImage",
    )?;
    if appimage.mode != 0o755
        || appimage.prefix.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || appimage.prefix.get(8..12) != Some(b"AI\x02\0")
        || appimage.prefix.get(18..20) != Some(&62_u16.to_le_bytes())
    {
        return Err(ReleaseEvidenceError::Invalid(
            "release AppImage is not mode-0755 Linux x86_64 Type-2".to_owned(),
        ));
    }
    let appdir_input = read_bounded_input(
        &request.appdir_manifest,
        MAX_APPDIR_MANIFEST_BYTES,
        "AppDir manifest",
    )?;
    let appdir: AppDirManifest = parse_canonical_json(&appdir_input, "AppDir manifest")?;
    validate_appdir(&appdir)?;
    let provenance_input = read_bounded_input(
        &request.provenance,
        MAX_PROVENANCE_BYTES,
        "AppImage provenance",
    )?;
    let provenance: AppImageManifest =
        parse_canonical_json(&provenance_input, "AppImage provenance")?;
    validate_preparation_provenance(
        &provenance,
        &appdir,
        &appdir_input.sha256,
        &appimage,
        contract,
    )?;
    let readiness_input = read_bounded_input(
        &request.release_readiness,
        MAX_READINESS_BYTES,
        "release readiness",
    )?;
    let readiness: ReleaseReadinessReport =
        parse_canonical_json(&readiness_input, "release readiness")?;
    let cargo_lock = read_bounded_input(&request.cargo_lock, MAX_CARGO_LOCK_BYTES, "Cargo.lock")?;
    validate_cargo_lock(&cargo_lock.bytes)?;
    validate_preparation_readiness(
        &readiness,
        &appdir_input.sha256,
        &provenance_input.sha256,
        &appimage,
        &cargo_lock.sha256,
    )?;
    let update_limit = contract
        .max_manifest_bytes
        .min(MAX_SMALL_RELEASE_ASSET_BYTES);
    let update_input = read_bounded_input(
        &request.update_manifest,
        update_limit,
        "signed update manifest",
    )?;
    let update = verify_signed_update_manifest(&update_input.bytes, contract)
        .map_err(|error| ReleaseEvidenceError::Invalid(error.to_string()))?;

    let evidence_root = open_evidence_generation(&request.evidence)?;
    let checksums = read_bounded_input_at(&evidence_root, "SHA256SUMS", 1024 * 1024, "SHA256SUMS")?;
    let sbom_input = read_bounded_input_at(
        &evidence_root,
        "codex-linux-x86_64.spdx.json",
        MAX_SMALL_RELEASE_ASSET_BYTES,
        "SPDX document",
    )?;
    let attestation_input = read_bounded_input_at(
        &evidence_root,
        "release-attestation.json",
        u64::try_from(MAX_ATTESTATION_BYTES).map_err(|_| {
            ReleaseEvidenceError::Input("attestation bound does not fit u64".to_owned())
        })?,
        "release attestation",
    )?;
    let notices_input = read_bounded_input_at(
        &evidence_root,
        "third-party-notices.json",
        MAX_SMALL_RELEASE_ASSET_BYTES,
        "notice inventory",
    )?;
    for (input, label) in [
        (&checksums, "SHA256SUMS"),
        (&sbom_input, "SPDX document"),
        (&attestation_input, "release attestation"),
        (&notices_input, "notice inventory"),
    ] {
        if input.mode != 0o644 {
            return Err(ReleaseEvidenceError::Input(format!(
                "{label} mode is not exactly 0644"
            )));
        }
    }

    let sbom: SpdxDocument = parse_canonical_json(&sbom_input, "SPDX document")?;
    let notices: ReleaseNoticeInventory = parse_canonical_json(&notices_input, "notice inventory")?;
    let verified_attestation =
        verify_signed_release_attestation(&attestation_input.bytes, contract)?;
    let payload = &verified_attestation.attestation.payload;
    if payload.source_commit != request.source_commit
        || payload.source_tree != request.source_tree
        || payload.application_version != appdir.application_version
        || payload.application_build != appdir.application_build
        || payload.release_tag != update.manifest.payload.release_tag
        || payload.created_at != update.manifest.payload.published_at
        || update.manifest.payload.source_commit != request.source_commit
        || update.manifest.payload.artifact.sha256 != appimage.sha256
        || update.manifest.payload.artifact.bytes != appimage.length
        || update.manifest.payload.artifact.provenance_sha256 != provenance_input.sha256
    {
        return Err(ReleaseEvidenceError::Invalid(
            "signed attestation, update manifest, and exact release chain differ".to_owned(),
        ));
    }
    if payload.evidence.appdir_manifest_sha256 != appdir_input.sha256
        || payload.evidence.appimage_provenance_sha256 != provenance_input.sha256
        || payload.evidence.update_manifest_sha256 != update_input.sha256
        || payload.evidence.release_readiness_sha256 != readiness_input.sha256
        || payload.evidence.cargo_lock_sha256 != cargo_lock.sha256
        || payload.evidence.sbom_sha256 != sbom_input.sha256
        || payload.evidence.notice_inventory_sha256 != notices_input.sha256
        || payload.evidence.checksums_sha256 != checksums.sha256
    {
        return Err(ReleaseEvidenceError::Invalid(
            "signed supporting-evidence digest set differs".to_owned(),
        ));
    }
    validate_spdx_document(
        &sbom,
        &appdir,
        &appdir_input.sha256,
        &appimage.sha256,
        payload,
    )?;
    validate_notice_inventory(
        &notices,
        &sbom,
        &appdir,
        &appdir_input.sha256,
        &sbom_input.sha256,
    )?;

    let mut checksum_subjects = vec![
        ReleaseSubject {
            name: "Cargo.lock".to_owned(),
            bytes: cargo_lock.length,
            sha256: cargo_lock.sha256.clone(),
        },
        ReleaseSubject {
            name: "appdir-manifest.json".to_owned(),
            bytes: appdir_input.length,
            sha256: appdir_input.sha256.clone(),
        },
        ReleaseSubject {
            name: contract.artifact_name.clone(),
            bytes: appimage.length,
            sha256: appimage.sha256.clone(),
        },
        ReleaseSubject {
            name: "provenance.json".to_owned(),
            bytes: provenance_input.length,
            sha256: provenance_input.sha256.clone(),
        },
        ReleaseSubject {
            name: "release-readiness.json".to_owned(),
            bytes: readiness_input.length,
            sha256: readiness_input.sha256.clone(),
        },
        ReleaseSubject {
            name: "codex-linux-x86_64-update.json".to_owned(),
            bytes: update_input.length,
            sha256: update_input.sha256.clone(),
        },
        ReleaseSubject {
            name: "codex-linux-x86_64.spdx.json".to_owned(),
            bytes: sbom_input.length,
            sha256: sbom_input.sha256.clone(),
        },
        ReleaseSubject {
            name: "third-party-notices.json".to_owned(),
            bytes: notices_input.length,
            sha256: notices_input.sha256.clone(),
        },
    ];
    checksum_subjects.sort_by(|left, right| left.name.cmp(&right.name));
    let mut expected_checksums = String::new();
    for subject in &checksum_subjects {
        use std::fmt::Write as _;
        writeln!(
            &mut expected_checksums,
            "{}  {}",
            subject.sha256, subject.name
        )
        .map_err(|error| ReleaseEvidenceError::Invalid(format!("encode checksums: {error}")))?;
    }
    if checksums.bytes != expected_checksums.as_bytes() {
        return Err(ReleaseEvidenceError::Invalid(
            "SHA256SUMS differs from exact release assets".to_owned(),
        ));
    }
    checksum_subjects.push(ReleaseSubject {
        name: "SHA256SUMS".to_owned(),
        bytes: checksums.length,
        sha256: checksums.sha256.clone(),
    });
    checksum_subjects.sort_by(|left, right| left.name.cmp(&right.name));
    if payload.subjects != checksum_subjects {
        return Err(ReleaseEvidenceError::Invalid(
            "signed release subject set differs from exact assets".to_owned(),
        ));
    }

    let mut files = vec![
        ReleaseSubject {
            name: "SHA256SUMS".to_owned(),
            bytes: checksums.length,
            sha256: checksums.sha256,
        },
        ReleaseSubject {
            name: "codex-linux-x86_64.spdx.json".to_owned(),
            bytes: sbom_input.length,
            sha256: sbom_input.sha256,
        },
        ReleaseSubject {
            name: "release-attestation.json".to_owned(),
            bytes: attestation_input.length,
            sha256: attestation_input.sha256,
        },
        ReleaseSubject {
            name: "third-party-notices.json".to_owned(),
            bytes: notices_input.length,
            sha256: notices_input.sha256,
        },
    ];
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(ReleaseEvidenceVerification {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_release_evidence_verification",
        evidence: request.evidence.clone(),
        release_tag: payload.release_tag.clone(),
        source_commit: payload.source_commit.clone(),
        source_tree: payload.source_tree.clone(),
        artifact_sha256: appimage.sha256,
        files,
        verification_status: "signed_release_evidence_verified_operational_gates_and_publication_not_implied",
    })
}

fn validate_verification_request(
    request: &ReleaseEvidenceVerificationRequest,
) -> Result<(), ReleaseEvidenceError> {
    let paths = [
        (&request.evidence, "release evidence generation"),
        (&request.appimage, "AppImage"),
        (&request.provenance, "AppImage provenance"),
        (&request.update_manifest, "signed update manifest"),
        (&request.release_readiness, "release readiness"),
        (&request.appdir_manifest, "AppDir manifest"),
        (&request.cargo_lock, "Cargo.lock"),
    ];
    let mut seen = BTreeSet::new();
    for (path, label) in paths {
        validate_absolute_path(path, label)?;
        if !seen.insert(path.clone()) {
            return Err(ReleaseEvidenceError::Invalid(format!(
                "{label} aliases another verification input"
            )));
        }
    }
    validate_git_identity(&request.source_commit, "source commit")?;
    validate_git_identity(&request.source_tree, "source tree")
}

fn open_evidence_generation(path: &Path) -> Result<OwnedFd, ReleaseEvidenceError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| ReleaseEvidenceError::Input(format!("open evidence generation: {error}")))?;
    let metadata = fstat(&descriptor).map_err(|error| {
        ReleaseEvidenceError::Input(format!("inspect evidence generation: {error}"))
    })?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_mode & 0o7777 != 0o755
    {
        return Err(ReleaseEvidenceError::Input(
            "evidence generation is not a mode-0755 directory".to_owned(),
        ));
    }
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut directory = RawDir::new(&descriptor, &mut buffer);
    let mut names = Vec::new();
    while let Some(entry) = directory.next() {
        let entry = entry.map_err(|error| {
            ReleaseEvidenceError::Input(format!("enumerate evidence generation: {error}"))
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    names.sort();
    let expected = [
        b"SHA256SUMS".to_vec(),
        b"codex-linux-x86_64.spdx.json".to_vec(),
        b"release-attestation.json".to_vec(),
        b"third-party-notices.json".to_vec(),
    ];
    if names != expected {
        return Err(ReleaseEvidenceError::Input(
            "evidence generation does not contain exactly the four required files".to_owned(),
        ));
    }
    Ok(descriptor)
}

fn read_bounded_input_at(
    parent: &OwnedFd,
    name: &str,
    maximum: u64,
    label: &str,
) -> Result<BoundedInput, ReleaseEvidenceError> {
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ReleaseEvidenceError::Input(format!("open {label}: {error}")))?;
    read_bounded_descriptor(descriptor, maximum, label)
}

fn validate_spdx_document(
    document: &SpdxDocument,
    appdir: &AppDirManifest,
    appdir_sha256: &str,
    artifact_sha256: &str,
    payload: &ReleaseAttestationPayload,
) -> Result<(), ReleaseEvidenceError> {
    let expected_name = format!(
        "codex-desktop-unofficial-linux-x86_64-{}-{}",
        appdir.application_version, appdir.application_build
    );
    let expected_namespace = format!(
        "https://github.com/BearHuddleston/codex-linux-packager/releases/spdx/{}/{}",
        payload.source_commit, artifact_sha256
    );
    let expected_comment = format!(
        "source_commit={} source_tree={} appdir_manifest_sha256={}",
        payload.source_commit, payload.source_tree, appdir_sha256
    );
    let mut expected_describes =
        Vec::with_capacity(document.packages.len().saturating_add(appdir.entries.len()));
    expected_describes.push("SPDXRef-Package-AppImage".to_owned());
    for index in 0..document.packages.len().saturating_sub(1) {
        let identifier = index.checked_add(1).ok_or_else(|| {
            ReleaseEvidenceError::Invalid("SPDX package index overflowed".to_owned())
        })?;
        expected_describes.push(format!("SPDXRef-Package-Rust-{identifier:04}"));
    }
    for index in 0..appdir.entries.len() {
        let identifier = index.checked_add(1).ok_or_else(|| {
            ReleaseEvidenceError::Invalid("SPDX file index overflowed".to_owned())
        })?;
        expected_describes.push(format!("SPDXRef-File-{identifier:06}"));
    }
    if document.spdx_version != SPDX_VERSION
        || document.data_license != SPDX_DATA_LICENSE
        || document.spdx_id != "SPDXRef-DOCUMENT"
        || document.name != expected_name
        || document.document_namespace != expected_namespace
        || document.creation_info.creators != [format!("Tool: {PRODUCER_IDENTIFIER}")]
        || document.creation_info.created != payload.created_at
        || document.creation_info.comment != expected_comment
        || document.document_describes != expected_describes
        || document.files.len() != appdir.entries.len()
        || !document.relationships.is_empty()
        || document.packages.is_empty()
    {
        return Err(ReleaseEvidenceError::Invalid(
            "SPDX document identity or coverage differs".to_owned(),
        ));
    }
    let appimage_package = &document.packages[0];
    if appimage_package.name != "codex-desktop-unofficial-x86_64.AppImage"
        || appimage_package.spdx_id != "SPDXRef-Package-AppImage"
        || appimage_package.version_info
            != format!(
                "{}-{}",
                appdir.application_version, appdir.application_build
            )
        || appimage_package.download_location != "NOASSERTION"
        || appimage_package.files_analyzed
        || appimage_package.checksums != [sha256_checksum(artifact_sha256)]
        || appimage_package.license_concluded != "NOASSERTION"
        || appimage_package.license_declared != "NOASSERTION"
        || appimage_package.license_comments
            != "no_license_identifiers_or_expression_were_concluded_for_the_complete_appimage"
        || appimage_package.copyright_text != "NOASSERTION"
    {
        return Err(ReleaseEvidenceError::Invalid(
            "SPDX AppImage package identity differs".to_owned(),
        ));
    }
    let mut previous_package = None;
    for (index, package) in document.packages.iter().skip(1).enumerate() {
        let identifier = index.checked_add(1).ok_or_else(|| {
            ReleaseEvidenceError::Invalid("SPDX package index overflowed".to_owned())
        })?;
        let key = (
            package.name.as_str(),
            package.version_info.as_str(),
            package.download_location.as_str(),
        );
        if package.spdx_id != format!("SPDXRef-Package-Rust-{identifier:04}")
            || package.name.is_empty()
            || package.version_info.is_empty()
            || package.files_analyzed
            || !package.checksums.is_empty()
            || package.license_concluded != "NOASSERTION"
            || package.license_declared != "NOASSERTION"
            || !package
                .license_comments
                .starts_with("cargo_deny_observed_license_identifiers=[")
            || !package
                .license_comments
                .ends_with("]; no_license_expression_or_conclusion_is_asserted")
            || package.copyright_text != "NOASSERTION"
            || previous_package.is_some_and(|previous| previous >= key)
        {
            return Err(ReleaseEvidenceError::Invalid(
                "SPDX Rust package inventory differs or is unsorted".to_owned(),
            ));
        }
        previous_package = Some(key);
    }
    for (index, (file, entry)) in document.files.iter().zip(&appdir.entries).enumerate() {
        let identifier = index.checked_add(1).ok_or_else(|| {
            ReleaseEvidenceError::Invalid("SPDX file index overflowed".to_owned())
        })?;
        let file_id = format!("SPDXRef-File-{identifier:06}");
        if file.file_name != format!("./{}", entry.path)
            || file.spdx_id != file_id
            || file.checksums != [sha256_checksum(&entry.sha256)]
            || file.license_concluded != "NOASSERTION"
            || file.license_info_in_files != ["NOASSERTION"]
            || file.copyright_text != "NOASSERTION"
        {
            return Err(ReleaseEvidenceError::Invalid(
                "SPDX file inventory differs from the AppDir manifest".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_notice_inventory(
    notices: &ReleaseNoticeInventory,
    sbom: &SpdxDocument,
    appdir: &AppDirManifest,
    appdir_sha256: &str,
    sbom_sha256: &str,
) -> Result<(), ReleaseEvidenceError> {
    let expected_notices = appdir
        .entries
        .iter()
        .filter(|entry| is_notice_path(&entry.path))
        .map(|entry| EmbeddedNoticeFile {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            bytes: entry.bytes,
        })
        .collect::<Vec<_>>();
    if notices.schema != SCHEMA_VERSION
        || notices.producer != PRODUCER_IDENTIFIER
        || notices.kind != "linux_x86_64_release_notice_inventory"
        || notices.application_version != appdir.application_version
        || notices.application_build != appdir.application_build
        || notices.appdir_manifest_sha256 != appdir_sha256
        || notices.sbom_sha256 != sbom_sha256
        || notices.embedded_notice_files != expected_notices
        || notices.rust_packages.len() != sbom.packages.len().saturating_sub(1)
        || notices.coverage.appdir_entries
            != u64::try_from(appdir.entries.len()).unwrap_or(u64::MAX)
        || notices.coverage.embedded_notice_files
            != u64::try_from(expected_notices.len()).unwrap_or(u64::MAX)
        || notices.coverage.rust_packages
            != u64::try_from(notices.rust_packages.len()).unwrap_or(u64::MAX)
        || notices.review_status != "generated_inventory_requires_independent_license_review"
        || notices.publisher_notice
            != "unofficial_and_unaffiliated_publisher_remains_responsible_for_redistribution_and_marks"
    {
        return Err(ReleaseEvidenceError::Invalid(
            "notice inventory identity or coverage differs".to_owned(),
        ));
    }
    for (notice, package) in notices
        .rust_packages
        .iter()
        .zip(sbom.packages.iter().skip(1))
    {
        if notice.name != package.name
            || notice.version != package.version_info
            || notice.source
                != if package.download_location == "NOASSERTION" {
                    "local_source_tree"
                } else {
                    "crates.io"
                }
            || notice.license_identifiers_observed.is_empty()
            || notice.license_identifiers_observed.len() > 16
            || notice
                .license_identifiers_observed
                .iter()
                .any(|license| !valid_license(license))
            || !notice
                .license_identifiers_observed
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || package.license_comments
                != observed_license_comment(&notice.license_identifiers_observed)
        {
            return Err(ReleaseEvidenceError::Invalid(
                "notice and SPDX Rust license observations differ".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_preparation_request(
    request: &ReleaseEvidencePreparationRequest,
) -> Result<(), ReleaseEvidenceError> {
    let paths = [
        (&request.appimage, "AppImage"),
        (&request.provenance, "AppImage provenance"),
        (&request.update_manifest, "signed update manifest"),
        (&request.release_readiness, "release readiness"),
        (&request.appdir_manifest, "AppDir manifest"),
        (&request.cargo_lock, "Cargo.lock"),
        (&request.cargo_license_report, "Cargo license report"),
        (&request.private_key, "private release-signing key"),
        (&request.output, "release evidence output"),
    ];
    let mut seen = BTreeSet::new();
    for (path, label) in paths {
        validate_absolute_path(path, label)?;
        if !seen.insert(path.clone()) {
            return Err(ReleaseEvidenceError::Invalid(format!(
                "{label} aliases another input or output"
            )));
        }
    }
    validate_git_identity(&request.source_commit, "source commit")?;
    validate_git_identity(&request.source_tree, "source tree")?;
    validate_timestamp(&request.created_at)
}

fn validate_preparation_provenance(
    provenance: &AppImageManifest,
    appdir: &AppDirManifest,
    appdir_sha256: &str,
    appimage: &DigestedInput,
    contract: &UpdateContract,
) -> Result<(), ReleaseEvidenceError> {
    if provenance.schema != SCHEMA_VERSION
        || provenance.producer != PRODUCER_IDENTIFIER
        || provenance.kind != "linux_x86_64_appimage"
        || provenance.application_version != appdir.application_version
        || provenance.application_build != appdir.application_build
        || provenance.artifact.path != contract.artifact_name
        || provenance.artifact.sha256 != appimage.sha256
        || provenance.artifact.bytes != appimage.length
        || provenance.artifact.mode != "0755"
        || provenance.reproduction_sha256 != appimage.sha256
        || provenance.appdir_manifest_sha256 != appdir_sha256
        || provenance.reproduction_appdir_manifest_sha256 != appdir_sha256
        || !provenance.twice_built_byte_identical
        || !provenance.extracted_tree_verified
        || provenance.release_status
            != "engineering_candidate_only_legal_branding_signing_matrix_and_release_gates_not_implied"
    {
        return Err(ReleaseEvidenceError::Invalid(
            "AppImage provenance conflicts with the exact release chain".to_owned(),
        ));
    }
    Ok(())
}

fn validate_preparation_readiness(
    report: &ReleaseReadinessReport,
    appdir_sha256: &str,
    provenance_sha256: &str,
    appimage: &DigestedInput,
    cargo_lock_sha256: &str,
) -> Result<(), ReleaseEvidenceError> {
    if report.schema != SCHEMA_VERSION
        || report.producer != PRODUCER_IDENTIFIER
        || report.kind != "release_readiness_assessment"
        || report.publication_scope
            != "bytes_at_durable_commit_boundary_under_documented_threat_model"
        || !report.engineering_candidate
        || report.stable_publication_permitted
        || report.release_status != "not_release_approved_do_not_publish"
        || report.assessment_scope.appdir_manifest_sha256 != appdir_sha256
        || report.assessment_scope.appimage_provenance_sha256 != provenance_sha256
        || report.assessment_scope.artifact_sha256 != appimage.sha256
        || report.assessment_scope.artifact_bytes != appimage.length
        || report.assessment_scope.cargo_lock_sha256 != cargo_lock_sha256
    {
        return Err(ReleaseEvidenceError::Invalid(
            "release-readiness identity or digest scope differs".to_owned(),
        ));
    }
    let catalog = release_gate_catalog();
    if report.gates.len() != catalog.len() {
        return Err(ReleaseEvidenceError::Invalid(
            "release-readiness gate catalog length differs".to_owned(),
        ));
    }
    for (index, (actual, expected)) in report.gates.iter().zip(&catalog).enumerate() {
        let expected_status = if index < 7 {
            GateStatus::Satisfied
        } else {
            GateStatus::NotSatisfied
        };
        if actual.id != expected.id
            || !actual.blocking
            || actual.status != expected_status
            || (index < 7
                && (actual.evidence.is_empty()
                    || actual.required_action
                        != "No further engineering evidence is required for this exact digest set; later byte changes require reassessment."))
            || (index >= 7
                && (actual.evidence != expected.evidence
                    || actual.required_action != expected.required_action))
        {
            return Err(ReleaseEvidenceError::Invalid(
                "release-readiness gate identity, disposition, or action differs".to_owned(),
            ));
        }
    }
    let blocking = report
        .gates
        .iter()
        .filter(|gate| gate.status == GateStatus::NotSatisfied && gate.blocking)
        .map(|gate| gate.id.clone())
        .collect::<Vec<_>>();
    if blocking != report.blocking_gate_ids {
        return Err(ReleaseEvidenceError::Invalid(
            "release-readiness blocking gate list is inconsistent".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cargo_lock(bytes: &[u8]) -> Result<(), ReleaseEvidenceError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ReleaseEvidenceError::Invalid("Cargo.lock is not UTF-8".to_owned()))?;
    if !text.starts_with(
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n",
    ) || !text.contains("name = \"codex-linux-packager\"")
    {
        return Err(ReleaseEvidenceError::Invalid(
            "Cargo.lock is not the expected version-4 project lockfile".to_owned(),
        ));
    }
    Ok(())
}

fn parse_canonical_json<T>(input: &BoundedInput, label: &str) -> Result<T, ReleaseEvidenceError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(&input.bytes)
        .map_err(|error| ReleaseEvidenceError::Invalid(format!("parse {label}: {error}")))?;
    let canonical = to_json_line(&value)
        .map_err(|error| ReleaseEvidenceError::Invalid(format!("encode {label}: {error}")))?;
    if canonical.as_bytes() != input.bytes {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "{label} is not canonical schema-1 JSON"
        )));
    }
    Ok(value)
}

fn read_bounded_input(
    path: &Path,
    maximum: u64,
    label: &str,
) -> Result<BoundedInput, ReleaseEvidenceError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ReleaseEvidenceError::Input(format!("open {label}: {error}")))?;
    read_bounded_descriptor(descriptor, maximum, label)
}

fn read_bounded_descriptor(
    descriptor: OwnedFd,
    maximum: u64,
    label: &str,
) -> Result<BoundedInput, ReleaseEvidenceError> {
    if maximum == 0 {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} bound is zero"
        )));
    }
    let before = fstat(&descriptor)
        .map_err(|error| ReleaseEvidenceError::Input(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_size <= 0 {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} is not a nonempty regular file"
        )));
    }
    let length = u64::try_from(before.st_size)
        .map_err(|_| ReleaseEvidenceError::Input(format!("{label} size is negative")))?;
    if length > maximum {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| ReleaseEvidenceError::Input(format!("{label} size does not fit usize")))?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReleaseEvidenceError::Input(format!("read {label}: {error}")))?;
    if bytes.len() != capacity {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} changed length while reading"
        )));
    }
    validate_unchanged_input(&file, &before, label)?;
    Ok(BoundedInput {
        sha256: hex_lower(&Sha256::digest(&bytes)),
        bytes,
        length,
        mode: before.st_mode & 0o7777,
    })
}

fn digest_regular_input(
    path: &Path,
    maximum: u64,
    label: &str,
) -> Result<DigestedInput, ReleaseEvidenceError> {
    if maximum == 0 {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} bound is zero"
        )));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ReleaseEvidenceError::Input(format!("open {label}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| ReleaseEvidenceError::Input(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile || before.st_size <= 0 {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} is not a nonempty regular file"
        )));
    }
    let length = u64::try_from(before.st_size)
        .map_err(|_| ReleaseEvidenceError::Input(format!("{label} size is negative")))?;
    if length > maximum {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} exceeds {maximum} bytes"
        )));
    }
    let mut file = File::from(descriptor);
    let mut hasher = Sha256::new();
    let mut prefix = [0_u8; 20];
    let mut prefix_length = 0_usize;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| ReleaseEvidenceError::Input(format!("read {label}: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| ReleaseEvidenceError::Input("read size overflowed".to_owned()))?,
            )
            .ok_or_else(|| ReleaseEvidenceError::Input(format!("{label} length overflowed")))?;
        if total > length {
            return Err(ReleaseEvidenceError::Input(format!(
                "{label} grew while reading"
            )));
        }
        if prefix_length < prefix.len() {
            let copied = (prefix.len() - prefix_length).min(count);
            prefix[prefix_length..prefix_length + copied].copy_from_slice(&buffer[..copied]);
            prefix_length += copied;
        }
        hasher.update(&buffer[..count]);
    }
    if total != length || prefix_length != prefix.len() {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} changed length or is too short"
        )));
    }
    validate_unchanged_input(&file, &before, label)?;
    Ok(DigestedInput {
        sha256: hex_lower(&hasher.finalize()),
        length,
        mode: before.st_mode & 0o7777,
        prefix,
    })
}

fn validate_unchanged_input(
    file: &File,
    before: &rustix::fs::Stat,
    label: &str,
) -> Result<(), ReleaseEvidenceError> {
    let after = fstat(file)
        .map_err(|error| ReleaseEvidenceError::Input(format!("reinspect {label}: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_mtime != before.st_mtime
        || after.st_mtime_nsec != before.st_mtime_nsec
        || after.st_ctime != before.st_ctime
        || after.st_ctime_nsec != before.st_ctime_nsec
    {
        return Err(ReleaseEvidenceError::Input(format!(
            "{label} changed while being read"
        )));
    }
    Ok(())
}

fn validate_request(request: &ReleaseSbomRequest<'_>) -> Result<(), ReleaseEvidenceError> {
    validate_appdir(request.appdir)?;
    validate_digest(request.appdir_manifest_sha256, "AppDir manifest")?;
    validate_digest(request.artifact_sha256, "AppImage")?;
    validate_git_identity(request.source_commit, "source commit")?;
    validate_git_identity(request.source_tree, "source tree")?;
    validate_timestamp(request.created_at)?;
    if request.artifact_name != "codex-desktop-unofficial-x86_64.AppImage" {
        return Err(ReleaseEvidenceError::Invalid(
            "AppImage asset name differs from the Linux x86_64 contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_appdir(appdir: &AppDirManifest) -> Result<(), ReleaseEvidenceError> {
    if appdir.schema != SCHEMA_VERSION
        || appdir.producer != PRODUCER_IDENTIFIER
        || appdir.kind != APPDIR_KIND
        || appdir.application_version.is_empty()
        || appdir.application_build.is_empty()
        || appdir.entries.is_empty()
    {
        return Err(ReleaseEvidenceError::Invalid(
            "AppDir manifest identity is not current or its inventory is empty".to_owned(),
        ));
    }
    let mut previous = None;
    for entry in &appdir.entries {
        validate_digest(&entry.sha256, "AppDir entry")?;
        if entry.path.is_empty()
            || entry.path.starts_with('/')
            || entry
                .path
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
            || previous.is_some_and(|prior: &str| prior >= entry.path.as_str())
        {
            return Err(ReleaseEvidenceError::Invalid(
                "AppDir entries are not unique, safe, and strictly sorted".to_owned(),
            ));
        }
        previous = Some(entry.path.as_str());
    }
    Ok(())
}

fn is_notice_path(path: &str) -> bool {
    let Some(name) = path.rsplit('/').next() else {
        return false;
    };
    let upper = name.to_ascii_uppercase();
    ["LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS"]
        .iter()
        .any(|prefix| {
            upper == *prefix
                || upper
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with(['.', '-', '_']))
        })
}

fn validate_material_subject(
    subject: &ReleaseSubject,
    expected_name: &str,
    maximum_bytes: u64,
) -> Result<(), ReleaseEvidenceError> {
    if subject.name != expected_name || subject.bytes == 0 || subject.bytes > maximum_bytes {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "release subject {expected_name:?} has an invalid name or length"
        )));
    }
    validate_digest(&subject.sha256, "release subject")
}

fn subject_from_bytes(name: &str, bytes: &[u8]) -> Result<ReleaseSubject, ReleaseEvidenceError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| ReleaseEvidenceError::Invalid(format!("{name} length overflowed")))?;
    if length == 0 || length > MAX_SMALL_RELEASE_ASSET_BYTES {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "{name} length is outside its bound"
        )));
    }
    Ok(ReleaseSubject {
        name: name.to_owned(),
        bytes: length,
        sha256: hex_lower(&Sha256::digest(bytes)),
    })
}

fn validate_absolute_output(path: &Path) -> Result<(), ReleaseEvidenceError> {
    validate_absolute_path(path, "release evidence output")
        .map_err(|error| ReleaseEvidenceError::Publication(error.to_string()))
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), ReleaseEvidenceError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components.clone().count() < 2
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "{label} path must be absolute, normalized, and name one file or generation"
        )));
    }
    Ok(())
}

fn map_extraction_error(error: ExtractionError) -> ReleaseEvidenceError {
    match error {
        ExtractionError::PostCommitDurability(message) => {
            ReleaseEvidenceError::PostCommitDurability(message)
        }
        other => ReleaseEvidenceError::Publication(other.to_string()),
    }
}

fn cleanup_publication(
    publisher: &mut TreePublisher,
    original: ReleaseEvidenceError,
) -> ReleaseEvidenceError {
    match publisher.cleanup() {
        Ok(()) => original,
        Err(cleanup) => ReleaseEvidenceError::Publication(format!(
            "{original}; private evidence cleanup was intentionally incomplete: {cleanup}"
        )),
    }
}

fn validate_release_contract(contract: &UpdateContract) -> Result<[u8; 32], ReleaseEvidenceError> {
    if contract.schema != SCHEMA_VERSION
        || contract.producer != PRODUCER_IDENTIFIER
        || contract.kind != "linux_x86_64_update_contract"
        || contract.channel != "stable"
        || contract.target != "linux-x86_64"
        || contract.release_repository != "BearHuddleston/codex-linux-packager"
        || contract.artifact_name != "codex-desktop-unofficial-x86_64.AppImage"
    {
        return Err(ReleaseEvidenceError::Attestation(
            "release key contract identity differs".to_owned(),
        ));
    }
    validate_digest(&contract.public_key_sha256, "release public key")?;
    let decoded = BASE64_STANDARD
        .decode(&contract.public_key_base64)
        .map_err(|error| {
            ReleaseEvidenceError::Attestation(format!("decode release public key: {error}"))
        })?;
    let public_key: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        ReleaseEvidenceError::Attestation("release public key is not exactly 32 bytes".to_owned())
    })?;
    if BASE64_STANDARD.encode(public_key) != contract.public_key_base64
        || hex_lower(&Sha256::digest(public_key)) != contract.public_key_sha256
    {
        return Err(ReleaseEvidenceError::Attestation(
            "release public key encoding or fingerprint differs".to_owned(),
        ));
    }
    Ok(public_key)
}

fn validate_attestation_payload(
    payload: &ReleaseAttestationPayload,
    contract: Option<&UpdateContract>,
) -> Result<(), ReleaseEvidenceError> {
    if payload.schema != SCHEMA_VERSION
        || payload.producer != PRODUCER_IDENTIFIER
        || payload.kind != RELEASE_ATTESTATION_PAYLOAD_KIND
        || payload.predicate_type != RELEASE_PREDICATE_TYPE
        || payload.publication_status != RELEASE_EVIDENCE_STATUS
    {
        return Err(ReleaseEvidenceError::Attestation(
            "attestation payload identity or disposition differs".to_owned(),
        ));
    }
    validate_release_identity(&payload.application_version, &payload.application_build)?;
    let expected_tag = format!(
        "codex-app-{}-{}",
        payload.application_version, payload.application_build
    );
    if payload.release_tag != expected_tag {
        return Err(ReleaseEvidenceError::Attestation(
            "release tag differs from version/build".to_owned(),
        ));
    }
    validate_git_identity(&payload.source_commit, "source commit")?;
    validate_git_identity(&payload.source_tree, "source tree")?;
    validate_timestamp(payload.created_at.as_str())?;
    for digest in [
        &payload.evidence.appdir_manifest_sha256,
        &payload.evidence.appimage_provenance_sha256,
        &payload.evidence.update_manifest_sha256,
        &payload.evidence.release_readiness_sha256,
        &payload.evidence.cargo_lock_sha256,
        &payload.evidence.sbom_sha256,
        &payload.evidence.notice_inventory_sha256,
        &payload.evidence.checksums_sha256,
    ] {
        validate_digest(digest, "attestation evidence")?;
    }

    let expected_names = [
        "Cargo.lock",
        "SHA256SUMS",
        "appdir-manifest.json",
        "codex-desktop-unofficial-x86_64.AppImage",
        "codex-linux-x86_64-update.json",
        "codex-linux-x86_64.spdx.json",
        "provenance.json",
        "release-readiness.json",
        "third-party-notices.json",
    ];
    if payload.subjects.len() != expected_names.len() {
        return Err(ReleaseEvidenceError::Attestation(
            "release subject set is incomplete".to_owned(),
        ));
    }
    for (subject, expected_name) in payload.subjects.iter().zip(expected_names) {
        if subject.name != expected_name || subject.bytes == 0 {
            return Err(ReleaseEvidenceError::Attestation(
                "release subjects are not the exact sorted asset set".to_owned(),
            ));
        }
        validate_digest(&subject.sha256, "release subject")?;
        if subject.name != "codex-desktop-unofficial-x86_64.AppImage"
            && subject.bytes > MAX_SMALL_RELEASE_ASSET_BYTES
        {
            return Err(ReleaseEvidenceError::Attestation(
                "small release subject exceeds its bound".to_owned(),
            ));
        }
    }
    let subject_digest = |name: &str| {
        payload
            .subjects
            .iter()
            .find(|subject| subject.name == name)
            .map(|subject| subject.sha256.as_str())
    };
    if subject_digest("appdir-manifest.json")
        != Some(payload.evidence.appdir_manifest_sha256.as_str())
        || subject_digest("provenance.json")
            != Some(payload.evidence.appimage_provenance_sha256.as_str())
        || subject_digest("codex-linux-x86_64-update.json")
            != Some(payload.evidence.update_manifest_sha256.as_str())
        || subject_digest("codex-linux-x86_64.spdx.json")
            != Some(payload.evidence.sbom_sha256.as_str())
        || subject_digest("third-party-notices.json")
            != Some(payload.evidence.notice_inventory_sha256.as_str())
        || subject_digest("release-readiness.json")
            != Some(payload.evidence.release_readiness_sha256.as_str())
        || subject_digest("Cargo.lock") != Some(payload.evidence.cargo_lock_sha256.as_str())
        || subject_digest("SHA256SUMS") != Some(payload.evidence.checksums_sha256.as_str())
    {
        return Err(ReleaseEvidenceError::Attestation(
            "release subjects conflict with supporting evidence digests".to_owned(),
        ));
    }
    if let Some(contract) = contract {
        if payload.channel != contract.channel
            || payload.target != contract.target
            || payload.release_repository != contract.release_repository
            || subject_digest(&contract.artifact_name).is_none()
            || payload
                .subjects
                .iter()
                .find(|subject| subject.name == contract.artifact_name)
                .is_some_and(|subject| subject.bytes > contract.max_appimage_bytes)
        {
            return Err(ReleaseEvidenceError::Attestation(
                "attestation payload differs from the release contract".to_owned(),
            ));
        }
    } else if payload.channel != "stable"
        || payload.target != "linux-x86_64"
        || payload.release_repository != "BearHuddleston/codex-linux-packager"
    {
        return Err(ReleaseEvidenceError::Attestation(
            "attestation release namespace differs".to_owned(),
        ));
    }
    Ok(())
}

fn validate_release_identity(version: &str, build: &str) -> Result<(), ReleaseEvidenceError> {
    if version.len() > 128
        || build.len() > 32
        || build.is_empty()
        || !build.bytes().all(|byte| byte.is_ascii_digit())
        || version
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || version.matches('.').count() < 1
    {
        return Err(ReleaseEvidenceError::Attestation(
            "release version/build is not canonical numeric text".to_owned(),
        ));
    }
    Ok(())
}

fn decode_canonical<const N: usize>(
    encoded: &str,
    label: &str,
) -> Result<[u8; N], ReleaseEvidenceError> {
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|error| {
        ReleaseEvidenceError::Attestation(format!("decode {label} base64: {error}"))
    })?;
    let value: [u8; N] = decoded.as_slice().try_into().map_err(|_| {
        ReleaseEvidenceError::Attestation(format!("{label} has the wrong decoded length"))
    })?;
    if BASE64_STANDARD.encode(value) != encoded {
        return Err(ReleaseEvidenceError::Attestation(format!(
            "{label} base64 is not canonical"
        )));
    }
    Ok(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_cargo_license_report(bytes: &[u8]) -> Result<Vec<CargoPackage>, ReleaseEvidenceError> {
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(ReleaseEvidenceError::CargoLicenses(
            "report size is outside its bound".to_owned(),
        ));
    }
    let CargoDenyLicenseReport(report) = serde_json::from_slice(bytes)
        .map_err(|error| ReleaseEvidenceError::CargoLicenses(error.to_string()))?;
    if report.is_empty() || report.len() > 4_096 {
        return Err(ReleaseEvidenceError::CargoLicenses(
            "package count is outside its bound".to_owned(),
        ));
    }
    let mut packages = Vec::with_capacity(report.len());
    for (identity, entry) in report {
        let mut parts = identity.splitn(3, ' ');
        let name = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        let source = parts.next().unwrap_or_default();
        if !valid_package_token(name) || !valid_version(version) {
            return Err(ReleaseEvidenceError::CargoLicenses(format!(
                "invalid package identity {identity:?}"
            )));
        }
        let source = if source == CRATES_IO_SOURCE {
            CargoSource::CratesIo
        } else if source.starts_with("path+file:///") {
            CargoSource::Local
        } else {
            return Err(ReleaseEvidenceError::CargoLicenses(format!(
                "unreviewed package source in {identity:?}"
            )));
        };
        let mut licenses = entry.licenses;
        licenses.sort();
        if licenses.is_empty()
            || licenses.len() > 16
            || licenses.windows(2).any(|pair| pair[0] == pair[1])
            || licenses.iter().any(|license| !valid_license(license))
        {
            return Err(ReleaseEvidenceError::CargoLicenses(format!(
                "invalid license set for {identity:?}"
            )));
        }
        packages.push(CargoPackage {
            name: name.to_owned(),
            version: version.to_owned(),
            source,
            licenses,
        });
    }
    packages.sort();
    for pair in packages.windows(2) {
        if pair[0].name == pair[1].name && pair[0].version == pair[1].version {
            return Err(ReleaseEvidenceError::CargoLicenses(
                "duplicate normalized Cargo package identity".to_owned(),
            ));
        }
    }
    Ok(packages)
}

fn sha256_checksum(value: &str) -> SpdxChecksum {
    SpdxChecksum {
        algorithm: "SHA256".to_owned(),
        checksum_value: value.to_owned(),
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), ReleaseEvidenceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "{label} SHA-256 is not lowercase hexadecimal"
        )));
    }
    Ok(())
}

fn validate_git_identity(value: &str, label: &str) -> Result<(), ReleaseEvidenceError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseEvidenceError::Invalid(format!(
            "{label} is not a 40-character lowercase hexadecimal identity"
        )));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<(), ReleaseEvidenceError> {
    if !is_canonical_utc_timestamp(value) {
        return Err(ReleaseEvidenceError::Invalid(
            "creation time is not canonical UTC seconds".to_owned(),
        ));
    }
    Ok(())
}

fn valid_package_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'/')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
}

fn valid_license(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'+' | b'(' | b')' | b' ' | b'/')
        })
}

fn observed_license_comment(licenses: &[String]) -> String {
    format!(
        "cargo_deny_observed_license_identifiers=[{}]; no_license_expression_or_conclusion_is_asserted",
        licenses.join(",")
    )
}
