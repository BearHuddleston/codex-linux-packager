//! Authentication and bounded structural inspection of desktop ZIP artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use quick_xml::Reader;
use quick_xml::events::Event;
use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::ZipArchive;

use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION};
use crate::signature::{
    PINNED_SPARKLE_PUBLIC_KEY_BASE64, PINNED_SPARKLE_PUBLIC_KEY_SHA256, SignatureError,
    SignatureVerification, verify_ed25519_bytes,
};

/// Largest complete desktop artifact accepted by this implementation.
pub const MAX_ARTIFACT_BYTES: u64 = 640 * 1024 * 1024;
/// Largest central directory accepted before any general ZIP parsing.
pub const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 4 * 1024 * 1024;
/// Largest number of members accepted in one archive.
pub const MAX_ARCHIVE_MEMBERS: usize = 20_000;
/// Largest aggregate declared uncompressed size.
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Largest accepted `Info.plist`.
pub const MAX_INFO_PLIST_BYTES: u64 = 1024 * 1024;
/// Largest accepted `app.asar`.
pub const MAX_APP_ASAR_BYTES: u64 = 384 * 1024 * 1024;

const MAX_MEMBER_UNCOMPRESSED_BYTES: u64 = 768 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 100;
const MAX_MEMBER_NAME_BYTES: usize = 4_096;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PATH_COMPONENTS: usize = 64;
const EOCD_MIN_BYTES: usize = 22;
const EOCD_MAX_SEARCH_BYTES: usize = EOCD_MIN_BYTES + 65_535;
const CENTRAL_HEADER_BYTES: usize = 46;
const LOCAL_HEADER_BYTES: usize = 30;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const UNICODE_PATH_EXTRA_ID: u16 = 0x7075;
const AES_EXTRA_ID: u16 = 0x9901;
const ZIP_FLAG_ALLOWED: u16 = 0x0006 | 0x0008 | 0x0800;
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const ZIP_METHOD_STORED: u16 = 0;
const ZIP_METHOD_DEFLATE: u16 = 8;

/// Feed-derived facts that must agree with an authenticated artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContract {
    /// Exact complete artifact length declared by Sparkle.
    pub expected_length: u64,
    /// Canonical standard-base64 Ed25519 signature from Sparkle.
    pub signature_base64: String,
    /// Expected `CFBundleShortVersionString`.
    pub version: String,
    /// Expected `CFBundleVersion`.
    pub build: String,
}

/// Independently established Ed25519 trust root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTrust {
    public_key: [u8; 32],
    public_key_base64: String,
    public_key_sha256: String,
}

impl ArtifactTrust {
    /// Constructs a trust root from raw bytes. This is primarily useful for
    /// synthetic tests whose private key is generated only at test runtime.
    #[must_use]
    pub fn from_public_key(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            public_key_base64: BASE64_STANDARD.encode(public_key),
            public_key_sha256: hex_lower(&Sha256::digest(public_key)),
        }
    }

    /// Returns the independently reviewed production trust root.
    pub fn pinned_production() -> Result<Self, ArtifactError> {
        let decoded = decode_canonical::<32>(
            PINNED_SPARKLE_PUBLIC_KEY_BASE64,
            "compiled Sparkle public key",
        )?;
        let trust = Self::from_public_key(decoded);
        if trust.public_key_sha256 != PINNED_SPARKLE_PUBLIC_KEY_SHA256 {
            return Err(ArtifactError::Trust(
                "compiled Sparkle public key does not match its reviewed fingerprint".to_owned(),
            ));
        }
        Ok(trust)
    }

    /// SHA-256 fingerprint of the raw 32-byte public key.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.public_key_sha256
    }
}

/// Digest and size of a complete byte input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ByteIdentity {
    /// SHA-256 digest in lowercase hexadecimal.
    pub sha256: String,
    /// Exact byte count.
    pub bytes: u64,
}

/// Digest, size, and authenticated archive path of one selected member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveMemberIdentity {
    /// Raw-name-equivalent validated ASCII member path.
    pub path: String,
    /// SHA-256 digest of the uncompressed member bytes.
    pub sha256: String,
    /// Exact uncompressed byte count.
    pub bytes: u64,
}

/// ZIP resource-accounting facts established by the raw preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZipSummary {
    /// Number of central-directory members.
    pub member_count: u64,
    /// Validated link members retained only inside the opaque source archive.
    pub symlink_member_count: u64,
    /// Exact central-directory byte count.
    pub central_directory_bytes: u64,
    /// Aggregate declared uncompressed member bytes.
    pub total_uncompressed_bytes: u64,
}

/// Bundle facts reconciled with the feed contract and independent trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleMetadata {
    /// Canonical top-level `.app` directory.
    pub root: String,
    /// Exact application bundle identifier.
    pub identifier: String,
    /// Exact short version.
    pub version: String,
    /// Exact build version.
    pub build: String,
    /// Flat executable basename declared by the bundle.
    pub executable: String,
    /// SHA-256 fingerprint of the declared and independently pinned key.
    pub sparkle_public_key_sha256: String,
}

/// Deterministic schema-1 artifact inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactInspection {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer identifier.
    pub producer: &'static str,
    /// Stable document kind.
    pub kind: &'static str,
    /// Identity of the exact signed archive bytes.
    pub artifact: ByteIdentity,
    /// Exact signature operation that succeeded.
    pub signature: SignatureVerification,
    /// Raw ZIP preflight accounting.
    pub zip: ZipSummary,
    /// Reconciled authenticated bundle metadata.
    pub bundle: BundleMetadata,
    /// Identity of the only application payload member selected for staging.
    pub app_asar: ArchiveMemberIdentity,
}

/// Rejection of an unauthenticated, ambiguous, or unsafe artifact.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArtifactError {
    /// The complete byte envelope conflicts with the feed contract.
    #[error("invalid artifact envelope: {0}")]
    Envelope(String),
    /// A local artifact path could not be opened or read safely.
    #[error("invalid local artifact input: {0}")]
    Input(String),
    /// The independently established trust root is invalid.
    #[error("invalid artifact trust root: {0}")]
    Trust(String),
    /// Exact-byte Ed25519 authentication failed.
    #[error("artifact signature authentication failed: {0}")]
    Signature(#[from] SignatureError),
    /// Raw ZIP structure is unsafe or unsupported.
    #[error("invalid artifact ZIP: {0}")]
    Zip(String),
    /// Bundle metadata or selected members conflict with the contract.
    #[error("invalid artifact bundle: {0}")]
    Bundle(String),
}

#[derive(Debug)]
pub struct InspectedArtifact {
    /// Deterministic authentication and bundle-inspection record.
    pub inspection: ArtifactInspection,
    /// Exact uncompressed authenticated `app.asar` member bytes.
    pub app_asar: Vec<u8>,
}

/// Exact source bytes plus the selectively extracted authenticated payload.
#[derive(Debug)]
pub struct AuthenticatedArtifact {
    /// Exact complete signed source archive.
    pub source_archive: Vec<u8>,
    /// Deterministic inspection record.
    pub inspection: ArtifactInspection,
    /// Exact authenticated `app.asar` member.
    pub app_asar: Vec<u8>,
}

#[derive(Debug)]
struct Preflight {
    members: Vec<Member>,
    central_directory_bytes: u64,
    total_uncompressed_bytes: u64,
}

#[derive(Debug)]
struct Member {
    index: usize,
    raw_name: Vec<u8>,
    name: String,
    flags: u16,
    method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: usize,
    kind: MemberKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    Regular,
    Directory,
    Symlink,
}

/// Authenticates the exact complete artifact bytes, preflights the raw ZIP, and
/// reconciles the one canonical bundle without writing to the filesystem.
pub fn inspect_artifact_bytes(
    bytes: &[u8],
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<ArtifactInspection, ArtifactError> {
    Ok(inspect_artifact_payload(bytes, contract, trust)?.inspection)
}

/// Opens one bounded regular artifact without following a final symlink or
/// blocking on a FIFO, then authenticates and inspects its exact bytes.
pub fn inspect_artifact_file(
    path: &Path,
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<ArtifactInspection, ArtifactError> {
    Ok(authenticate_artifact_file(path, contract, trust)?.inspection)
}

/// Safely reads and authenticates a local artifact while retaining the exact
/// source archive and selected `app.asar` bytes for transactional staging.
pub fn authenticate_artifact_file(
    path: &Path,
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<AuthenticatedArtifact, ArtifactError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            ArtifactError::Input("artifact path is a symlink".to_owned())
        } else {
            ArtifactError::Input(error.to_string())
        }
    })?;
    let metadata = fstat(&descriptor).map_err(|error| ArtifactError::Input(error.to_string()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(ArtifactError::Input(
            "artifact input is not a regular file".to_owned(),
        ));
    }
    if metadata.st_size < 0 {
        return Err(ArtifactError::Input(
            "artifact input has a negative size".to_owned(),
        ));
    }
    let size = u64::try_from(metadata.st_size)
        .map_err(|_| ArtifactError::Input("artifact input size does not fit u64".to_owned()))?;
    if size > MAX_ARTIFACT_BYTES {
        return Err(ArtifactError::Input(format!(
            "artifact input exceeds {MAX_ARTIFACT_BYTES} bytes"
        )));
    }
    if size != contract.expected_length {
        return Err(ArtifactError::Input(format!(
            "artifact input size {size} differs from declared length {}",
            contract.expected_length
        )));
    }

    let capacity = usize::try_from(size)
        .map_err(|_| ArtifactError::Input("artifact input size does not fit usize".to_owned()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(descriptor);
    file.by_ref()
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ArtifactError::Input(error.to_string()))?;
    if bytes.len() != capacity {
        return Err(ArtifactError::Input(
            "artifact input changed size or was truncated while reading".to_owned(),
        ));
    }
    let after = fstat(&file).map_err(|error| ArtifactError::Input(error.to_string()))?;
    if after.st_size != metadata.st_size
        || after.st_dev != metadata.st_dev
        || after.st_ino != metadata.st_ino
    {
        return Err(ArtifactError::Input(
            "artifact input identity changed while reading".to_owned(),
        ));
    }
    let inspected = inspect_artifact_payload(&bytes, contract, trust)?;
    Ok(AuthenticatedArtifact {
        source_archive: bytes,
        inspection: inspected.inspection,
        app_asar: inspected.app_asar,
    })
}

pub(crate) fn inspect_artifact_payload(
    bytes: &[u8],
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<InspectedArtifact, ArtifactError> {
    let artifact_bytes = u64::try_from(bytes.len())
        .map_err(|_| ArtifactError::Envelope("artifact length does not fit u64".to_owned()))?;
    if artifact_bytes == 0 {
        return Err(ArtifactError::Envelope("artifact is empty".to_owned()));
    }
    if artifact_bytes > MAX_ARTIFACT_BYTES {
        return Err(ArtifactError::Envelope(format!(
            "artifact exceeds {MAX_ARTIFACT_BYTES} bytes"
        )));
    }
    if artifact_bytes != contract.expected_length {
        return Err(ArtifactError::Envelope(format!(
            "artifact length {artifact_bytes} differs from declared length {}",
            contract.expected_length
        )));
    }
    validate_version(&contract.version, "contract version")?;
    validate_build(&contract.build, "contract build")?;

    let signature = decode_canonical::<64>(&contract.signature_base64, "Sparkle signature")?;
    verify_ed25519_bytes(bytes, &signature, &trust.public_key)?;
    let signature = SignatureVerification {
        algorithm: "ed25519-rfc8032-exact-artifact-bytes",
        verified: true,
        public_key_sha256: trust.public_key_sha256.clone(),
    };

    let preflight = preflight_zip(bytes)?;
    let info_candidates: Vec<&Member> = preflight
        .members
        .iter()
        .filter(|member| is_canonical_info_path(&member.name) && member.kind == MemberKind::Regular)
        .collect();
    let info_member = exactly_one(info_candidates, "canonical Info.plist")?;
    if info_member.uncompressed_size == 0 || info_member.uncompressed_size > MAX_INFO_PLIST_BYTES {
        return Err(ArtifactError::Bundle(format!(
            "Info.plist size is outside 1..={MAX_INFO_PLIST_BYTES}"
        )));
    }

    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
        ArtifactError::Zip(format!("general parser rejected preflighted ZIP: {error}"))
    })?;
    if zip.len() != preflight.members.len() {
        return Err(ArtifactError::Zip(
            "general parser member count differs from raw preflight".to_owned(),
        ));
    }
    let info_bytes = read_member(&mut zip, info_member)?;
    let parsed_bundle = parse_bundle_plist(&info_bytes, contract, trust)?;
    let root = info_member
        .name
        .strip_suffix("/Contents/Info.plist")
        .ok_or_else(|| ArtifactError::Bundle("invalid canonical Info.plist path".to_owned()))?;
    if !root.ends_with(".app") || root.contains('/') {
        return Err(ArtifactError::Bundle(
            "canonical bundle root must be one top-level .app directory".to_owned(),
        ));
    }

    let app_asar_path = format!("{root}/Contents/Resources/app.asar");
    let app_asar_candidates: Vec<&Member> = preflight
        .members
        .iter()
        .filter(|member| member.name == app_asar_path && member.kind == MemberKind::Regular)
        .collect();
    let app_asar_member = exactly_one(app_asar_candidates, "same-root app.asar")?;
    if app_asar_member.uncompressed_size == 0
        || app_asar_member.uncompressed_size > MAX_APP_ASAR_BYTES
    {
        return Err(ArtifactError::Bundle(format!(
            "app.asar size is outside 1..={MAX_APP_ASAR_BYTES}"
        )));
    }

    let executable_path = format!("{root}/Contents/MacOS/{}", parsed_bundle.executable);
    let executable_candidates: Vec<&Member> = preflight
        .members
        .iter()
        .filter(|member| member.name == executable_path && member.kind == MemberKind::Regular)
        .collect();
    let executable_member = exactly_one(executable_candidates, "same-root declared executable")?;
    if executable_member.uncompressed_size == 0 {
        return Err(ArtifactError::Bundle(
            "declared executable member is empty".to_owned(),
        ));
    }

    let app_asar = read_member(&mut zip, app_asar_member)?;
    let app_asar_bytes = u64::try_from(app_asar.len())
        .map_err(|_| ArtifactError::Bundle("app.asar length does not fit u64".to_owned()))?;
    let inspection = ArtifactInspection {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "artifact_inspection",
        artifact: ByteIdentity {
            sha256: hex_lower(&Sha256::digest(bytes)),
            bytes: artifact_bytes,
        },
        signature,
        zip: ZipSummary {
            member_count: u64::try_from(preflight.members.len())
                .map_err(|_| ArtifactError::Zip("member count does not fit u64".to_owned()))?,
            symlink_member_count: u64::try_from(
                preflight
                    .members
                    .iter()
                    .filter(|member| member.kind == MemberKind::Symlink)
                    .count(),
            )
            .map_err(|_| ArtifactError::Zip("symlink count does not fit u64".to_owned()))?,
            central_directory_bytes: preflight.central_directory_bytes,
            total_uncompressed_bytes: preflight.total_uncompressed_bytes,
        },
        bundle: BundleMetadata {
            root: root.to_owned(),
            identifier: parsed_bundle.identifier,
            version: parsed_bundle.version,
            build: parsed_bundle.build,
            executable: parsed_bundle.executable,
            sparkle_public_key_sha256: trust.public_key_sha256.clone(),
        },
        app_asar: ArchiveMemberIdentity {
            path: app_asar_path,
            sha256: hex_lower(&Sha256::digest(&app_asar)),
            bytes: app_asar_bytes,
        },
    };

    Ok(InspectedArtifact {
        inspection,
        app_asar,
    })
}

fn preflight_zip(bytes: &[u8]) -> Result<Preflight, ArtifactError> {
    let eocd_offset = find_unique_final_eocd(bytes)?;
    let disk = read_u16(bytes, eocd_offset + 4)?;
    let central_disk = read_u16(bytes, eocd_offset + 6)?;
    let entries_on_disk = read_u16(bytes, eocd_offset + 8)?;
    let entry_count = read_u16(bytes, eocd_offset + 10)?;
    let central_size_u32 = read_u32(bytes, eocd_offset + 12)?;
    let central_offset_u32 = read_u32(bytes, eocd_offset + 16)?;
    if disk != 0 || central_disk != 0 || entries_on_disk != entry_count {
        return Err(ArtifactError::Zip(
            "multi-disk and split archives are forbidden".to_owned(),
        ));
    }
    if entry_count == u16::MAX || central_size_u32 == u32::MAX || central_offset_u32 == u32::MAX {
        return Err(ArtifactError::Zip(
            "ZIP64 archives are forbidden".to_owned(),
        ));
    }
    let entry_count = usize::from(entry_count);
    if entry_count == 0 || entry_count > MAX_ARCHIVE_MEMBERS {
        return Err(ArtifactError::Zip(format!(
            "member count is outside 1..={MAX_ARCHIVE_MEMBERS}"
        )));
    }
    let central_size = u64::from(central_size_u32);
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES {
        return Err(ArtifactError::Zip(format!(
            "central directory exceeds {MAX_CENTRAL_DIRECTORY_BYTES} bytes"
        )));
    }
    let central_offset = usize::try_from(central_offset_u32).map_err(|_| {
        ArtifactError::Zip("central directory offset does not fit usize".to_owned())
    })?;
    let central_size_usize = usize::try_from(central_size)
        .map_err(|_| ArtifactError::Zip("central directory size does not fit usize".to_owned()))?;
    let central_end = checked_add(central_offset, central_size_usize, "central directory")?;
    if central_end != eocd_offset {
        return Err(ArtifactError::Zip(
            "central directory does not end exactly at the final EOCD".to_owned(),
        ));
    }

    let mut cursor = central_offset;
    let mut members = Vec::with_capacity(entry_count);
    let mut names = BTreeSet::<Vec<u8>>::new();
    let mut total_uncompressed = 0_u64;
    for index in 0..entry_count {
        require_signature(bytes, cursor, b"PK\x01\x02", "central-directory header")?;
        let fixed_end = checked_add(cursor, CENTRAL_HEADER_BYTES, "central-directory header")?;
        if fixed_end > central_end {
            return Err(ArtifactError::Zip(
                "truncated central-directory header".to_owned(),
            ));
        }
        let creator_os = bytes[cursor + 5];
        let flags = read_u16(bytes, cursor + 8)?;
        let method = read_u16(bytes, cursor + 10)?;
        let crc32 = read_u32(bytes, cursor + 16)?;
        let compressed_size = u64::from(read_u32(bytes, cursor + 20)?);
        let uncompressed_size = u64::from(read_u32(bytes, cursor + 24)?);
        let name_length = usize::from(read_u16(bytes, cursor + 28)?);
        let extra_length = usize::from(read_u16(bytes, cursor + 30)?);
        let comment_length = usize::from(read_u16(bytes, cursor + 32)?);
        let start_disk = read_u16(bytes, cursor + 34)?;
        let external_attributes = read_u32(bytes, cursor + 38)?;
        let local_offset_u32 = read_u32(bytes, cursor + 42)?;
        if compressed_size == u64::from(u32::MAX)
            || uncompressed_size == u64::from(u32::MAX)
            || local_offset_u32 == u32::MAX
        {
            return Err(ArtifactError::Zip("ZIP64 members are forbidden".to_owned()));
        }
        if start_disk != 0 {
            return Err(ArtifactError::Zip(
                "member starts on a foreign disk".to_owned(),
            ));
        }
        validate_flags_and_method(flags, method)?;
        validate_resource_bounds(compressed_size, uncompressed_size)?;

        let name_start = fixed_end;
        let name_end = checked_add(name_start, name_length, "member name")?;
        let extra_end = checked_add(name_end, extra_length, "central extra field")?;
        let entry_end = checked_add(extra_end, comment_length, "member comment")?;
        if entry_end > central_end {
            return Err(ArtifactError::Zip(
                "central-directory entry crosses its declared boundary".to_owned(),
            ));
        }
        let raw_name = bytes[name_start..name_end].to_vec();
        let (name, is_directory) = validate_raw_name(&raw_name)?;
        if !names.insert(raw_name.clone()) {
            return Err(ArtifactError::Zip(format!(
                "duplicate raw member name {name:?}"
            )));
        }
        validate_extra(&bytes[name_end..extra_end])?;
        let kind = validate_member_kind(
            creator_os,
            external_attributes,
            is_directory,
            &name,
            method,
            uncompressed_size,
        )?;
        total_uncompressed = total_uncompressed
            .checked_add(uncompressed_size)
            .ok_or_else(|| ArtifactError::Zip("uncompressed size sum overflowed".to_owned()))?;
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(ArtifactError::Zip(format!(
                "aggregate uncompressed size exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
            )));
        }
        let local_offset = usize::try_from(local_offset_u32)
            .map_err(|_| ArtifactError::Zip("local header offset does not fit usize".to_owned()))?;
        if local_offset >= central_offset {
            return Err(ArtifactError::Zip(
                "local header is not before the central directory".to_owned(),
            ));
        }
        members.push(Member {
            index,
            raw_name,
            name,
            flags,
            method,
            crc32,
            compressed_size,
            uncompressed_size,
            local_offset,
            kind,
        });
        cursor = entry_end;
    }
    if cursor != central_end {
        return Err(ArtifactError::Zip(
            "central directory has unparsed trailing bytes".to_owned(),
        ));
    }

    validate_local_records(bytes, central_offset, &members)?;
    Ok(Preflight {
        members,
        central_directory_bytes: central_size,
        total_uncompressed_bytes: total_uncompressed,
    })
}

fn find_unique_final_eocd(bytes: &[u8]) -> Result<usize, ArtifactError> {
    if bytes.len() < EOCD_MIN_BYTES {
        return Err(ArtifactError::Zip(
            "archive is shorter than an EOCD".to_owned(),
        ));
    }
    let start = bytes.len().saturating_sub(EOCD_MAX_SEARCH_BYTES);
    let last = bytes.len() - EOCD_MIN_BYTES;
    let mut candidate = None;
    for offset in start..=last {
        if bytes.get(offset..offset + 4) != Some(b"PK\x05\x06") {
            continue;
        }
        let comment_length = usize::from(read_u16(bytes, offset + 20)?);
        let end = checked_add(offset + EOCD_MIN_BYTES, comment_length, "EOCD comment")?;
        if end == bytes.len() && candidate.replace(offset).is_some() {
            return Err(ArtifactError::Zip(
                "multiple final EOCD candidates are ambiguous".to_owned(),
            ));
        }
    }
    candidate.ok_or_else(|| {
        ArtifactError::Zip("no unique EOCD ending at the final archive byte".to_owned())
    })
}

fn validate_local_records(
    bytes: &[u8],
    central_offset: usize,
    members: &[Member],
) -> Result<(), ArtifactError> {
    let mut ranges = Vec::<(usize, usize)>::with_capacity(members.len());
    for member in members {
        let offset = member.local_offset;
        require_signature(bytes, offset, b"PK\x03\x04", "local-file header")?;
        let fixed_end = checked_add(offset, LOCAL_HEADER_BYTES, "local-file header")?;
        if fixed_end > central_offset {
            return Err(ArtifactError::Zip(
                "local-file header crosses the central directory".to_owned(),
            ));
        }
        let flags = read_u16(bytes, offset + 6)?;
        let method = read_u16(bytes, offset + 8)?;
        let local_crc = read_u32(bytes, offset + 14)?;
        let local_compressed = u64::from(read_u32(bytes, offset + 18)?);
        let local_uncompressed = u64::from(read_u32(bytes, offset + 22)?);
        let name_length = usize::from(read_u16(bytes, offset + 26)?);
        let extra_length = usize::from(read_u16(bytes, offset + 28)?);
        if flags != member.flags || method != member.method {
            return Err(ArtifactError::Zip(format!(
                "local header conflicts with central metadata for {:?}",
                member.name
            )));
        }
        let name_end = checked_add(fixed_end, name_length, "local member name")?;
        let extra_end = checked_add(name_end, extra_length, "local extra field")?;
        if extra_end > central_offset {
            return Err(ArtifactError::Zip(
                "local header metadata crosses the central directory".to_owned(),
            ));
        }
        if bytes[fixed_end..name_end] != member.raw_name {
            return Err(ArtifactError::Zip(format!(
                "local and central raw names differ for {:?}",
                member.name
            )));
        }
        validate_extra(&bytes[name_end..extra_end])?;
        let has_descriptor = flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        if has_descriptor {
            if !((local_crc == 0 || local_crc == member.crc32)
                && (local_compressed == 0 || local_compressed == member.compressed_size)
                && (local_uncompressed == 0 || local_uncompressed == member.uncompressed_size))
            {
                return Err(ArtifactError::Zip(format!(
                    "local placeholder sizes conflict for {:?}",
                    member.name
                )));
            }
        } else if local_crc != member.crc32
            || local_compressed != member.compressed_size
            || local_uncompressed != member.uncompressed_size
        {
            return Err(ArtifactError::Zip(format!(
                "local sizes or CRC conflict for {:?}",
                member.name
            )));
        }
        let compressed_size = usize::try_from(member.compressed_size)
            .map_err(|_| ArtifactError::Zip("compressed size does not fit usize".to_owned()))?;
        let data_end = checked_add(extra_end, compressed_size, "compressed member data")?;
        if data_end > central_offset {
            return Err(ArtifactError::Zip(format!(
                "compressed data crosses the central directory for {:?}",
                member.name
            )));
        }
        if member.kind == MemberKind::Symlink {
            validate_symlink_target(&member.name, &bytes[extra_end..data_end])?;
        }
        let record_end = if has_descriptor {
            validate_data_descriptor(bytes, data_end, central_offset, member)?
        } else {
            data_end
        };
        ranges.push((offset, record_end));
    }
    ranges.sort_unstable();
    let mut expected_start = 0_usize;
    for (start, end) in ranges {
        if start != expected_start {
            return Err(ArtifactError::Zip(
                "local records overlap or contain unexplained gaps".to_owned(),
            ));
        }
        if end <= start {
            return Err(ArtifactError::Zip(
                "local record has an invalid byte range".to_owned(),
            ));
        }
        expected_start = end;
    }
    if expected_start != central_offset {
        return Err(ArtifactError::Zip(
            "local records do not end exactly at the central directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_data_descriptor(
    bytes: &[u8],
    offset: usize,
    central_offset: usize,
    member: &Member,
) -> Result<usize, ArtifactError> {
    let signed = bytes.get(offset..offset.saturating_add(4)) == Some(b"PK\x07\x08");
    let body = if signed {
        checked_add(offset, 4, "data-descriptor signature")?
    } else {
        offset
    };
    let end = checked_add(body, 12, "data descriptor")?;
    if end > central_offset {
        return Err(ArtifactError::Zip(format!(
            "truncated data descriptor for {:?}",
            member.name
        )));
    }
    if read_u32(bytes, body)? != member.crc32
        || u64::from(read_u32(bytes, body + 4)?) != member.compressed_size
        || u64::from(read_u32(bytes, body + 8)?) != member.uncompressed_size
    {
        return Err(ArtifactError::Zip(format!(
            "data descriptor conflicts for {:?}",
            member.name
        )));
    }
    Ok(end)
}

fn validate_flags_and_method(flags: u16, method: u16) -> Result<(), ArtifactError> {
    if flags & !ZIP_FLAG_ALLOWED != 0 {
        return Err(ArtifactError::Zip(format!(
            "unsupported or dangerous ZIP flags 0x{flags:04x}"
        )));
    }
    if method != ZIP_METHOD_STORED && method != ZIP_METHOD_DEFLATE {
        return Err(ArtifactError::Zip(format!(
            "unsupported compression method {method}"
        )));
    }
    if method == ZIP_METHOD_STORED && flags & 0x0006 != 0 {
        return Err(ArtifactError::Zip(
            "deflate option flags are set on a stored member".to_owned(),
        ));
    }
    Ok(())
}

fn validate_resource_bounds(compressed: u64, uncompressed: u64) -> Result<(), ArtifactError> {
    if uncompressed > MAX_MEMBER_UNCOMPRESSED_BYTES {
        return Err(ArtifactError::Zip(format!(
            "member exceeds {MAX_MEMBER_UNCOMPRESSED_BYTES} uncompressed bytes"
        )));
    }
    if compressed == 0 {
        if uncompressed != 0 {
            return Err(ArtifactError::Zip(
                "nonempty member declares zero compressed bytes".to_owned(),
            ));
        }
    } else {
        let maximum = compressed.saturating_mul(MAX_COMPRESSION_RATIO);
        if uncompressed > maximum {
            return Err(ArtifactError::Zip(format!(
                "member exceeds {MAX_COMPRESSION_RATIO}:1 compression ratio"
            )));
        }
    }
    Ok(())
}

fn validate_raw_name(raw: &[u8]) -> Result<(String, bool), ArtifactError> {
    if raw.is_empty() || raw.len() > MAX_MEMBER_NAME_BYTES {
        return Err(ArtifactError::Zip(format!(
            "raw member name length is outside 1..={MAX_MEMBER_NAME_BYTES}"
        )));
    }
    if raw
        .iter()
        .any(|byte| !(0x20..=0x7e).contains(byte) || *byte == b'\\' || *byte == b':')
    {
        return Err(ArtifactError::Zip(
            "raw member names must use safe printable ASCII".to_owned(),
        ));
    }
    let name = std::str::from_utf8(raw)
        .map_err(|_| ArtifactError::Zip("raw member name is not UTF-8".to_owned()))?
        .to_owned();
    if name.starts_with('/') {
        return Err(ArtifactError::Zip(
            "absolute member paths are forbidden".to_owned(),
        ));
    }
    let is_directory = name.ends_with('/');
    let path = if is_directory {
        name.strip_suffix('/').unwrap_or_default()
    } else {
        &name
    };
    let components: Vec<&str> = path.split('/').collect();
    if components.is_empty() || components.len() > MAX_PATH_COMPONENTS {
        return Err(ArtifactError::Zip(format!(
            "member path component count is outside 1..={MAX_PATH_COMPONENTS}"
        )));
    }
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_PATH_COMPONENT_BYTES
        {
            return Err(ArtifactError::Zip(
                "member path contains an empty, dot, or oversized component".to_owned(),
            ));
        }
    }
    Ok((name, is_directory))
}

fn validate_extra(extra: &[u8]) -> Result<(), ArtifactError> {
    let mut offset = 0_usize;
    let mut identifiers = BTreeSet::new();
    while offset < extra.len() {
        let header_end = checked_add(offset, 4, "ZIP extra-field header")?;
        if header_end > extra.len() {
            return Err(ArtifactError::Zip(
                "truncated ZIP extra-field header".to_owned(),
            ));
        }
        let identifier = u16::from_le_bytes([extra[offset], extra[offset + 1]]);
        let length = usize::from(u16::from_le_bytes([extra[offset + 2], extra[offset + 3]]));
        if !identifiers.insert(identifier) {
            return Err(ArtifactError::Zip(format!(
                "duplicate ZIP extra-field identifier 0x{identifier:04x}"
            )));
        }
        if matches!(
            identifier,
            ZIP64_EXTRA_ID | UNICODE_PATH_EXTRA_ID | AES_EXTRA_ID
        ) {
            return Err(ArtifactError::Zip(format!(
                "unsupported ambiguous ZIP extra field 0x{identifier:04x}"
            )));
        }
        offset = checked_add(header_end, length, "ZIP extra-field payload")?;
        if offset > extra.len() {
            return Err(ArtifactError::Zip(
                "truncated ZIP extra-field payload".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_member_kind(
    creator_os: u8,
    external_attributes: u32,
    is_directory: bool,
    name: &str,
    method: u16,
    uncompressed_size: u64,
) -> Result<MemberKind, ArtifactError> {
    match creator_os {
        3 => {
            let mode = external_attributes >> 16;
            let file_type = mode & 0o170000;
            match (file_type, is_directory) {
                (0 | 0o100000, false) => Ok(MemberKind::Regular),
                (0 | 0o040000, true) => Ok(MemberKind::Directory),
                (0o120000, false)
                    if method == ZIP_METHOD_STORED
                        && (1..=MAX_MEMBER_NAME_BYTES as u64).contains(&uncompressed_size) =>
                {
                    Ok(MemberKind::Symlink)
                }
                (0o120000, false) => Err(ArtifactError::Zip(format!(
                    "symlink {name:?} must be stored and have a bounded nonempty target"
                ))),
                _ => Err(ArtifactError::Zip(format!(
                    "special-file mode or name/type conflict is forbidden for {name:?}"
                ))),
            }
        }
        0 => {
            let dos_directory = external_attributes & 0x10 != 0;
            if dos_directory != is_directory {
                return Err(ArtifactError::Zip(format!(
                    "DOS directory attributes conflict for {name:?}"
                )));
            }
            Ok(if is_directory {
                MemberKind::Directory
            } else {
                MemberKind::Regular
            })
        }
        other => Err(ArtifactError::Zip(format!(
            "unsupported creator operating system {other} for {name:?}"
        ))),
    }
}

fn validate_symlink_target(name: &str, target: &[u8]) -> Result<(), ArtifactError> {
    if target.is_empty()
        || target.len() > MAX_MEMBER_NAME_BYTES
        || target
            .iter()
            .any(|byte| !(0x20..=0x7e).contains(byte) || *byte == b'\\' || *byte == b':')
    {
        return Err(ArtifactError::Zip(format!(
            "symlink target for {name:?} is not bounded safe printable ASCII"
        )));
    }
    let target = std::str::from_utf8(target)
        .map_err(|_| ArtifactError::Zip(format!("symlink target for {name:?} is not UTF-8")))?;
    if target.starts_with('/') {
        return Err(ArtifactError::Zip(format!(
            "absolute symlink target is forbidden for {name:?}"
        )));
    }
    let mut resolved: Vec<&str> = name.split('/').collect();
    let _ = resolved.pop();
    for component in target.split('/') {
        match component {
            "" => {
                return Err(ArtifactError::Zip(format!(
                    "empty symlink target component for {name:?}"
                )));
            }
            "." => {}
            ".." => {
                if resolved.len() <= 1 {
                    return Err(ArtifactError::Zip(format!(
                        "symlink target escapes its top-level root for {name:?}"
                    )));
                }
                let _ = resolved.pop();
            }
            value if value.len() <= MAX_PATH_COMPONENT_BYTES => resolved.push(value),
            _ => {
                return Err(ArtifactError::Zip(format!(
                    "oversized symlink target component for {name:?}"
                )));
            }
        }
    }
    Ok(())
}

fn is_canonical_info_path(path: &str) -> bool {
    let mut components = path.split('/');
    matches!(
        (
            components.next(),
            components.next(),
            components.next(),
            components.next()
        ),
        (Some(root), Some("Contents"), Some("Info.plist"), None)
            if root.ends_with(".app") && !root.is_empty()
    )
}

fn exactly_one<'a>(candidates: Vec<&'a Member>, label: &str) -> Result<&'a Member, ArtifactError> {
    if candidates.len() != 1 {
        return Err(ArtifactError::Bundle(format!(
            "expected exactly one {label}, found {}",
            candidates.len()
        )));
    }
    Ok(candidates[0])
}

fn read_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    member: &Member,
) -> Result<Vec<u8>, ArtifactError> {
    let mut file = archive.by_index(member.index).map_err(|error| {
        ArtifactError::Zip(format!(
            "failed to open preflighted member {:?}: {error}",
            member.name
        ))
    })?;
    if file.name_raw() != member.raw_name
        || file.size() != member.uncompressed_size
        || file.compressed_size() != member.compressed_size
    {
        return Err(ArtifactError::Zip(format!(
            "general parser metadata differs for {:?}",
            member.name
        )));
    }
    let expected = usize::try_from(member.uncompressed_size)
        .map_err(|_| ArtifactError::Zip("member size does not fit usize".to_owned()))?;
    let mut output = Vec::with_capacity(expected);
    let limit = member
        .uncompressed_size
        .checked_add(1)
        .ok_or_else(|| ArtifactError::Zip("member read limit overflowed".to_owned()))?;
    file.by_ref()
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| {
            ArtifactError::Zip(format!(
                "failed to decompress or authenticate CRC for {:?}: {error}",
                member.name
            ))
        })?;
    if output.len() != expected {
        return Err(ArtifactError::Zip(format!(
            "decompressed length differs for {:?}",
            member.name
        )));
    }
    Ok(output)
}

#[derive(Debug)]
struct ParsedBundle {
    identifier: String,
    version: String,
    build: String,
    executable: String,
}

fn parse_bundle_plist(
    bytes: &[u8],
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<ParsedBundle, ArtifactError> {
    if bytes.contains(&0) {
        return Err(ArtifactError::Bundle(
            "Info.plist contains a NUL byte".to_owned(),
        ));
    }
    if !bytes.starts_with(b"<?xml") {
        return Err(ArtifactError::Bundle(
            "only an XML Info.plist is accepted".to_owned(),
        ));
    }
    reject_duplicate_critical_plist_keys(bytes)?;
    let dictionary = parse_root_plist_strings(bytes)?;
    let identifier = required_plist_string(&dictionary, "CFBundleIdentifier")?;
    if identifier != "com.openai.codex" {
        return Err(ArtifactError::Bundle(format!(
            "unexpected bundle identifier {identifier:?}"
        )));
    }
    let version = required_plist_string(&dictionary, "CFBundleShortVersionString")?;
    if version != contract.version {
        return Err(ArtifactError::Bundle(
            "bundle version differs from the feed contract".to_owned(),
        ));
    }
    let build = required_plist_string(&dictionary, "CFBundleVersion")?;
    if build != contract.build {
        return Err(ArtifactError::Bundle(
            "bundle build differs from the feed contract".to_owned(),
        ));
    }
    let executable = required_plist_string(&dictionary, "CFBundleExecutable")?;
    validate_flat_component(&executable, "CFBundleExecutable")?;
    let declared_key = required_plist_string(&dictionary, "SUPublicEDKey")?;
    let decoded_key = decode_canonical::<32>(&declared_key, "bundle SUPublicEDKey")?;
    if decoded_key != trust.public_key || declared_key != trust.public_key_base64 {
        return Err(ArtifactError::Bundle(
            "bundle signing key differs from the independent trust root".to_owned(),
        ));
    }

    Ok(ParsedBundle {
        identifier,
        version,
        build,
        executable,
    })
}

fn reject_duplicate_critical_plist_keys(bytes: &[u8]) -> Result<(), ArtifactError> {
    const APPLE_PLIST_DOCTYPE: &[u8] = br#"plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd""#;
    const CRITICAL: [&str; 5] = [
        "CFBundleIdentifier",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "CFBundleExecutable",
        "SUPublicEDKey",
    ];
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_comments = true;
    let mut depth = 0_usize;
    let mut active_key = None::<(usize, String)>;
    let mut counts = [0_u8; CRITICAL.len()];
    let mut saw_doctype = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| ArtifactError::Bundle(format!("invalid Info.plist XML: {error}")))?;
        match event {
            Event::Start(start) => {
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| ArtifactError::Bundle("plist depth overflowed".to_owned()))?;
                if depth > 64 {
                    return Err(ArtifactError::Bundle(
                        "Info.plist nesting exceeds configured depth".to_owned(),
                    ));
                }
                if start.name().as_ref() == b"key" {
                    if active_key.is_some() {
                        return Err(ArtifactError::Bundle("nested plist key element".to_owned()));
                    }
                    active_key = Some((depth, String::new()));
                }
            }
            Event::Text(text) => {
                if let Some((_, value)) = active_key.as_mut() {
                    let decoded = text.xml10_content().map_err(|error| {
                        ArtifactError::Bundle(format!("invalid plist key text: {error}"))
                    })?;
                    value.push_str(&decoded);
                    if value.len() > MAX_PATH_COMPONENT_BYTES {
                        return Err(ArtifactError::Bundle(
                            "plist key exceeds configured size".to_owned(),
                        ));
                    }
                }
            }
            Event::End(end) => {
                if end.name().as_ref() == b"key" {
                    let (key_depth, value) = active_key.take().ok_or_else(|| {
                        ArtifactError::Bundle("plist key end without start".to_owned())
                    })?;
                    if key_depth != depth {
                        return Err(ArtifactError::Bundle(
                            "nested markup inside plist key".to_owned(),
                        ));
                    }
                    if let Some(index) = CRITICAL.iter().position(|key| *key == value) {
                        counts[index] = counts[index].saturating_add(1);
                        if counts[index] > 1 {
                            return Err(ArtifactError::Bundle(format!(
                                "duplicate critical plist key {value:?}"
                            )));
                        }
                    }
                } else if active_key.is_some() {
                    return Err(ArtifactError::Bundle(
                        "nested markup inside plist key".to_owned(),
                    ));
                }
                depth = depth.checked_sub(1).ok_or_else(|| {
                    ArtifactError::Bundle("unexpected plist closing element".to_owned())
                })?;
            }
            Event::Empty(empty) => {
                if active_key.is_some() || empty.name().as_ref() == b"key" {
                    return Err(ArtifactError::Bundle(
                        "empty or nested markup inside plist key".to_owned(),
                    ));
                }
            }
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Eof => break,
            Event::DocType(doctype) => {
                if saw_doctype || depth != 0 || doctype.as_ref() != APPLE_PLIST_DOCTYPE {
                    return Err(ArtifactError::Bundle(
                        "only one exact Apple plist document type is accepted".to_owned(),
                    ));
                }
                saw_doctype = true;
            }
            Event::PI(_) => {
                return Err(ArtifactError::Bundle(
                    "Info.plist processing instructions are forbidden".to_owned(),
                ));
            }
            Event::CData(_) | Event::GeneralRef(_) => {
                return Err(ArtifactError::Bundle(
                    "Info.plist CDATA and entity references are forbidden".to_owned(),
                ));
            }
        }
    }
    if depth != 0 || active_key.is_some() {
        return Err(ArtifactError::Bundle("truncated Info.plist XML".to_owned()));
    }
    Ok(())
}

#[derive(Debug)]
enum PlistCapture {
    RootKey {
        depth: usize,
        text: String,
    },
    CriticalString {
        depth: usize,
        key: String,
        text: String,
    },
}

fn parse_root_plist_strings(bytes: &[u8]) -> Result<BTreeMap<String, String>, ArtifactError> {
    const CRITICAL: [&str; 5] = [
        "CFBundleIdentifier",
        "CFBundleShortVersionString",
        "CFBundleVersion",
        "CFBundleExecutable",
        "SUPublicEDKey",
    ];
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_comments = true;
    let mut stack = Vec::<Vec<u8>>::new();
    let mut capture = None::<PlistCapture>;
    let mut pending_root_key = None::<String>;
    let mut values = BTreeMap::<String, String>::new();
    let mut saw_plist = false;
    let mut saw_root_dictionary = false;
    let mut finished_root_dictionary = false;

    loop {
        let event = reader
            .read_event()
            .map_err(|error| ArtifactError::Bundle(format!("invalid Info.plist XML: {error}")))?;
        match event {
            Event::Start(start) => {
                let name = start.name().as_ref().to_vec();
                validate_plist_element(&name)?;
                validate_plist_attributes(&start, stack.is_empty() && name == b"plist")?;
                if capture.is_some() {
                    return Err(ArtifactError::Bundle(
                        "nested markup inside critical plist text".to_owned(),
                    ));
                }
                match stack.as_slice() {
                    [] => {
                        if name != b"plist" || saw_plist {
                            return Err(ArtifactError::Bundle(
                                "Info.plist must have one plist root".to_owned(),
                            ));
                        }
                        saw_plist = true;
                    }
                    [plist] if plist == b"plist" => {
                        if name != b"dict" || saw_root_dictionary || finished_root_dictionary {
                            return Err(ArtifactError::Bundle(
                                "Info.plist root value must be one dictionary".to_owned(),
                            ));
                        }
                        saw_root_dictionary = true;
                    }
                    [plist, dictionary] if plist == b"plist" && dictionary == b"dict" => {
                        if name == b"key" {
                            if pending_root_key.is_some() {
                                return Err(ArtifactError::Bundle(
                                    "root plist dictionary key has no value".to_owned(),
                                ));
                            }
                            capture = Some(PlistCapture::RootKey {
                                depth: stack.len() + 1,
                                text: String::new(),
                            });
                        } else {
                            let key = pending_root_key.as_ref().ok_or_else(|| {
                                ArtifactError::Bundle(
                                    "root plist dictionary value has no key".to_owned(),
                                )
                            })?;
                            if CRITICAL.contains(&key.as_str()) {
                                if name != b"string" {
                                    return Err(ArtifactError::Bundle(format!(
                                        "critical plist key {key:?} is not a string"
                                    )));
                                }
                                capture = Some(PlistCapture::CriticalString {
                                    depth: stack.len() + 1,
                                    key: key.clone(),
                                    text: String::new(),
                                });
                            }
                        }
                    }
                    _ => {}
                }
                stack.push(name);
                if stack.len() > 64 {
                    return Err(ArtifactError::Bundle(
                        "Info.plist nesting exceeds configured depth".to_owned(),
                    ));
                }
            }
            Event::Text(text) => {
                let decoded = text.xml10_content().map_err(|error| {
                    ArtifactError::Bundle(format!("invalid plist text: {error}"))
                })?;
                if let Some(capture) = capture.as_mut() {
                    let output = match capture {
                        PlistCapture::RootKey { text, .. }
                        | PlistCapture::CriticalString { text, .. } => text,
                    };
                    output.push_str(&decoded);
                    if output.len() > 512 {
                        return Err(ArtifactError::Bundle(
                            "critical plist text exceeds configured size".to_owned(),
                        ));
                    }
                } else if stack
                    .last()
                    .is_some_and(|name| matches!(name.as_slice(), b"plist" | b"dict" | b"array"))
                    && !decoded.trim().is_empty()
                {
                    return Err(ArtifactError::Bundle(
                        "non-whitespace text appears inside a plist container".to_owned(),
                    ));
                }
            }
            Event::End(end) => {
                let name = end.name().as_ref().to_vec();
                if stack.last().map(Vec::as_slice) != Some(name.as_slice()) {
                    return Err(ArtifactError::Bundle(
                        "mismatched Info.plist closing element".to_owned(),
                    ));
                }
                if let Some(active) = capture.take() {
                    match active {
                        PlistCapture::RootKey { depth, text }
                            if depth == stack.len() && name == b"key" =>
                        {
                            if text.is_empty() || text.len() > MAX_PATH_COMPONENT_BYTES {
                                return Err(ArtifactError::Bundle(
                                    "root plist key violates size bounds".to_owned(),
                                ));
                            }
                            pending_root_key = Some(text);
                        }
                        PlistCapture::CriticalString { depth, key, text }
                            if depth == stack.len() && name == b"string" =>
                        {
                            if values.insert(key, text).is_some() {
                                return Err(ArtifactError::Bundle(
                                    "duplicate critical root plist value".to_owned(),
                                ));
                            }
                        }
                        _ => {
                            return Err(ArtifactError::Bundle(
                                "critical plist text closed at the wrong depth".to_owned(),
                            ));
                        }
                    }
                }
                if stack.len() == 3
                    && stack[0] == b"plist"
                    && stack[1] == b"dict"
                    && name != b"key"
                    && pending_root_key.take().is_none()
                {
                    return Err(ArtifactError::Bundle(
                        "root plist dictionary value has no key".to_owned(),
                    ));
                }
                if stack.len() == 2 && name == b"dict" {
                    if pending_root_key.is_some() {
                        return Err(ArtifactError::Bundle(
                            "root plist dictionary ends after a key".to_owned(),
                        ));
                    }
                    finished_root_dictionary = true;
                }
                stack.pop();
            }
            Event::Empty(empty) => {
                let name = empty.name().as_ref().to_vec();
                validate_plist_element(&name)?;
                validate_plist_attributes(&empty, false)?;
                if capture.is_some() || name == b"key" {
                    return Err(ArtifactError::Bundle(
                        "empty or nested markup inside critical plist text".to_owned(),
                    ));
                }
                match stack.as_slice() {
                    [plist] if plist == b"plist" => {
                        if name != b"dict" || saw_root_dictionary || finished_root_dictionary {
                            return Err(ArtifactError::Bundle(
                                "Info.plist root value must be one dictionary".to_owned(),
                            ));
                        }
                        saw_root_dictionary = true;
                        finished_root_dictionary = true;
                    }
                    [plist, dictionary] if plist == b"plist" && dictionary == b"dict" => {
                        let key = pending_root_key.take().ok_or_else(|| {
                            ArtifactError::Bundle(
                                "root plist dictionary value has no key".to_owned(),
                            )
                        })?;
                        if CRITICAL.contains(&key.as_str()) {
                            if name != b"string" {
                                return Err(ArtifactError::Bundle(format!(
                                    "critical plist key {key:?} is not a string"
                                )));
                            }
                            values.insert(key, String::new());
                        }
                    }
                    [] => {
                        return Err(ArtifactError::Bundle(
                            "Info.plist must have a non-empty plist root".to_owned(),
                        ));
                    }
                    _ => {}
                }
            }
            Event::Decl(_) | Event::Comment(_) => {}
            Event::DocType(_) => {}
            Event::PI(_) => {
                return Err(ArtifactError::Bundle(
                    "Info.plist processing instructions are forbidden".to_owned(),
                ));
            }
            Event::CData(_) | Event::GeneralRef(_) => {
                return Err(ArtifactError::Bundle(
                    "Info.plist CDATA and entity references are forbidden".to_owned(),
                ));
            }
            Event::Eof => break,
        }
    }
    if !saw_plist
        || !saw_root_dictionary
        || !finished_root_dictionary
        || !stack.is_empty()
        || capture.is_some()
        || pending_root_key.is_some()
    {
        return Err(ArtifactError::Bundle(
            "truncated or structurally invalid Info.plist XML".to_owned(),
        ));
    }
    Ok(values)
}

fn validate_plist_element(name: &[u8]) -> Result<(), ArtifactError> {
    if !matches!(
        name,
        b"plist"
            | b"dict"
            | b"array"
            | b"key"
            | b"string"
            | b"data"
            | b"date"
            | b"integer"
            | b"real"
            | b"true"
            | b"false"
    ) {
        return Err(ArtifactError::Bundle(
            "Info.plist contains an unsupported element".to_owned(),
        ));
    }
    Ok(())
}

fn validate_plist_attributes(
    start: &quick_xml::events::BytesStart<'_>,
    is_plist_root: bool,
) -> Result<(), ArtifactError> {
    let attributes = start
        .attributes()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ArtifactError::Bundle(format!("invalid plist attribute: {error}")))?;
    if is_plist_root {
        if attributes.len() != 1
            || attributes[0].key.as_ref() != b"version"
            || attributes[0].value.as_ref() != b"1.0"
        {
            return Err(ArtifactError::Bundle(
                "plist root must declare exactly version 1.0".to_owned(),
            ));
        }
    } else if !attributes.is_empty() {
        return Err(ArtifactError::Bundle(
            "non-root plist elements must not have attributes".to_owned(),
        ));
    }
    Ok(())
}

fn required_plist_string(
    dictionary: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, ArtifactError> {
    let value = dictionary
        .get(key)
        .ok_or_else(|| ArtifactError::Bundle(format!("missing string plist key {key:?}")))?;
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return Err(ArtifactError::Bundle(format!(
            "plist string {key:?} violates ASCII or size bounds"
        )));
    }
    Ok(value.to_owned())
}

fn validate_flat_component(value: &str, label: &str) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > MAX_PATH_COMPONENT_BYTES
        || value == "."
        || value == ".."
        || !value.bytes().all(|byte| {
            (0x21..=0x7e).contains(&byte) && byte != b'/' && byte != b'\\' && byte != b':'
        })
    {
        return Err(ArtifactError::Bundle(format!(
            "{label} is not a safe flat ASCII filename"
        )));
    }
    Ok(())
}

fn validate_version(value: &str, label: &str) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('.')
        || value.ends_with('.')
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(ArtifactError::Envelope(format!(
            "{label} is not a bounded dotted numeric version"
        )));
    }
    Ok(())
}

fn validate_build(value: &str, label: &str) -> Result<(), ArtifactError> {
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArtifactError::Envelope(format!(
            "{label} is not a bounded numeric build"
        )));
    }
    Ok(())
}

fn decode_canonical<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], ArtifactError> {
    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| ArtifactError::Trust(format!("{label} is not valid base64")))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| ArtifactError::Trust(format!("{label} has the wrong decoded length")))?;
    if BASE64_STANDARD.encode(decoded) != encoded {
        return Err(ArtifactError::Trust(format!(
            "{label} is not canonical standard base64"
        )));
    }
    Ok(decoded)
}

fn require_signature(
    bytes: &[u8],
    offset: usize,
    signature: &[u8; 4],
    label: &str,
) -> Result<(), ArtifactError> {
    if bytes.get(offset..offset.saturating_add(4)) != Some(signature) {
        return Err(ArtifactError::Zip(format!(
            "missing {label} signature at offset {offset}"
        )));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ArtifactError> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| ArtifactError::Zip("truncated 16-bit ZIP field".to_owned()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ArtifactError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| ArtifactError::Zip("truncated 32-bit ZIP field".to_owned()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, ArtifactError> {
    left.checked_add(right)
        .ok_or_else(|| ArtifactError::Zip(format!("{label} offset overflowed")))
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
