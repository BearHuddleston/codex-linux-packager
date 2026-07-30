//! No-replace publication of the narrow authenticated staging generation.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, fchmod, fstat, fsync, mkdirat, open,
    openat, renameat_with, statat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::archive::{
    ArtifactContract, ArtifactError, ArtifactTrust, MAX_ARTIFACT_BYTES, authenticate_artifact_file,
    inspect_artifact_payload,
};
use crate::asar::{
    AsarError, AsarIndex, AsarInspection, MAX_ASAR_BYTES, index_asar_bytes, inspect_asar_bytes,
};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};

const SOURCE_ARCHIVE_NAME: &str = "source.zip";
const APP_ASAR_NAME: &str = "app.asar";
const PROVENANCE_NAME: &str = "provenance.json";
const MAX_PROVENANCE_BYTES: u64 = 1024 * 1024;
const PUBLICATION_SCOPE: &str = "bytes_at_durable_commit_boundary_under_documented_threat_model";

/// Exact contract copied into artifact-stage provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedContract {
    /// Exact source archive length.
    pub expected_length: u64,
    /// Canonical Sparkle signature over the complete source archive.
    pub signature_base64: String,
    /// Reconciled short version.
    pub version: String,
    /// Reconciled build version.
    pub build: String,
}

/// One committed staged file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFile {
    /// Fixed relative generation path.
    pub path: String,
    /// Narrow reason this file is retained.
    pub purpose: String,
    /// SHA-256 in lowercase hexadecimal.
    pub sha256: String,
    /// Exact byte count.
    pub bytes: u64,
    /// Exact committed Unix permission bits.
    pub mode: String,
}

/// Reconciled bundle identity stored independently of mutable source paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedBundle {
    /// Canonical top-level `.app` root in the source ZIP.
    pub root: String,
    /// Exact bundle identifier.
    pub identifier: String,
    /// Exact bundle version.
    pub version: String,
    /// Exact bundle build.
    pub build: String,
    /// Declared executable basename.
    pub executable: String,
    /// Independently pinned key fingerprint.
    pub sparkle_public_key_sha256: String,
}

/// Resource and integrity facts established for the staged `app.asar`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedAsar {
    /// SHA-256 of the complete ASAR.
    pub sha256: String,
    /// Exact ASAR byte count.
    pub bytes: u64,
    /// Exact unpadded JSON header byte count.
    pub header_json_bytes: u64,
    /// Packed data-region byte count.
    pub packed_data_bytes: u64,
    /// Declared directory count.
    pub directory_count: u64,
    /// Integrity-verified packed file count.
    pub packed_file_count: u64,
    /// External unpacked file count.
    pub unpacked_file_count: u64,
    /// Declared executable entry count.
    pub executable_file_count: u64,
    /// Aggregate bytes declared outside the ASAR.
    pub unpacked_declared_bytes: u64,
}

/// Deterministic schema-1 provenance for one private staging generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageProvenance {
    /// Rust-owned schema; only exactly 1 is accepted.
    pub schema: u32,
    /// Unambiguous Rust producer identifier.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Truthful scope of the publication guarantee.
    pub publication_scope: String,
    /// Feed-derived contract authenticated against the bundle.
    pub contract: StagedContract,
    /// Exact bundle metadata.
    pub bundle: StagedBundle,
    /// Strict ASAR framing, inventory, and packed-integrity summary.
    pub asar: StagedAsar,
    /// Complete narrow staged-file inventory, sorted by path.
    pub files: Vec<StagedFile>,
}

/// Authenticated stage contents ready for the next phase.
#[derive(Debug)]
pub struct ValidatedStage {
    /// Strict schema-1 provenance exactly reproduced from authenticated inputs.
    pub provenance: StageProvenance,
    /// Exact complete authenticated source archive.
    pub source_archive: Vec<u8>,
    /// Exact staged `app.asar`.
    pub app_asar: Vec<u8>,
    /// Complete validated ASAR index.
    pub asar: AsarIndex,
}

/// Artifact staging or publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StagingError {
    /// Source authentication or archive inspection failed.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// Authenticated `app.asar` framing or packed integrity is invalid.
    #[error(transparent)]
    Asar(#[from] AsarError),
    /// Persisted stage structure or provenance is invalid.
    #[error("invalid staged generation: {0}")]
    Validation(String),
    /// Output path or private generation construction failed.
    #[error("staging transaction failed: {0}")]
    Transaction(String),
    /// The no-replace commit boundary was not reached.
    #[error("staging publication failed before commit: {0}")]
    Publication(String),
    /// The name was committed, but durable-directory confirmation failed.
    #[error("staging name was committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

#[derive(Debug)]
struct CreatedIdentity {
    name: &'static str,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

/// Authenticates one source artifact, writes exactly three fixed generation
/// files, fsyncs them, and publishes the generation with `RENAME_NOREPLACE`.
pub fn stage_artifact_file(
    artifact_path: &Path,
    output: &Path,
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<StageProvenance, StagingError> {
    let authenticated = authenticate_artifact_file(artifact_path, contract, trust)?;
    let asar = inspect_asar_bytes(&authenticated.app_asar)?;
    let provenance = provenance_for(contract, &authenticated.inspection, &asar);
    let provenance_bytes =
        to_json_line(&provenance).map_err(|error| StagingError::Transaction(error.to_string()))?;

    let parent_path = output.parent().filter(|path| !path.as_os_str().is_empty());
    let parent_path = parent_path.unwrap_or_else(|| Path::new("."));
    let final_name = output.file_name().ok_or_else(|| {
        StagingError::Transaction("output must name one generation directory".to_owned())
    })?;
    if final_name == OsStr::new(".") || final_name == OsStr::new("..") {
        return Err(StagingError::Transaction(
            "output generation name cannot be dot or dot-dot".to_owned(),
        ));
    }
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        StagingError::Transaction(format!("open output parent without symlink: {error}"))
    })?;
    let (temporary_name, generation) = create_private_generation(&parent)?;
    fchmod(&generation, Mode::from_raw_mode(0o700))
        .map_err(|error| transaction_failure(&parent, &temporary_name, &generation, &[], error))?;
    let directory_stat = fstat(&generation)
        .map_err(|error| transaction_failure(&parent, &temporary_name, &generation, &[], error))?;
    let directory_identity = DirectoryIdentity {
        device: directory_stat.st_dev,
        inode: directory_stat.st_ino,
    };
    let mut created = Vec::<CreatedIdentity>::new();

    let preparation = (|| -> Result<(), StagingError> {
        write_generation_file(
            &generation,
            SOURCE_ARCHIVE_NAME,
            &authenticated.source_archive,
            &mut created,
        )?;
        write_generation_file(
            &generation,
            APP_ASAR_NAME,
            &authenticated.app_asar,
            &mut created,
        )?;
        write_generation_file(
            &generation,
            PROVENANCE_NAME,
            provenance_bytes.as_bytes(),
            &mut created,
        )?;
        fsync(&generation).map_err(|error| {
            StagingError::Transaction(format!("fsync private generation: {error}"))
        })
    })();
    if let Err(error) = preparation {
        return Err(with_cleanup(
            error,
            &parent,
            &temporary_name,
            &generation,
            &directory_identity,
            &created,
        ));
    }

    if let Err(error) = renameat_with(
        &parent,
        &temporary_name,
        &parent,
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        let publication =
            StagingError::Publication(format!("commit output with no replacement: {error}"));
        return Err(with_cleanup(
            publication,
            &parent,
            &temporary_name,
            &generation,
            &directory_identity,
            &created,
        ));
    }
    fsync(&parent).map_err(|error| StagingError::PostCommitDurability(error.to_string()))?;
    Ok(provenance)
}

/// Re-authenticates a staged generation using the production trust root and
/// rejects every schema other than this Rust implementation's schema 1.
pub fn validate_stage(path: &Path) -> Result<ValidatedStage, StagingError> {
    let trust = ArtifactTrust::pinned_production()?;
    validate_stage_with_trust(path, &trust)
}

/// Testable form of [`validate_stage`] with an independently supplied trust
/// root. Production callers should use [`validate_stage`].
pub fn validate_stage_with_trust(
    path: &Path,
    trust: &ArtifactTrust,
) -> Result<ValidatedStage, StagingError> {
    let generation = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| StagingError::Validation(format!("open stage without symlink: {error}")))?;
    validate_generation_inventory(&generation)?;
    let provenance_bytes =
        read_regular_file_at(&generation, PROVENANCE_NAME, MAX_PROVENANCE_BYTES)?;
    let provenance: StageProvenance = serde_json::from_slice(&provenance_bytes)
        .map_err(|error| StagingError::Validation(format!("parse provenance JSON: {error}")))?;
    validate_provenance_identity(&provenance)?;

    let source_archive =
        read_regular_file_at(&generation, SOURCE_ARCHIVE_NAME, MAX_ARTIFACT_BYTES)?;
    let app_asar = read_regular_file_at(&generation, APP_ASAR_NAME, MAX_ASAR_BYTES)?;
    let contract = ArtifactContract {
        expected_length: provenance.contract.expected_length,
        signature_base64: provenance.contract.signature_base64.clone(),
        version: provenance.contract.version.clone(),
        build: provenance.contract.build.clone(),
    };
    let authenticated = inspect_artifact_payload(&source_archive, &contract, trust)?;
    if authenticated.app_asar != app_asar {
        return Err(StagingError::Validation(
            "staged app.asar differs from the authenticated source member".to_owned(),
        ));
    }
    let asar = index_asar_bytes(&app_asar)?;
    let expected = provenance_for(&contract, &authenticated.inspection, &asar.inspection);
    if provenance != expected {
        return Err(StagingError::Validation(
            "provenance does not exactly describe authenticated staged bytes".to_owned(),
        ));
    }
    Ok(ValidatedStage {
        provenance,
        source_archive,
        app_asar,
        asar,
    })
}

fn validate_generation_inventory(generation: &OwnedFd) -> Result<(), StagingError> {
    let mut buffer = [MaybeUninit::<u8>::uninit(); 8192];
    let mut directory = RawDir::new(generation, &mut buffer);
    let mut names = Vec::<Vec<u8>>::new();
    while let Some(entry) = directory.next() {
        let entry =
            entry.map_err(|error| StagingError::Validation(format!("enumerate stage: {error}")))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    names.sort();
    let expected = [
        APP_ASAR_NAME.as_bytes().to_vec(),
        PROVENANCE_NAME.as_bytes().to_vec(),
        SOURCE_ARCHIVE_NAME.as_bytes().to_vec(),
    ];
    if names != expected {
        return Err(StagingError::Validation(
            "stage must contain exactly app.asar, provenance.json, and source.zip".to_owned(),
        ));
    }
    Ok(())
}

fn read_regular_file_at(
    generation: &OwnedFd,
    name: &'static str,
    maximum: u64,
) -> Result<Vec<u8>, StagingError> {
    let descriptor = openat(
        generation,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| StagingError::Validation(format!("open staged {name}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| StagingError::Validation(format!("inspect staged {name}: {error}")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
        return Err(StagingError::Validation(format!(
            "staged {name} is not a regular file"
        )));
    }
    if before.st_mode & 0o7777 != 0o600 {
        return Err(StagingError::Validation(format!(
            "staged {name} mode is not exactly 0600"
        )));
    }
    if before.st_size < 0 {
        return Err(StagingError::Validation(format!(
            "staged {name} has a negative size"
        )));
    }
    let size = u64::try_from(before.st_size)
        .map_err(|_| StagingError::Validation(format!("staged {name} size does not fit u64")))?;
    if size > maximum {
        return Err(StagingError::Validation(format!(
            "staged {name} exceeds {maximum} bytes"
        )));
    }
    let capacity = usize::try_from(size)
        .map_err(|_| StagingError::Validation(format!("staged {name} size does not fit usize")))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut file = File::from(descriptor);
    Read::by_ref(&mut file)
        .take(size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| StagingError::Validation(format!("read staged {name}: {error}")))?;
    if bytes.len() != capacity {
        return Err(StagingError::Validation(format!(
            "staged {name} changed size or was truncated while reading"
        )));
    }
    let after = fstat(&file)
        .map_err(|error| StagingError::Validation(format!("reinspect staged {name}: {error}")))?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(StagingError::Validation(format!(
            "staged {name} identity changed while reading"
        )));
    }
    Ok(bytes)
}

fn validate_provenance_identity(provenance: &StageProvenance) -> Result<(), StagingError> {
    if provenance.schema != SCHEMA_VERSION {
        return Err(StagingError::Validation(format!(
            "unsupported stage schema {}; expected exactly {SCHEMA_VERSION}",
            provenance.schema
        )));
    }
    if provenance.producer != PRODUCER_IDENTIFIER {
        return Err(StagingError::Validation(format!(
            "unexpected stage producer {:?}",
            provenance.producer
        )));
    }
    if provenance.kind != "artifact_stage" {
        return Err(StagingError::Validation(format!(
            "unexpected stage document kind {:?}",
            provenance.kind
        )));
    }
    if provenance.publication_scope != PUBLICATION_SCOPE {
        return Err(StagingError::Validation(
            "unexpected publication guarantee scope".to_owned(),
        ));
    }
    Ok(())
}

fn provenance_for(
    contract: &ArtifactContract,
    inspection: &crate::archive::ArtifactInspection,
    asar: &AsarInspection,
) -> StageProvenance {
    let mut files = vec![
        StagedFile {
            path: APP_ASAR_NAME.to_owned(),
            purpose: "authenticated_electron_application_archive".to_owned(),
            sha256: inspection.app_asar.sha256.clone(),
            bytes: inspection.app_asar.bytes,
            mode: "0600".to_owned(),
        },
        StagedFile {
            path: SOURCE_ARCHIVE_NAME.to_owned(),
            purpose: "exact_authenticated_source_archive".to_owned(),
            sha256: inspection.artifact.sha256.clone(),
            bytes: inspection.artifact.bytes,
            mode: "0600".to_owned(),
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    StageProvenance {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "artifact_stage".to_owned(),
        publication_scope: PUBLICATION_SCOPE.to_owned(),
        contract: StagedContract {
            expected_length: contract.expected_length,
            signature_base64: contract.signature_base64.clone(),
            version: contract.version.clone(),
            build: contract.build.clone(),
        },
        bundle: StagedBundle {
            root: inspection.bundle.root.clone(),
            identifier: inspection.bundle.identifier.clone(),
            version: inspection.bundle.version.clone(),
            build: inspection.bundle.build.clone(),
            executable: inspection.bundle.executable.clone(),
            sparkle_public_key_sha256: inspection.bundle.sparkle_public_key_sha256.clone(),
        },
        asar: StagedAsar {
            sha256: asar.asar_sha256.clone(),
            bytes: asar.asar_bytes,
            header_json_bytes: asar.header_json_bytes,
            packed_data_bytes: asar.packed_data_bytes,
            directory_count: asar.directory_count,
            packed_file_count: asar.packed_file_count,
            unpacked_file_count: asar.unpacked_file_count,
            executable_file_count: asar.executable_file_count,
            unpacked_declared_bytes: asar.unpacked_declared_bytes,
        },
        files,
    }
}

fn create_private_generation(parent: &OwnedFd) -> Result<(OsString, OwnedFd), StagingError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom(&mut random, GetRandomFlags::empty()).map_err(|error| {
            StagingError::Transaction(format!("obtain generation entropy: {error}"))
        })?;
        let name = OsString::from(format!(
            ".codex-linux-packager-stage-{}",
            hex_lower(&random)
        ));
        match mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let initial =
                    statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
                        StagingError::Transaction(format!(
                            "inspect newly created private generation: {error}"
                        ))
                    })?;
                if FileType::from_raw_mode(initial.st_mode) != FileType::Directory {
                    return Err(StagingError::Transaction(
                        "new private generation name was substituted".to_owned(),
                    ));
                }
                let descriptor = match openat(
                    parent,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ) {
                    Ok(descriptor) => descriptor,
                    Err(error) => {
                        let current = statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW);
                        let cleaned = current.is_ok_and(|current| {
                            FileType::from_raw_mode(current.st_mode) == FileType::Directory
                                && current.st_dev == initial.st_dev
                                && current.st_ino == initial.st_ino
                                && unlinkat(parent, &name, AtFlags::REMOVEDIR).is_ok()
                        });
                        return Err(StagingError::Transaction(format!(
                            "open newly created private generation: {error}; safe cleanup {}",
                            if cleaned { "succeeded" } else { "was refused" }
                        )));
                    }
                };
                let opened = fstat(&descriptor).map_err(|error| {
                    StagingError::Transaction(format!("inspect opened private generation: {error}"))
                })?;
                if opened.st_dev != initial.st_dev || opened.st_ino != initial.st_ino {
                    return Err(StagingError::Transaction(
                        "opened private generation identity differs from created name".to_owned(),
                    ));
                }
                return Ok((name, descriptor));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(StagingError::Transaction(format!(
                    "create private generation: {error}"
                )));
            }
        }
    }
    Err(StagingError::Transaction(
        "could not allocate a unique private generation name".to_owned(),
    ))
}

fn write_generation_file(
    generation: &OwnedFd,
    name: &'static str,
    bytes: &[u8],
    created: &mut Vec<CreatedIdentity>,
) -> Result<(), StagingError> {
    let descriptor = openat(
        generation,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| StagingError::Transaction(format!("create {name}: {error}")))?;
    let metadata = fstat(&descriptor)
        .map_err(|error| StagingError::Transaction(format!("inspect created {name}: {error}")))?;
    created.push(CreatedIdentity {
        name,
        device: metadata.st_dev,
        inode: metadata.st_ino,
    });
    fchmod(&descriptor, Mode::from_raw_mode(0o600))
        .map_err(|error| StagingError::Transaction(format!("set mode on {name}: {error}")))?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .map_err(|error| StagingError::Transaction(format!("write {name}: {error}")))?;
    file.sync_all()
        .map_err(|error| StagingError::Transaction(format!("fsync {name}: {error}")))
}

fn with_cleanup(
    original: StagingError,
    parent: &OwnedFd,
    temporary_name: &OsStr,
    generation: &OwnedFd,
    directory_identity: &DirectoryIdentity,
    created: &[CreatedIdentity],
) -> StagingError {
    match cleanup_generation(
        parent,
        temporary_name,
        generation,
        directory_identity,
        created,
    ) {
        Ok(()) => original,
        Err(cleanup) => StagingError::Transaction(format!(
            "{original}; private generation cleanup was intentionally incomplete: {cleanup}"
        )),
    }
}

fn cleanup_generation(
    parent: &OwnedFd,
    temporary_name: &OsStr,
    generation: &OwnedFd,
    directory_identity: &DirectoryIdentity,
    created: &[CreatedIdentity],
) -> Result<(), String> {
    for identity in created.iter().rev() {
        let current = statat(generation, identity.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| format!("inspect {} before cleanup: {error}", identity.name))?;
        if FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
            || current.st_dev != identity.device
            || current.st_ino != identity.inode
        {
            return Err(format!(
                "refused to unlink substituted staged file {}",
                identity.name
            ));
        }
        unlinkat(generation, identity.name, AtFlags::empty())
            .map_err(|error| format!("unlink owned {}: {error}", identity.name))?;
    }
    let current = statat(parent, temporary_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| format!("inspect private generation before cleanup: {error}"))?;
    if FileType::from_raw_mode(current.st_mode) != FileType::Directory
        || current.st_dev != directory_identity.device
        || current.st_ino != directory_identity.inode
    {
        return Err("refused to remove a substituted private generation".to_owned());
    }
    unlinkat(parent, temporary_name, AtFlags::REMOVEDIR)
        .map_err(|error| format!("remove owned private generation: {error}"))
}

fn transaction_failure(
    parent: &OwnedFd,
    temporary_name: &OsStr,
    generation: &OwnedFd,
    created: &[CreatedIdentity],
    error: rustix::io::Errno,
) -> StagingError {
    let metadata = fstat(generation);
    let original = StagingError::Transaction(error.to_string());
    match metadata {
        Ok(metadata) => with_cleanup(
            original,
            parent,
            temporary_name,
            generation,
            &DirectoryIdentity {
                device: metadata.st_dev,
                inode: metadata.st_ino,
            },
            created,
        ),
        Err(_) => original,
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
