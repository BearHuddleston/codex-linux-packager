//! Authenticated, no-replace extraction of integrity-verified packed ASAR files.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, Timespec, Timestamps, fchmod, fstat, fsync,
    futimens, mkdirat, open, openat, renameat_with, statat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::archive::ArtifactTrust;
use crate::asar::AsarStorage;
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::staging::{StagingError, validate_stage, validate_stage_with_trust};

const FILES_DIRECTORY: &str = "files";
const MANIFEST_NAME: &str = "manifest.json";

/// One ASAR file and its extraction disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionEntry {
    /// Safe path relative to the ASAR root.
    pub path: String,
    /// `extracted_packed` or `omitted_unpacked`.
    pub disposition: String,
    /// Declared and, for packed files, verified SHA-256.
    pub sha256: String,
    /// Exact declared bytes.
    pub bytes: u64,
    /// Committed mode for an extracted file; absent when omitted.
    pub mode: Option<String>,
}

/// Deterministic complete manifest for one ASAR extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// SHA-256 of the authenticated complete source archive.
    pub source_archive_sha256: String,
    /// SHA-256 of the authenticated ASAR.
    pub app_asar_sha256: String,
    /// Reconciled application version.
    pub version: String,
    /// Reconciled application build.
    pub build: String,
    /// Complete lexical file inventory.
    pub entries: Vec<ExtractionEntry>,
}

/// Stage validation, extraction, or publication failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExtractionError {
    /// The staged input failed independent validation.
    #[error(transparent)]
    Stage(#[from] StagingError),
    /// Private extraction construction failed.
    #[error("ASAR extraction transaction failed: {0}")]
    Transaction(String),
    /// No-replace publication failed before the commit boundary.
    #[error("ASAR extraction publication failed before commit: {0}")]
    Publication(String),
    /// The name was committed but parent-directory durability is uncertain.
    #[error("ASAR extraction was committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

/// Validates a production stage and publishes its packed ASAR contents.
pub fn extract_stage(stage: &Path, output: &Path) -> Result<ExtractionManifest, ExtractionError> {
    let validated = validate_stage(stage)?;
    extract_validated_stage(validated, output)
}

/// Testable extraction form with an explicitly supplied independent trust root.
pub fn extract_stage_with_trust(
    stage: &Path,
    output: &Path,
    trust: &ArtifactTrust,
) -> Result<ExtractionManifest, ExtractionError> {
    let validated = validate_stage_with_trust(stage, trust)?;
    extract_validated_stage(validated, output)
}

fn extract_validated_stage(
    validated: crate::staging::ValidatedStage,
    output: &Path,
) -> Result<ExtractionManifest, ExtractionError> {
    let entries = validated
        .asar
        .entries
        .iter()
        .map(|entry| ExtractionEntry {
            path: entry.path.clone(),
            disposition: match entry.storage {
                AsarStorage::Packed => "extracted_packed",
                AsarStorage::Unpacked => "omitted_unpacked",
            }
            .to_owned(),
            sha256: entry.sha256.clone(),
            bytes: entry.bytes,
            mode: match entry.storage {
                AsarStorage::Packed if entry.executable => Some("0755".to_owned()),
                AsarStorage::Packed => Some("0644".to_owned()),
                AsarStorage::Unpacked => None,
            },
        })
        .collect();
    let source_file = validated
        .provenance
        .files
        .iter()
        .find(|file| file.path == "source.zip")
        .ok_or_else(|| {
            ExtractionError::Transaction(
                "validated stage lost its source archive identity".to_owned(),
            )
        })?;
    let manifest = ExtractionManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "asar_extraction".to_owned(),
        source_archive_sha256: source_file.sha256.clone(),
        app_asar_sha256: validated.asar.inspection.asar_sha256.clone(),
        version: validated.provenance.bundle.version.clone(),
        build: validated.provenance.bundle.build.clone(),
        entries,
    };
    let manifest_bytes =
        to_json_line(&manifest).map_err(|error| ExtractionError::Transaction(error.to_string()))?;

    let mut publisher = TreePublisher::new(output)?;
    let build = (|| -> Result<(), ExtractionError> {
        let _ = publisher.ensure_directory(FILES_DIRECTORY)?;
        for entry in &validated.asar.entries {
            if entry.storage != AsarStorage::Packed {
                continue;
            }
            let offset = entry.offset.ok_or_else(|| {
                ExtractionError::Transaction(format!(
                    "packed ASAR entry {:?} lost its offset",
                    entry.path
                ))
            })?;
            let relative = usize::try_from(offset).map_err(|_| {
                ExtractionError::Transaction(format!(
                    "packed offset does not fit for {:?}",
                    entry.path
                ))
            })?;
            let start = validated
                .asar
                .data_offset
                .checked_add(relative)
                .ok_or_else(|| {
                    ExtractionError::Transaction("packed start offset overflowed".to_owned())
                })?;
            let size = usize::try_from(entry.bytes).map_err(|_| {
                ExtractionError::Transaction(format!(
                    "packed size does not fit for {:?}",
                    entry.path
                ))
            })?;
            let end = start.checked_add(size).ok_or_else(|| {
                ExtractionError::Transaction("packed end offset overflowed".to_owned())
            })?;
            let bytes = validated.app_asar.get(start..end).ok_or_else(|| {
                ExtractionError::Transaction(format!(
                    "verified packed range disappeared for {:?}",
                    entry.path
                ))
            })?;
            let relative_path = format!("{FILES_DIRECTORY}/{}", entry.path);
            publisher.write_file(
                &relative_path,
                bytes,
                if entry.executable { 0o755 } else { 0o644 },
            )?;
        }
        publisher.write_file(MANIFEST_NAME, manifest_bytes.as_bytes(), 0o644)?;
        Ok(())
    })();
    if let Err(error) = build {
        return Err(publisher.abort(error));
    }
    if let Err(error) = publisher.commit() {
        return Err(publisher.abort(error));
    }
    Ok(manifest)
}

#[derive(Debug)]
struct DirectoryRecord {
    parent: Option<usize>,
    name: OsString,
    descriptor: OwnedFd,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
struct FileRecord {
    parent: usize,
    name: OsString,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct TreePublisher {
    parent: OwnedFd,
    final_name: OsString,
    temporary_name: OsString,
    directories: Vec<DirectoryRecord>,
    directory_paths: BTreeMap<String, usize>,
    files: Vec<FileRecord>,
    committed: bool,
}

impl TreePublisher {
    pub(crate) fn new(output: &Path) -> Result<Self, ExtractionError> {
        let parent_path = output.parent().filter(|path| !path.as_os_str().is_empty());
        let parent_path = parent_path.unwrap_or_else(|| Path::new("."));
        let final_name = output
            .file_name()
            .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
            .ok_or_else(|| {
                ExtractionError::Transaction(
                    "output must name one non-dot extraction directory".to_owned(),
                )
            })?
            .to_owned();
        let parent = open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            ExtractionError::Transaction(format!("open output parent without symlink: {error}"))
        })?;
        let (temporary_name, root) = create_private_root(&parent)?;
        let metadata = fstat(&root).map_err(|error| {
            ExtractionError::Transaction(format!("inspect private extraction root: {error}"))
        })?;
        let directories = vec![DirectoryRecord {
            parent: None,
            name: temporary_name.clone(),
            descriptor: root,
            device: metadata.st_dev,
            inode: metadata.st_ino,
        }];
        let mut directory_paths = BTreeMap::new();
        directory_paths.insert(String::new(), 0);
        Ok(Self {
            parent,
            final_name,
            temporary_name,
            directories,
            directory_paths,
            files: Vec::new(),
            committed: false,
        })
    }

    fn ensure_directory(&mut self, path: &str) -> Result<usize, ExtractionError> {
        if path.is_empty() {
            return Ok(0);
        }
        let mut parent = 0_usize;
        let mut accumulated = String::new();
        for component in path.split('/') {
            if !accumulated.is_empty() {
                accumulated.push('/');
            }
            accumulated.push_str(component);
            if let Some(index) = self.directory_paths.get(&accumulated) {
                parent = *index;
                continue;
            }
            let descriptor = mkdir_open(&self.directories[parent].descriptor, component)?;
            let metadata = fstat(&descriptor).map_err(|error| {
                ExtractionError::Transaction(format!(
                    "inspect created directory {accumulated:?}: {error}"
                ))
            })?;
            let index = self.directories.len();
            self.directories.push(DirectoryRecord {
                parent: Some(parent),
                name: OsString::from(component),
                descriptor,
                device: metadata.st_dev,
                inode: metadata.st_ino,
            });
            self.directory_paths.insert(accumulated.clone(), index);
            parent = index;
        }
        Ok(parent)
    }

    pub(crate) fn write_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<(), ExtractionError> {
        let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = self.ensure_directory(parent_path)?;
        let descriptor = openat(
            &self.directories[parent].descriptor,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(mode),
        )
        .map_err(|error| {
            ExtractionError::Transaction(format!("create extracted file {path:?}: {error}"))
        })?;
        let metadata = fstat(&descriptor).map_err(|error| {
            ExtractionError::Transaction(format!("inspect extracted file {path:?}: {error}"))
        })?;
        self.files.push(FileRecord {
            parent,
            name: OsString::from(name),
            device: metadata.st_dev,
            inode: metadata.st_ino,
        });
        fchmod(&descriptor, Mode::from_raw_mode(mode)).map_err(|error| {
            ExtractionError::Transaction(format!("set mode on extracted file {path:?}: {error}"))
        })?;
        let mut file = File::from(descriptor);
        file.write_all(bytes).map_err(|error| {
            ExtractionError::Transaction(format!("write extracted file {path:?}: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            ExtractionError::Transaction(format!("fsync extracted file {path:?}: {error}"))
        })
    }

    pub(crate) fn normalize_timestamps(
        &self,
        source_date_epoch: i64,
    ) -> Result<(), ExtractionError> {
        if !(315_532_800..=4_102_444_800).contains(&source_date_epoch) {
            return Err(ExtractionError::Transaction(
                "SOURCE_DATE_EPOCH must be within 1980-01-01..=2100-01-01".to_owned(),
            ));
        }
        let timestamp = Timespec {
            tv_sec: source_date_epoch,
            tv_nsec: 0,
        };
        let timestamps = Timestamps {
            last_access: timestamp,
            last_modification: timestamp,
        };
        for file in &self.files {
            let parent = &self.directories[file.parent].descriptor;
            let descriptor = openat(
                parent,
                &file.name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                ExtractionError::Transaction(format!(
                    "open created file for timestamp normalization: {error}"
                ))
            })?;
            let metadata = fstat(&descriptor).map_err(|error| {
                ExtractionError::Transaction(format!(
                    "inspect created file for timestamp normalization: {error}"
                ))
            })?;
            if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
                || metadata.st_dev != file.device
                || metadata.st_ino != file.inode
            {
                return Err(ExtractionError::Transaction(
                    "refused to timestamp a substituted created file".to_owned(),
                ));
            }
            futimens(&descriptor, &timestamps).map_err(|error| {
                ExtractionError::Transaction(format!("normalize created file timestamp: {error}"))
            })?;
        }
        for directory in self.directories.iter().rev() {
            futimens(&directory.descriptor, &timestamps).map_err(|error| {
                ExtractionError::Transaction(format!(
                    "normalize created directory timestamp: {error}"
                ))
            })?;
        }
        Ok(())
    }

    pub(crate) fn commit(&mut self) -> Result<(), ExtractionError> {
        fchmod(&self.directories[0].descriptor, Mode::from_raw_mode(0o755)).map_err(|error| {
            ExtractionError::Transaction(format!("set extraction root mode: {error}"))
        })?;
        for directory in self.directories.iter().rev() {
            fsync(&directory.descriptor).map_err(|error| {
                ExtractionError::Transaction(format!("fsync extraction directory: {error}"))
            })?;
        }
        renameat_with(
            &self.parent,
            &self.temporary_name,
            &self.parent,
            &self.final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            ExtractionError::Publication(format!("commit output with no replacement: {error}"))
        })?;
        self.committed = true;
        fsync(&self.parent)
            .map_err(|error| ExtractionError::PostCommitDurability(error.to_string()))
    }

    fn abort(&mut self, original: ExtractionError) -> ExtractionError {
        if self.committed {
            return original;
        }
        match self.cleanup() {
            Ok(()) => original,
            Err(cleanup) => ExtractionError::Transaction(format!(
                "{original}; private extraction cleanup was intentionally incomplete: {cleanup}"
            )),
        }
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), String> {
        for file in self.files.iter().rev() {
            let parent = &self.directories[file.parent].descriptor;
            let current = statat(parent, &file.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| format!("inspect created file before cleanup: {error}"))?;
            if FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
                || current.st_dev != file.device
                || current.st_ino != file.inode
            {
                return Err("refused to unlink a substituted extracted file".to_owned());
            }
            unlinkat(parent, &file.name, AtFlags::empty())
                .map_err(|error| format!("unlink created extracted file: {error}"))?;
        }
        for index in (1..self.directories.len()).rev() {
            let directory = &self.directories[index];
            let parent_index = directory
                .parent
                .ok_or_else(|| "non-root directory lost its parent".to_owned())?;
            let parent = &self.directories[parent_index].descriptor;
            let current = statat(parent, &directory.name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| format!("inspect created directory before cleanup: {error}"))?;
            if FileType::from_raw_mode(current.st_mode) != FileType::Directory
                || current.st_dev != directory.device
                || current.st_ino != directory.inode
            {
                return Err("refused to remove a substituted extracted directory".to_owned());
            }
            unlinkat(parent, &directory.name, AtFlags::REMOVEDIR)
                .map_err(|error| format!("remove created extracted directory: {error}"))?;
        }
        let root = &self.directories[0];
        let current = statat(
            &self.parent,
            &self.temporary_name,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| format!("inspect extraction root before cleanup: {error}"))?;
        if FileType::from_raw_mode(current.st_mode) != FileType::Directory
            || current.st_dev != root.device
            || current.st_ino != root.inode
        {
            return Err("refused to remove a substituted extraction root".to_owned());
        }
        unlinkat(&self.parent, &self.temporary_name, AtFlags::REMOVEDIR)
            .map_err(|error| format!("remove created extraction root: {error}"))
    }
}

fn create_private_root(parent: &OwnedFd) -> Result<(OsString, OwnedFd), ExtractionError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom(&mut random, GetRandomFlags::empty()).map_err(|error| {
            ExtractionError::Transaction(format!("obtain extraction entropy: {error}"))
        })?;
        let name = OsString::from(format!(
            ".codex-linux-packager-extract-{}",
            hex_lower(&random)
        ));
        match mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                let descriptor = openat(
                    parent,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| {
                    ExtractionError::Transaction(format!(
                        "open newly created extraction root: {error}"
                    ))
                })?;
                return Ok((name, descriptor));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(ExtractionError::Transaction(format!(
                    "create private extraction root: {error}"
                )));
            }
        }
    }
    Err(ExtractionError::Transaction(
        "could not allocate a unique extraction root".to_owned(),
    ))
}

fn mkdir_open(parent: &OwnedFd, name: &str) -> Result<OwnedFd, ExtractionError> {
    mkdirat(parent, name, Mode::from_raw_mode(0o755)).map_err(|error| {
        ExtractionError::Transaction(format!("create extracted directory {name:?}: {error}"))
    })?;
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ExtractionError::Transaction(format!("open extracted directory {name:?}: {error}"))
    })?;
    fchmod(&descriptor, Mode::from_raw_mode(0o755)).map_err(|error| {
        ExtractionError::Transaction(format!("set mode on extracted directory {name:?}: {error}"))
    })?;
    Ok(descriptor)
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
