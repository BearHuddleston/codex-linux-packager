//! Strict Electron ASAR header parsing and packed-content verification.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION};

/// Largest ASAR accepted from an authenticated desktop artifact.
pub const MAX_ASAR_BYTES: u64 = 384 * 1024 * 1024;
/// Largest serialized JSON header accepted.
pub const MAX_ASAR_HEADER_BYTES: usize = 16 * 1024 * 1024;
/// Largest number of directory and file entries accepted.
pub const MAX_ASAR_ENTRIES: usize = 50_000;

const MAX_ASAR_DEPTH: usize = 64;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_FILE_BYTES: u64 = 768 * 1024 * 1024;
const MAX_UNPACKED_DECLARED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const INTEGRITY_BLOCK_BYTES: u64 = 4 * 1024 * 1024;

/// Whether an ASAR file's bytes are inside the archive or externally unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsarStorage {
    /// File bytes occupy a verified slice of the packed data region.
    Packed,
    /// Header declares bytes in a separate `app.asar.unpacked` tree.
    Unpacked,
}

/// One validated ASAR file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsarEntry {
    /// Safe normalized relative path.
    pub path: String,
    /// Packed or externally unpacked storage.
    pub storage: AsarStorage,
    /// Declared file byte count.
    pub bytes: u64,
    /// Relative packed-data offset, absent for unpacked files.
    pub offset: Option<u64>,
    /// Whether Electron marks the entry executable.
    pub executable: bool,
    /// Declared SHA-256, verified for packed files.
    pub sha256: String,
}

/// Deterministic schema-1 ASAR inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsarInspection {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable document kind.
    pub kind: &'static str,
    /// SHA-256 of the complete ASAR.
    pub asar_sha256: String,
    /// Exact complete ASAR byte count.
    pub asar_bytes: u64,
    /// Exact unpadded JSON header byte count.
    pub header_json_bytes: u64,
    /// Exact packed data-region byte count.
    pub packed_data_bytes: u64,
    /// Number of declared directories, excluding the implicit root.
    pub directory_count: u64,
    /// Number of files whose bytes are inside the ASAR.
    pub packed_file_count: u64,
    /// Number of files declared in `app.asar.unpacked`.
    pub unpacked_file_count: u64,
    /// Number of entries marked executable.
    pub executable_file_count: u64,
    /// Aggregate declared external byte count.
    pub unpacked_declared_bytes: u64,
    /// True only after every packed full-file and block digest was checked.
    pub packed_integrity_verified: bool,
}

/// Parsed and integrity-checked ASAR index.
#[derive(Debug, Clone)]
pub struct AsarIndex {
    /// Deterministic summary.
    pub inspection: AsarInspection,
    /// Complete file inventory in lexical path order.
    pub entries: Vec<AsarEntry>,
    /// Byte offset at which packed file data begins.
    pub data_offset: usize,
}

/// Malformed, ambiguous, or resource-exhausting ASAR rejection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AsarError {
    /// Pickle framing or byte envelope is invalid.
    #[error("invalid ASAR envelope: {0}")]
    Envelope(String),
    /// JSON is malformed, duplicated, or outside the accepted schema.
    #[error("invalid ASAR header: {0}")]
    Header(String),
    /// File paths, ranges, or integrity metadata are invalid.
    #[error("invalid ASAR entry: {0}")]
    Entry(String),
    /// Packed bytes do not match declared integrity.
    #[error("ASAR integrity verification failed: {0}")]
    Integrity(String),
}

/// Validates framing, duplicate-free JSON, all entry paths and ranges, and
/// every packed whole-file and block SHA-256 digest.
pub fn inspect_asar_bytes(bytes: &[u8]) -> Result<AsarInspection, AsarError> {
    Ok(index_asar_bytes(bytes)?.inspection)
}

/// Returns a complete verified index for safe selective extraction.
pub fn index_asar_bytes(bytes: &[u8]) -> Result<AsarIndex, AsarError> {
    let asar_bytes = u64::try_from(bytes.len())
        .map_err(|_| AsarError::Envelope("ASAR length does not fit u64".to_owned()))?;
    if !(16..=MAX_ASAR_BYTES).contains(&asar_bytes) {
        return Err(AsarError::Envelope(format!(
            "ASAR length is outside 16..={MAX_ASAR_BYTES}"
        )));
    }
    if read_u32(bytes, 0)? != 4 {
        return Err(AsarError::Envelope(
            "outer Pickle must contain exactly one 32-bit header size".to_owned(),
        ));
    }
    let header_pickle = usize::try_from(read_u32(bytes, 4)?)
        .map_err(|_| AsarError::Envelope("header Pickle size does not fit usize".to_owned()))?;
    let string_payload = usize::try_from(read_u32(bytes, 8)?)
        .map_err(|_| AsarError::Envelope("string Pickle size does not fit usize".to_owned()))?;
    let json_length = usize::try_from(read_u32(bytes, 12)?)
        .map_err(|_| AsarError::Envelope("JSON size does not fit usize".to_owned()))?;
    if json_length == 0 || json_length > MAX_ASAR_HEADER_BYTES {
        return Err(AsarError::Envelope(format!(
            "JSON header size is outside 1..={MAX_ASAR_HEADER_BYTES}"
        )));
    }
    let unpadded_payload = checked_add(5, json_length, "string payload")?;
    let expected_payload = align_four(unpadded_payload)?;
    if string_payload != expected_payload
        || header_pickle != checked_add(4, string_payload, "header Pickle")?
    {
        return Err(AsarError::Envelope(
            "noncanonical Pickle length fields".to_owned(),
        ));
    }
    let data_offset = checked_add(8, header_pickle, "packed data offset")?;
    if data_offset > bytes.len() {
        return Err(AsarError::Envelope(
            "header Pickle crosses the complete ASAR".to_owned(),
        ));
    }
    let json_end = checked_add(16, json_length, "JSON header")?;
    if json_end >= data_offset || bytes[json_end] != 0 {
        return Err(AsarError::Envelope(
            "header string is missing its canonical NUL terminator".to_owned(),
        ));
    }
    if bytes[json_end + 1..data_offset]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(AsarError::Envelope(
            "header Pickle padding is not zero".to_owned(),
        ));
    }

    let root: StrictValue = serde_json::from_slice(&bytes[16..json_end])
        .map_err(|error| AsarError::Header(error.to_string()))?;
    let mut root = root.into_object("root")?;
    let files = remove_required(&mut root, "files", "root")?.into_object("root files")?;
    reject_remaining(&root, "root")?;

    let data = &bytes[data_offset..];
    let mut state = WalkState::default();
    walk_files(files, "", false, 1, data, &mut state)?;
    state
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    validate_packed_layout(data, &state.entries)?;

    let packed_file_count = state
        .entries
        .iter()
        .filter(|entry| entry.storage == AsarStorage::Packed)
        .count();
    let unpacked_file_count = state.entries.len() - packed_file_count;
    let executable_file_count = state
        .entries
        .iter()
        .filter(|entry| entry.executable)
        .count();
    let inspection = AsarInspection {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "asar_inspection",
        asar_sha256: hex_lower(&Sha256::digest(bytes)),
        asar_bytes,
        header_json_bytes: u64::try_from(json_length)
            .map_err(|_| AsarError::Envelope("JSON length does not fit u64".to_owned()))?,
        packed_data_bytes: u64::try_from(data.len())
            .map_err(|_| AsarError::Envelope("data length does not fit u64".to_owned()))?,
        directory_count: u64::try_from(state.directory_count)
            .map_err(|_| AsarError::Entry("directory count does not fit u64".to_owned()))?,
        packed_file_count: u64::try_from(packed_file_count)
            .map_err(|_| AsarError::Entry("packed file count does not fit u64".to_owned()))?,
        unpacked_file_count: u64::try_from(unpacked_file_count)
            .map_err(|_| AsarError::Entry("unpacked file count does not fit u64".to_owned()))?,
        executable_file_count: u64::try_from(executable_file_count)
            .map_err(|_| AsarError::Entry("executable count does not fit u64".to_owned()))?,
        unpacked_declared_bytes: state.unpacked_declared_bytes,
        packed_integrity_verified: true,
    };
    Ok(AsarIndex {
        inspection,
        entries: state.entries,
        data_offset,
    })
}

#[derive(Debug, Default)]
struct WalkState {
    entries: Vec<AsarEntry>,
    directory_count: usize,
    unpacked_declared_bytes: u64,
}

fn walk_files(
    files: BTreeMap<String, StrictValue>,
    parent: &str,
    inherited_unpacked: bool,
    depth: usize,
    data: &[u8],
    state: &mut WalkState,
) -> Result<(), AsarError> {
    if depth > MAX_ASAR_DEPTH {
        return Err(AsarError::Entry(format!(
            "path depth exceeds {MAX_ASAR_DEPTH}"
        )));
    }
    for (component, value) in files {
        validate_component(&component)?;
        let path = if parent.is_empty() {
            component
        } else {
            format!("{parent}/{component}")
        };
        if path.len() > MAX_PATH_BYTES {
            return Err(AsarError::Entry(format!(
                "path exceeds {MAX_PATH_BYTES} bytes"
            )));
        }
        let mut object = value.into_object(&path)?;
        if let Some(children) = object.remove("files") {
            let own_unpacked = take_optional_true(&mut object, "unpacked", &path)?;
            reject_remaining(&object, &path)?;
            state.directory_count = state
                .directory_count
                .checked_add(1)
                .ok_or_else(|| AsarError::Entry("directory count overflowed".to_owned()))?;
            enforce_entry_count(state)?;
            walk_files(
                children.into_object(&format!("{path} files"))?,
                &path,
                inherited_unpacked || own_unpacked,
                depth + 1,
                data,
                state,
            )?;
            continue;
        }
        if object.contains_key("link") {
            return Err(AsarError::Entry(format!(
                "ASAR links are not accepted: {path:?}"
            )));
        }
        let size = remove_required(&mut object, "size", &path)?.into_u64(&path)?;
        if size > MAX_FILE_BYTES {
            return Err(AsarError::Entry(format!(
                "file {path:?} exceeds {MAX_FILE_BYTES} bytes"
            )));
        }
        let own_unpacked = take_optional_true(&mut object, "unpacked", &path)?;
        let unpacked = inherited_unpacked || own_unpacked;
        let executable = take_optional_true(&mut object, "executable", &path)?;
        let integrity = parse_integrity(
            remove_required(&mut object, "integrity", &path)?,
            size,
            &path,
        )?;
        let offset = match object.remove("offset") {
            Some(value) if unpacked => {
                return Err(AsarError::Entry(format!(
                    "unpacked file {path:?} declares a packed offset: {value:?}"
                )));
            }
            Some(value) => Some(parse_offset(value, &path)?),
            None if unpacked => None,
            None => {
                return Err(AsarError::Entry(format!(
                    "packed file {path:?} is missing its offset"
                )));
            }
        };
        reject_remaining(&object, &path)?;
        if let Some(offset) = offset {
            verify_packed_integrity(data, offset, size, &integrity, &path)?;
        } else {
            state.unpacked_declared_bytes = state
                .unpacked_declared_bytes
                .checked_add(size)
                .ok_or_else(|| AsarError::Entry("unpacked size sum overflowed".to_owned()))?;
            if state.unpacked_declared_bytes > MAX_UNPACKED_DECLARED_BYTES {
                return Err(AsarError::Entry(format!(
                    "unpacked declared bytes exceed {MAX_UNPACKED_DECLARED_BYTES}"
                )));
            }
        }
        state.entries.push(AsarEntry {
            path,
            storage: if unpacked {
                AsarStorage::Unpacked
            } else {
                AsarStorage::Packed
            },
            bytes: size,
            offset,
            executable,
            sha256: integrity.hash,
        });
        enforce_entry_count(state)?;
    }
    Ok(())
}

fn enforce_entry_count(state: &WalkState) -> Result<(), AsarError> {
    let count = state
        .directory_count
        .checked_add(state.entries.len())
        .ok_or_else(|| AsarError::Entry("entry count overflowed".to_owned()))?;
    if count > MAX_ASAR_ENTRIES {
        return Err(AsarError::Entry(format!(
            "entry count exceeds {MAX_ASAR_ENTRIES}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct Integrity {
    hash: String,
    block_hashes: Vec<String>,
}

fn parse_integrity(value: StrictValue, size: u64, path: &str) -> Result<Integrity, AsarError> {
    let mut object = value.into_object(&format!("{path} integrity"))?;
    let algorithm = remove_required(&mut object, "algorithm", path)?.into_string(path)?;
    if algorithm != "SHA256" {
        return Err(AsarError::Entry(format!(
            "unsupported integrity algorithm for {path:?}"
        )));
    }
    let hash = remove_required(&mut object, "hash", path)?.into_string(path)?;
    validate_sha256(&hash, path)?;
    let block_size = remove_required(&mut object, "blockSize", path)?.into_u64(path)?;
    if block_size != INTEGRITY_BLOCK_BYTES {
        return Err(AsarError::Entry(format!(
            "integrity block size for {path:?} is not {INTEGRITY_BLOCK_BYTES}"
        )));
    }
    let blocks = remove_required(&mut object, "blocks", path)?.into_array(path)?;
    let expected_blocks = if size == 0 {
        1
    } else {
        usize::try_from((size - 1) / INTEGRITY_BLOCK_BYTES + 1)
            .map_err(|_| AsarError::Entry(format!("block count does not fit for {path:?}")))?
    };
    if blocks.len() != expected_blocks {
        return Err(AsarError::Entry(format!(
            "integrity block count differs for {path:?}"
        )));
    }
    let mut block_hashes = Vec::with_capacity(blocks.len());
    for block in blocks {
        let hash = block.into_string(path)?;
        validate_sha256(&hash, path)?;
        block_hashes.push(hash);
    }
    reject_remaining(&object, &format!("{path} integrity"))?;
    Ok(Integrity { hash, block_hashes })
}

fn verify_packed_integrity(
    data: &[u8],
    offset: u64,
    size: u64,
    integrity: &Integrity,
    path: &str,
) -> Result<(), AsarError> {
    let start = usize::try_from(offset)
        .map_err(|_| AsarError::Entry(format!("offset does not fit for {path:?}")))?;
    let size_usize = usize::try_from(size)
        .map_err(|_| AsarError::Entry(format!("size does not fit for {path:?}")))?;
    let end = checked_add(start, size_usize, "packed file range")?;
    let contents = data
        .get(start..end)
        .ok_or_else(|| AsarError::Entry(format!("packed range crosses ASAR for {path:?}")))?;
    if hex_lower(&Sha256::digest(contents)) != integrity.hash {
        return Err(AsarError::Integrity(format!(
            "whole-file SHA-256 differs for {path:?}"
        )));
    }
    let block_bytes = usize::try_from(INTEGRITY_BLOCK_BYTES)
        .map_err(|_| AsarError::Envelope("block size does not fit usize".to_owned()))?;
    if contents.is_empty() {
        if hex_lower(&Sha256::digest([])) != integrity.block_hashes[0] {
            return Err(AsarError::Integrity(format!(
                "empty block SHA-256 differs for {path:?}"
            )));
        }
    } else {
        for (block, expected) in contents.chunks(block_bytes).zip(&integrity.block_hashes) {
            if hex_lower(&Sha256::digest(block)) != *expected {
                return Err(AsarError::Integrity(format!(
                    "block SHA-256 differs for {path:?}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_packed_layout(data: &[u8], entries: &[AsarEntry]) -> Result<(), AsarError> {
    let mut packed: Vec<&AsarEntry> = entries
        .iter()
        .filter(|entry| entry.storage == AsarStorage::Packed)
        .collect();
    packed.sort_by(|left, right| {
        left.offset
            .cmp(&right.offset)
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut expected = 0_u64;
    for entry in packed {
        let offset = entry
            .offset
            .ok_or_else(|| AsarError::Entry("packed entry lost its offset".to_owned()))?;
        if offset != expected {
            return Err(AsarError::Entry(format!(
                "packed ranges overlap or contain a gap before {:?}",
                entry.path
            )));
        }
        expected = expected
            .checked_add(entry.bytes)
            .ok_or_else(|| AsarError::Entry("packed size sum overflowed".to_owned()))?;
    }
    let data_bytes = u64::try_from(data.len())
        .map_err(|_| AsarError::Envelope("data length does not fit u64".to_owned()))?;
    if expected != data_bytes {
        return Err(AsarError::Entry(
            "packed ranges do not consume the exact data region".to_owned(),
        ));
    }
    Ok(())
}

fn validate_component(component: &str) -> Result<(), AsarError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_COMPONENT_BYTES
        || !component.is_ascii()
        || component
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || matches!(byte, b'/' | b'\\' | b':' | 0))
    {
        return Err(AsarError::Entry(format!(
            "unsafe ASAR path component {component:?}"
        )));
    }
    Ok(())
}

fn parse_offset(value: StrictValue, path: &str) -> Result<u64, AsarError> {
    let value = value.into_string(path)?;
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AsarError::Entry(format!(
            "noncanonical packed offset for {path:?}"
        )));
    }
    value
        .parse()
        .map_err(|_| AsarError::Entry(format!("packed offset overflows for {path:?}")))
}

fn take_optional_true(
    object: &mut BTreeMap<String, StrictValue>,
    key: &str,
    context: &str,
) -> Result<bool, AsarError> {
    match object.remove(key) {
        None => Ok(false),
        Some(StrictValue::Bool(true)) => Ok(true),
        Some(_) => Err(AsarError::Entry(format!(
            "{key:?} must be true when present in {context:?}"
        ))),
    }
}

fn remove_required(
    object: &mut BTreeMap<String, StrictValue>,
    key: &str,
    context: &str,
) -> Result<StrictValue, AsarError> {
    object
        .remove(key)
        .ok_or_else(|| AsarError::Header(format!("missing {key:?} in {context:?}")))
}

fn reject_remaining(
    object: &BTreeMap<String, StrictValue>,
    context: &str,
) -> Result<(), AsarError> {
    if let Some(key) = object.keys().next() {
        return Err(AsarError::Header(format!(
            "unknown field {key:?} in {context:?}"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str, path: &str) -> Result<(), AsarError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AsarError::Entry(format!(
            "invalid lowercase SHA-256 for {path:?}"
        )));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AsarError> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| AsarError::Envelope("truncated 32-bit Pickle field".to_owned()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn align_four(value: usize) -> Result<usize, AsarError> {
    checked_add(value, 3, "Pickle alignment").map(|value| value & !3)
}

fn checked_add(left: usize, right: usize, label: &str) -> Result<usize, AsarError> {
    left.checked_add(right)
        .ok_or_else(|| AsarError::Envelope(format!("{label} overflowed")))
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

#[derive(Clone)]
enum StrictValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl fmt::Debug for StrictValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null"),
            Self::Bool(value) => value.fmt(formatter),
            Self::Unsigned(value) => value.fmt(formatter),
            Self::String(value) => value.fmt(formatter),
            Self::Array(value) => value.fmt(formatter),
            Self::Object(value) => value.fmt(formatter),
        }
    }
}

impl StrictValue {
    fn into_object(self, context: &str) -> Result<BTreeMap<String, Self>, AsarError> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err(AsarError::Header(format!("{context:?} must be an object"))),
        }
    }

    fn into_array(self, context: &str) -> Result<Vec<Self>, AsarError> {
        match self {
            Self::Array(value) => Ok(value),
            _ => Err(AsarError::Header(format!("{context:?} must be an array"))),
        }
    }

    fn into_string(self, context: &str) -> Result<String, AsarError> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err(AsarError::Header(format!("{context:?} must be a string"))),
        }
    }

    fn into_u64(self, context: &str) -> Result<u64, AsarError> {
        match self {
            Self::Unsigned(value) => Ok(value),
            _ => Err(AsarError::Header(format!(
                "{context:?} must be an unsigned integer"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue::Unsigned(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map(StrictValue::Unsigned)
            .map_err(|_| E::custom("negative JSON integers are forbidden"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point JSON numbers are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!("duplicate JSON key {key:?}")));
            }
        }
        Ok(StrictValue::Object(values))
    }
}
