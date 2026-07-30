//! Strict, bounded parsing for the official x86_64 Sparkle feed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use rustix::fs::{Mode, OFlags, fstat, open};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION};

/// Official Intel/x86_64 update feed used for the Linux x86_64 source pipeline.
pub const OFFICIAL_FEED_URL: &str =
    "https://persistent.oaistatic.com/codex-app-prod/appcast-x64.xml";

/// Maximum accepted XML feed size.
pub const MAX_FEED_BYTES: usize = 256 * 1024;
const MAX_FEED_BYTES_U64: u64 = 256 * 1024;

const MAX_RELEASES: usize = 64;
const MAX_XML_DEPTH: usize = 16;
const MAX_TEXT_FIELD_BYTES: usize = 2_048;
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SPARKLE_NAMESPACE: &str = "http://www.andymatuschak.org/xml-namespaces/sparkle";
const ARTIFACT_PREFIX: &str = "https://persistent.oaistatic.com/codex-app-prod/";

/// Identifies where inspected feed bytes came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedSource {
    /// Bytes fetched from the one compiled-in official URL.
    OfficialHttps {
        /// Exact final URL.
        url: String,
    },
    /// Bytes read from a bounded local fixture.
    LocalFixture {
        /// Caller-provided fixture path.
        path: String,
    },
}

/// A complete Sparkle artifact enclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactMetadata {
    /// Exact HTTPS artifact URL.
    pub url: String,
    /// Declared complete artifact length.
    pub length: u64,
    /// Exact declared media type.
    pub content_type: String,
    /// Standard-base64 Ed25519 signature over the complete artifact.
    pub ed25519_signature: String,
}

/// Typed release metadata from one feed item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseMetadata {
    /// Human-facing item title.
    pub title: String,
    /// Sparkle short version.
    pub version: String,
    /// Sparkle build version.
    pub build: String,
    /// RFC 2822-style publication date as supplied by the feed.
    pub published_at: String,
    /// Minimum supported macOS version declared by the source artifact.
    pub minimum_system_version: String,
    /// Required source hardware architecture.
    pub hardware_requirements: String,
    /// Exact metadata source that established the architecture.
    pub architecture_source: &'static str,
    /// Complete source archive metadata.
    pub artifact: ArtifactMetadata,
}

/// Deterministic schema-1 result of feed inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FeedInspection {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer identifier.
    pub producer: &'static str,
    /// Stable document kind.
    pub kind: &'static str,
    /// Exact byte source.
    pub source: FeedSource,
    /// SHA-256 of the complete inspected XML bytes.
    pub feed_sha256: String,
    /// Complete XML byte length.
    pub feed_bytes: u64,
    /// Exact channel title.
    pub channel_title: String,
    /// Releases in authoritative feed order.
    pub releases: Vec<ReleaseMetadata>,
}

/// Feed download or parse rejection.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FeedError {
    /// The byte envelope is invalid.
    #[error("invalid feed envelope: {0}")]
    Envelope(&'static str),

    /// XML structure or content is invalid.
    #[error("invalid feed XML: {0}")]
    Xml(String),

    /// A required value is absent, duplicated, or invalid.
    #[error("invalid feed metadata: {0}")]
    Metadata(String),

    /// A local fixture could not be opened or read safely.
    #[error("invalid local feed fixture: {0}")]
    Fixture(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextTarget {
    ChannelTitle,
    ItemTitle,
    PublishedAt,
    Build,
    Version,
    MinimumSystemVersion,
    HardwareRequirements,
}

#[derive(Debug)]
struct ActiveText {
    depth: usize,
    target: TextTarget,
    value: String,
}

#[derive(Debug, Default)]
struct ItemBuilder {
    title: Option<String>,
    published_at: Option<String>,
    build: Option<String>,
    version: Option<String>,
    minimum_system_version: Option<String>,
    hardware_requirements: Option<String>,
    artifact: Option<ArtifactMetadata>,
}

impl ItemBuilder {
    fn set_text(&mut self, target: TextTarget, value: String) -> Result<(), FeedError> {
        let slot = match target {
            TextTarget::ItemTitle => &mut self.title,
            TextTarget::PublishedAt => &mut self.published_at,
            TextTarget::Build => &mut self.build,
            TextTarget::Version => &mut self.version,
            TextTarget::MinimumSystemVersion => &mut self.minimum_system_version,
            TextTarget::HardwareRequirements => &mut self.hardware_requirements,
            TextTarget::ChannelTitle => {
                return Err(FeedError::Xml(
                    "channel title appeared inside an item".to_owned(),
                ));
            }
        };
        if slot.replace(value).is_some() {
            return Err(FeedError::Metadata(format!(
                "duplicate scalar field {target:?}"
            )));
        }
        Ok(())
    }

    fn finish(self) -> Result<ReleaseMetadata, FeedError> {
        let title = required(self.title, "item title")?;
        let version = required(self.version, "short version")?;
        if title != version {
            return Err(FeedError::Metadata(
                "item title and short version differ".to_owned(),
            ));
        }
        validate_dotted_numeric(&version, "short version")?;

        let build = required(self.build, "build version")?;
        validate_ascii_digits(&build, "build version")?;

        let published_at = required(self.published_at, "publication date")?;
        validate_ascii_field(&published_at, "publication date", 96)?;

        let minimum_system_version =
            required(self.minimum_system_version, "minimum system version")?;
        validate_dotted_numeric(&minimum_system_version, "minimum system version")?;

        let (hardware_requirements, architecture_source) = match self.hardware_requirements {
            Some(value) if value == "x86_64" => (value, "sparkle_hardware_requirements"),
            Some(value) => {
                return Err(FeedError::Metadata(format!(
                    "unsupported hardware requirements {value:?}"
                )));
            }
            None => ("x86_64".to_owned(), "fixed_x86_64_feed_endpoint"),
        };

        Ok(ReleaseMetadata {
            title,
            version,
            build,
            published_at,
            minimum_system_version,
            hardware_requirements,
            architecture_source,
            artifact: required(self.artifact, "primary enclosure")?,
        })
    }
}

/// Parses already bounded feed bytes into typed release metadata.
pub fn inspect_feed_bytes(bytes: &[u8], source: FeedSource) -> Result<FeedInspection, FeedError> {
    validate_envelope(bytes, &source)?;

    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_comments = true;

    let mut stack = Vec::<Vec<u8>>::new();
    let mut saw_declaration = false;
    let mut saw_root = false;
    let mut saw_channel = false;
    let mut channel_title = None;
    let mut current_item = None::<ItemBuilder>;
    let mut active_text = None::<ActiveText>;
    let mut releases = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|error| FeedError::Xml(error.to_string()))?;
        match event {
            Event::Decl(declaration) => {
                if saw_declaration || saw_root || !stack.is_empty() {
                    return Err(FeedError::Xml(
                        "misplaced or duplicate XML declaration".to_owned(),
                    ));
                }
                let version = declaration
                    .version()
                    .map_err(|error| FeedError::Xml(error.to_string()))?;
                if version.as_ref() != b"1.0" {
                    return Err(FeedError::Xml("only XML 1.0 is accepted".to_owned()));
                }
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.map_err(|error| FeedError::Xml(error.to_string()))?;
                    if !encoding.as_ref().eq_ignore_ascii_case(b"utf-8") {
                        return Err(FeedError::Xml("only UTF-8 XML is accepted".to_owned()));
                    }
                }
                saw_declaration = true;
            }
            Event::Start(start) => {
                if active_text.is_some() {
                    return Err(FeedError::Xml(
                        "nested markup inside scalar field".to_owned(),
                    ));
                }
                let name = start.name().as_ref().to_vec();
                stack.push(name.clone());
                if stack.len() > MAX_XML_DEPTH {
                    return Err(FeedError::Xml(
                        "XML nesting exceeds configured depth".to_owned(),
                    ));
                }
                on_start(
                    &start,
                    &reader,
                    &stack,
                    &mut saw_root,
                    &mut saw_channel,
                    &mut current_item,
                    &mut active_text,
                )?;
            }
            Event::Empty(empty) => {
                if active_text.is_some() {
                    return Err(FeedError::Xml("markup inside scalar field".to_owned()));
                }
                let mut path = stack.clone();
                path.push(empty.name().as_ref().to_vec());
                if path.len() > MAX_XML_DEPTH {
                    return Err(FeedError::Xml(
                        "XML nesting exceeds configured depth".to_owned(),
                    ));
                }
                if path_is(&path, &[b"rss", b"channel", b"item", b"enclosure"]) {
                    let artifact = parse_enclosure(&empty, &reader)?;
                    let item = current_item.as_mut().ok_or_else(|| {
                        FeedError::Xml("primary enclosure outside an item".to_owned())
                    })?;
                    if item.artifact.replace(artifact).is_some() {
                        return Err(FeedError::Metadata(
                            "duplicate primary enclosure".to_owned(),
                        ));
                    }
                }
            }
            Event::Text(text) => {
                if let Some(active) = active_text.as_mut() {
                    let decoded = text
                        .xml10_content()
                        .map_err(|error| FeedError::Xml(error.to_string()))?;
                    active.value.push_str(&decoded);
                    if active.value.len() > MAX_TEXT_FIELD_BYTES {
                        return Err(FeedError::Xml(
                            "scalar field exceeds configured size".to_owned(),
                        ));
                    }
                } else {
                    let decoded = text
                        .xml10_content()
                        .map_err(|error| FeedError::Xml(error.to_string()))?;
                    if !decoded.trim().is_empty() {
                        return Err(FeedError::Xml("unexpected free text".to_owned()));
                    }
                }
            }
            Event::End(end) => {
                let depth = stack.len();
                if let Some(active) = active_text.take() {
                    if active.depth == depth {
                        let value = active.value.trim().to_owned();
                        if value.is_empty() {
                            return Err(FeedError::Metadata("empty scalar field".to_owned()));
                        }
                        if active.target == TextTarget::ChannelTitle {
                            if channel_title.replace(value).is_some() {
                                return Err(FeedError::Metadata(
                                    "duplicate channel title".to_owned(),
                                ));
                            }
                        } else {
                            current_item
                                .as_mut()
                                .ok_or_else(|| {
                                    FeedError::Xml("item field outside item".to_owned())
                                })?
                                .set_text(active.target, value)?;
                        }
                    } else {
                        active_text = Some(active);
                    }
                }

                if path_is(&stack, &[b"rss", b"channel", b"item"]) {
                    let item = current_item
                        .take()
                        .ok_or_else(|| FeedError::Xml("item end without item".to_owned()))?;
                    releases.push(item.finish()?);
                    if releases.len() > MAX_RELEASES {
                        return Err(FeedError::Metadata(
                            "release count exceeds configured limit".to_owned(),
                        ));
                    }
                }

                let expected = stack
                    .pop()
                    .ok_or_else(|| FeedError::Xml("unexpected closing element".to_owned()))?;
                if expected.as_slice() != end.name().as_ref() {
                    return Err(FeedError::Xml("mismatched closing element".to_owned()));
                }
            }
            Event::Comment(_) => {}
            Event::Eof => break,
            Event::DocType(_) => {
                return Err(FeedError::Xml(
                    "document type declarations are forbidden".to_owned(),
                ));
            }
            Event::PI(_) => {
                return Err(FeedError::Xml(
                    "processing instructions are forbidden".to_owned(),
                ));
            }
            Event::CData(_) => {
                return Err(FeedError::Xml("CDATA sections are forbidden".to_owned()));
            }
            Event::GeneralRef(_) => {
                return Err(FeedError::Xml("entity references are forbidden".to_owned()));
            }
        }
    }

    if !stack.is_empty() || current_item.is_some() || active_text.is_some() {
        return Err(FeedError::Xml("truncated XML document".to_owned()));
    }
    if !saw_declaration || !saw_root || !saw_channel {
        return Err(FeedError::Xml(
            "required XML envelope is missing".to_owned(),
        ));
    }
    let channel_title = required(channel_title, "channel title")?;
    if channel_title != "Codex" {
        return Err(FeedError::Metadata(format!(
            "unexpected channel title {channel_title:?}"
        )));
    }
    if releases.is_empty() {
        return Err(FeedError::Metadata("feed contains no releases".to_owned()));
    }
    validate_release_uniqueness(&releases)?;

    let digest = Sha256::digest(bytes);
    Ok(FeedInspection {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "feed_inspection",
        source,
        feed_sha256: hex_lower(&digest),
        feed_bytes: u64::try_from(bytes.len())
            .map_err(|_| FeedError::Envelope("feed length is not representable"))?,
        channel_title,
        releases,
    })
}

/// Opens and inspects one bounded, regular local XML fixture without following
/// a final symlink or blocking on a FIFO.
pub fn inspect_feed_fixture(path: &Path) -> Result<FeedInspection, FeedError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| FeedError::Fixture(error.to_string()))?;
    let metadata = fstat(&descriptor).map_err(|error| FeedError::Fixture(error.to_string()))?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(FeedError::Fixture("input is not a regular file".to_owned()));
    }
    if metadata.st_size < 0
        || u64::try_from(metadata.st_size).map_or(true, |size| size > MAX_FEED_BYTES_U64)
    {
        return Err(FeedError::Fixture(
            "input exceeds configured byte limit".to_owned(),
        ));
    }

    let mut file = File::from(descriptor);
    let read_limit = MAX_FEED_BYTES_U64 + 1;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| FeedError::Fixture(error.to_string()))?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(FeedError::Fixture(
            "input exceeds configured byte limit".to_owned(),
        ));
    }

    inspect_feed_bytes(
        &bytes,
        FeedSource::LocalFixture {
            path: path.display().to_string(),
        },
    )
}

fn on_start(
    start: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    stack: &[Vec<u8>],
    saw_root: &mut bool,
    saw_channel: &mut bool,
    current_item: &mut Option<ItemBuilder>,
    active_text: &mut Option<ActiveText>,
) -> Result<(), FeedError> {
    if path_is(stack, &[b"rss"]) {
        if *saw_root {
            return Err(FeedError::Xml("duplicate RSS root".to_owned()));
        }
        validate_root(start, reader)?;
        *saw_root = true;
        return Ok(());
    }
    if path_is(stack, &[b"rss", b"channel"]) {
        if *saw_channel {
            return Err(FeedError::Xml("duplicate channel".to_owned()));
        }
        if has_attributes(start) {
            return Err(FeedError::Xml(
                "channel attributes are forbidden".to_owned(),
            ));
        }
        *saw_channel = true;
        return Ok(());
    }
    if path_is(stack, &[b"rss", b"channel", b"item"]) {
        if current_item.replace(ItemBuilder::default()).is_some() {
            return Err(FeedError::Xml("nested item".to_owned()));
        }
        if has_attributes(start) {
            return Err(FeedError::Xml("item attributes are forbidden".to_owned()));
        }
        return Ok(());
    }
    if path_is(stack, &[b"rss", b"channel", b"item", b"enclosure"]) {
        let artifact = parse_enclosure(start, reader)?;
        let item = current_item
            .as_mut()
            .ok_or_else(|| FeedError::Xml("primary enclosure outside item".to_owned()))?;
        if item.artifact.replace(artifact).is_some() {
            return Err(FeedError::Metadata(
                "duplicate primary enclosure".to_owned(),
            ));
        }
        return Ok(());
    }

    let target = if path_is(stack, &[b"rss", b"channel", b"title"]) {
        Some(TextTarget::ChannelTitle)
    } else if path_is(stack, &[b"rss", b"channel", b"item", b"title"]) {
        Some(TextTarget::ItemTitle)
    } else if path_is(stack, &[b"rss", b"channel", b"item", b"pubDate"]) {
        Some(TextTarget::PublishedAt)
    } else if path_is(stack, &[b"rss", b"channel", b"item", b"sparkle:version"]) {
        Some(TextTarget::Build)
    } else if path_is(
        stack,
        &[b"rss", b"channel", b"item", b"sparkle:shortVersionString"],
    ) {
        Some(TextTarget::Version)
    } else if path_is(
        stack,
        &[b"rss", b"channel", b"item", b"sparkle:minimumSystemVersion"],
    ) {
        Some(TextTarget::MinimumSystemVersion)
    } else if path_is(
        stack,
        &[b"rss", b"channel", b"item", b"sparkle:hardwareRequirements"],
    ) {
        Some(TextTarget::HardwareRequirements)
    } else {
        None
    };

    if let Some(target) = target {
        if has_attributes(start) {
            return Err(FeedError::Xml(
                "scalar field attributes are forbidden".to_owned(),
            ));
        }
        *active_text = Some(ActiveText {
            depth: stack.len(),
            target,
            value: String::new(),
        });
    }
    Ok(())
}

fn validate_root(start: &BytesStart<'_>, reader: &Reader<&[u8]>) -> Result<(), FeedError> {
    let attributes = attributes(start, reader)?;
    if attributes.len() != 2
        || attributes.get(b"version".as_slice()).map(String::as_str) != Some("2.0")
        || attributes
            .get(b"xmlns:sparkle".as_slice())
            .map(String::as_str)
            != Some(SPARKLE_NAMESPACE)
    {
        return Err(FeedError::Xml(
            "RSS root attributes are not the exact Sparkle contract".to_owned(),
        ));
    }
    Ok(())
}

fn parse_enclosure(
    start: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
) -> Result<ArtifactMetadata, FeedError> {
    let mut attributes = attributes(start, reader)?;
    if attributes.len() != 4 {
        return Err(FeedError::Metadata(
            "primary enclosure must have exactly four attributes".to_owned(),
        ));
    }
    let url = take_attribute(&mut attributes, b"url", "artifact URL")?;
    validate_artifact_url(&url)?;

    let length = take_attribute(&mut attributes, b"length", "artifact length")?;
    validate_ascii_digits(&length, "artifact length")?;
    let length = length.parse::<u64>().map_err(|_| {
        FeedError::Metadata("artifact length is not an unsigned integer".to_owned())
    })?;
    if length == 0 || length > MAX_ARTIFACT_BYTES {
        return Err(FeedError::Metadata(
            "artifact length is outside configured bounds".to_owned(),
        ));
    }

    let content_type = take_attribute(&mut attributes, b"type", "artifact content type")?;
    if content_type != "application/octet-stream" {
        return Err(FeedError::Metadata(format!(
            "unsupported artifact content type {content_type:?}"
        )));
    }

    let ed25519_signature = take_attribute(
        &mut attributes,
        b"sparkle:edSignature",
        "artifact Ed25519 signature",
    )?;
    let signature = BASE64_STANDARD
        .decode(ed25519_signature.as_bytes())
        .map_err(|_| {
            FeedError::Metadata("artifact Ed25519 signature is not canonical base64".to_owned())
        })?;
    if signature.len() != 64 || BASE64_STANDARD.encode(&signature) != ed25519_signature {
        return Err(FeedError::Metadata(
            "artifact Ed25519 signature is not 64 canonical bytes".to_owned(),
        ));
    }

    if !attributes.is_empty() {
        return Err(FeedError::Metadata(
            "unknown primary enclosure attribute".to_owned(),
        ));
    }

    Ok(ArtifactMetadata {
        url,
        length,
        content_type,
        ed25519_signature,
    })
}

fn attributes(
    start: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
) -> Result<BTreeMap<Vec<u8>, String>, FeedError> {
    let mut result = BTreeMap::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| FeedError::Xml(error.to_string()))?;
        let key = attribute.key.as_ref().to_vec();
        let value = attribute
            .decoded_and_normalized_value(quick_xml::XmlVersion::Explicit1_0, reader.decoder())
            .map_err(|error| FeedError::Xml(error.to_string()))?
            .into_owned();
        if result.insert(key, value).is_some() {
            return Err(FeedError::Xml("duplicate XML attribute".to_owned()));
        }
    }
    Ok(result)
}

fn has_attributes(start: &BytesStart<'_>) -> bool {
    start.attributes().next().is_some()
}

fn take_attribute(
    attributes: &mut BTreeMap<Vec<u8>, String>,
    name: &[u8],
    label: &str,
) -> Result<String, FeedError> {
    attributes
        .remove(name)
        .ok_or_else(|| FeedError::Metadata(format!("missing {label}")))
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

fn validate_envelope(bytes: &[u8], source: &FeedSource) -> Result<(), FeedError> {
    if bytes.is_empty() {
        return Err(FeedError::Envelope("feed is empty"));
    }
    if bytes.len() > MAX_FEED_BYTES {
        return Err(FeedError::Envelope("feed exceeds configured byte limit"));
    }
    if bytes.contains(&0) {
        return Err(FeedError::Envelope("NUL bytes are forbidden"));
    }
    if contains_ascii_case_insensitive(bytes, b"<!doctype") {
        return Err(FeedError::Envelope(
            "document type declarations are forbidden",
        ));
    }
    if contains_ascii_case_insensitive(bytes, b"<!entity") {
        return Err(FeedError::Envelope("entity declarations are forbidden"));
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(FeedError::Envelope("feed is not valid UTF-8"));
    }
    if let FeedSource::OfficialHttps { url } = source {
        if url != OFFICIAL_FEED_URL {
            return Err(FeedError::Envelope(
                "official source URL is not the compiled-in endpoint",
            ));
        }
    }
    Ok(())
}

fn validate_artifact_url(value: &str) -> Result<(), FeedError> {
    if value.len() > MAX_TEXT_FIELD_BYTES {
        return Err(FeedError::Metadata(
            "artifact URL exceeds configured size".to_owned(),
        ));
    }
    let Some(file_name) = value.strip_prefix(ARTIFACT_PREFIX) else {
        return Err(FeedError::Metadata(
            "artifact URL violates the exact-origin policy".to_owned(),
        ));
    };
    if file_name.is_empty()
        || !file_name.ends_with(".zip")
        || file_name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
        || file_name.starts_with('.')
        || file_name.contains("..")
    {
        return Err(FeedError::Metadata(
            "artifact URL violates the exact-origin policy".to_owned(),
        ));
    }
    Ok(())
}

fn validate_release_uniqueness(releases: &[ReleaseMetadata]) -> Result<(), FeedError> {
    let mut versions = BTreeSet::new();
    let mut builds = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for release in releases {
        if !versions.insert(release.version.as_str()) {
            return Err(FeedError::Metadata("duplicate release version".to_owned()));
        }
        if !builds.insert(release.build.as_str()) {
            return Err(FeedError::Metadata("duplicate release build".to_owned()));
        }
        if !urls.insert(release.artifact.url.as_str()) {
            return Err(FeedError::Metadata("duplicate artifact URL".to_owned()));
        }
    }
    Ok(())
}

fn validate_ascii_field(value: &str, label: &str, max_bytes: usize) -> Result<(), FeedError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(FeedError::Metadata(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_ascii_digits(value: &str, label: &str) -> Result<(), FeedError> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FeedError::Metadata(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_dotted_numeric(value: &str, label: &str) -> Result<(), FeedError> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('.')
        || value.ends_with('.')
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(FeedError::Metadata(format!("invalid {label}")));
    }
    Ok(())
}

fn required<T>(value: Option<T>, label: &str) -> Result<T, FeedError> {
    value.ok_or_else(|| FeedError::Metadata(format!("missing {label}")))
}

fn path_is(path: &[Vec<u8>], expected: &[&[u8]]) -> bool {
    path.len() == expected.len()
        && path
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_slice() == *expected)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}
