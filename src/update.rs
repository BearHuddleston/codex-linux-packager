//! Signed, pinned-key release metadata and restart-safe AppImage updates.

use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek as _, SeekFrom, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, open, openat,
    renameat_with, statat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::appimage::AppImageManifest;
use crate::manifest::{
    PRODUCER_IDENTIFIER, SCHEMA_VERSION, is_canonical_utc_timestamp, to_json_line,
};
use crate::signature::verify_ed25519_bytes;

const UPDATE_CONTRACT_KIND: &str = "linux_x86_64_update_contract";
const UPDATE_CONTRACT_JSON: &str = include_str!("../data/update-contract.json");
const UPDATE_PAYLOAD_KIND: &str = "linux_x86_64_update_payload";
const SIGNED_UPDATE_KIND: &str = "linux_x86_64_signed_update_manifest";
const UPDATE_TARGET: &str = "linux-x86_64";
const UPDATE_CHANNEL: &str = "automatic";
const UPDATE_ASSET_NAME: &str = "codex-desktop-unofficial-x86_64.AppImage";
const UPDATE_MANIFEST_NAME: &str = "codex-linux-x86_64-update.json";
const MAX_CONTRACT_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CONTRACT_APPIMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Independently pinned trust and resource contract compiled into an updater.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateContract {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Release channel accepted by this updater.
    pub channel: String,
    /// Only supported target.
    pub target: String,
    /// Fixed latest-manifest URL.
    pub manifest_url: String,
    /// Exact GitHub `owner/repository` release namespace.
    pub release_repository: String,
    /// Exact AppImage asset name within every release.
    pub artifact_name: String,
    /// Canonical base64 raw Ed25519 verifying key.
    pub public_key_base64: String,
    /// SHA-256 of the raw verifying key.
    pub public_key_sha256: String,
    /// Maximum signed-manifest bytes.
    pub max_manifest_bytes: u64,
    /// Maximum complete AppImage bytes.
    pub max_appimage_bytes: u64,
}

/// Exact downloadable AppImage authenticated by one signed update payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateArtifact {
    /// Fixed release asset name.
    pub name: String,
    /// Exact immutable-tag download URL.
    pub url: String,
    /// Complete AppImage length.
    pub bytes: u64,
    /// SHA-256 of the complete AppImage.
    pub sha256: String,
    /// SHA-256 of the matching AppImage provenance document.
    pub provenance_sha256: String,
}

/// Canonical bytes covered by the release Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePayload {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable signed-payload kind.
    pub kind: String,
    /// Release channel.
    pub channel: String,
    /// Exact supported target.
    pub target: String,
    /// Immutable GitHub release tag.
    pub release_tag: String,
    /// Codex desktop application version.
    pub application_version: String,
    /// Codex desktop application build.
    pub application_build: String,
    /// Exact packager source commit.
    pub source_commit: String,
    /// UTC release timestamp in seconds.
    pub published_at: String,
    /// Complete downloadable AppImage identity.
    pub artifact: UpdateArtifact,
}

/// Signed schema-1 update manifest downloaded by packaged applications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedUpdateManifest {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable signed-envelope kind.
    pub kind: String,
    /// Independently pinned key fingerprint.
    pub key_fingerprint_sha256: String,
    /// Canonical signed release payload.
    pub payload: UpdatePayload,
    /// Canonical base64 Ed25519 signature over `payload` JSON plus newline.
    pub signature_base64: String,
}

/// Application identity embedded in the currently running AppImage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRelease {
    /// Codex desktop application version.
    pub application_version: String,
    /// Codex desktop application build.
    pub application_build: String,
}

/// Proof that a downloaded manifest was canonical and verified by the pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedUpdateManifest {
    /// Strictly verified manifest.
    pub manifest: SignedUpdateManifest,
    /// SHA-256 of the exact canonical signed payload bytes.
    pub signed_payload_sha256: String,
}

/// Inputs for activating one already downloaded and digest-verified AppImage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationRequest {
    /// Absolute path used to launch the currently running AppImage.
    pub current_appimage: PathBuf,
    /// Absolute private replacement path in the same directory.
    pub replacement: PathBuf,
    /// Current Codex desktop version.
    pub current_version: String,
    /// Current Codex desktop build.
    pub current_build: String,
    /// Replacement Codex desktop version.
    pub replacement_version: String,
    /// Replacement Codex desktop build.
    pub replacement_build: String,
    /// Expected complete replacement SHA-256.
    pub replacement_sha256: String,
    /// Expected complete replacement bytes.
    pub replacement_bytes: u64,
}

/// Durable activation receipt for a verified AppImage replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivationReceipt {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable receipt kind.
    pub kind: &'static str,
    /// Truthful publication guarantee scope.
    pub publication_scope: &'static str,
    /// Absolute path now naming the replacement.
    pub current_appimage: PathBuf,
    /// Absolute no-replace path retaining the previous AppImage.
    pub rollback_appimage: PathBuf,
    /// Version activated for the next launch.
    pub replacement_version: String,
    /// Build activated for the next launch.
    pub replacement_build: String,
    /// Complete replacement digest.
    pub replacement_sha256: String,
    /// Complete prior-image digest.
    pub previous_sha256: String,
    /// Linux primitive sequence used for the commit.
    pub commit_primitive: &'static str,
}

/// Public half of a newly generated release-signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateKeyGeneration {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable receipt kind.
    pub kind: &'static str,
    /// Path receiving the raw private seed without replacement.
    pub private_key_path: PathBuf,
    /// Canonical base64 raw Ed25519 public key.
    pub public_key_base64: String,
    /// SHA-256 of the raw public key.
    pub public_key_sha256: String,
    /// Required private-key storage mode.
    pub private_key_mode: &'static str,
}

/// Exact inputs used to sign one immutable AppImage release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateSigningRequest {
    /// Complete verified AppImage.
    pub appimage: PathBuf,
    /// Canonical AppImage provenance emitted by `pack-appimage`.
    pub provenance: PathBuf,
    /// Raw 32-byte Ed25519 seed matching the embedded public pin.
    pub private_key: PathBuf,
    /// Exact 40-character packager source commit.
    pub source_commit: String,
    /// Explicit canonical UTC release timestamp.
    pub published_at: String,
    /// New signed update-manifest path.
    pub output: PathBuf,
}

/// Durable publication receipt for a signed update manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateManifestPublication {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable receipt kind.
    pub kind: &'static str,
    /// New signed-manifest path.
    pub output: PathBuf,
    /// SHA-256 of the exact canonical manifest bytes.
    pub manifest_sha256: String,
    /// Complete signed release metadata.
    pub manifest: SignedUpdateManifest,
}

/// Update metadata validation, signing, or selection failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpdateError {
    /// A compiled or supplied trust contract is invalid.
    #[error("invalid update trust contract: {0}")]
    Contract(String),
    /// Downloaded release metadata is invalid.
    #[error("invalid update manifest: {0}")]
    Manifest(String),
    /// The pinned Ed25519 check failed.
    #[error("update signature verification failed: {0}")]
    Signature(String),
    /// A release identity cannot be compared safely.
    #[error("invalid update release identity: {0}")]
    Release(String),
    /// AppImage validation or atomic activation failed before commit.
    #[error("AppImage update activation failed before commit: {0}")]
    Activation(String),
    /// The atomic name commit succeeded but directory durability is uncertain.
    #[error("AppImage update committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
    /// Release-signing key generation or loading failed.
    #[error("update signing key operation failed: {0}")]
    Key(String),
    /// Release evidence could not be reconciled or published.
    #[error("update manifest signing failed: {0}")]
    Signing(String),
}

/// Parses and validates the release trust root compiled into this source tree.
pub fn embedded_update_contract() -> Result<UpdateContract, UpdateError> {
    let contract: UpdateContract = serde_json::from_str(UPDATE_CONTRACT_JSON)
        .map_err(|error| UpdateError::Contract(format!("parse embedded contract: {error}")))?;
    validate_contract(&contract)?;
    Ok(contract)
}

/// Produces a signed envelope over the canonical schema-1 payload bytes.
pub fn create_signed_update_manifest(
    payload: &UpdatePayload,
    signing_seed: &[u8; 32],
) -> Result<SignedUpdateManifest, UpdateError> {
    validate_payload_identity(payload)?;
    let signing_key = SigningKey::from_bytes(signing_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload_bytes = to_json_line(payload)
        .map_err(|error| UpdateError::Manifest(format!("encode signed payload: {error}")))?;
    let signature = signing_key.sign(payload_bytes.as_bytes()).to_bytes();
    Ok(SignedUpdateManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: SIGNED_UPDATE_KIND.to_owned(),
        key_fingerprint_sha256: hex_lower(&Sha256::digest(public_key)),
        payload: payload.clone(),
        signature_base64: BASE64_STANDARD.encode(signature),
    })
}

/// Verifies canonical envelope bytes with the independently supplied key pin.
pub fn verify_signed_update_manifest(
    bytes: &[u8],
    contract: &UpdateContract,
) -> Result<VerifiedUpdateManifest, UpdateError> {
    let public_key = validate_contract(contract)?;
    let maximum = usize::try_from(contract.max_manifest_bytes)
        .map_err(|_| UpdateError::Contract("manifest bound does not fit this host".to_owned()))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(UpdateError::Manifest(
            "manifest size is outside its configured bound".to_owned(),
        ));
    }
    let manifest: SignedUpdateManifest = serde_json::from_slice(bytes)
        .map_err(|error| UpdateError::Manifest(format!("parse signed JSON: {error}")))?;
    let canonical = to_json_line(&manifest)
        .map_err(|error| UpdateError::Manifest(format!("canonicalize signed JSON: {error}")))?;
    if canonical.as_bytes() != bytes {
        return Err(UpdateError::Manifest(
            "signed manifest is not canonical schema-1 JSON".to_owned(),
        ));
    }
    if manifest.schema != SCHEMA_VERSION
        || manifest.producer != PRODUCER_IDENTIFIER
        || manifest.kind != SIGNED_UPDATE_KIND
    {
        return Err(UpdateError::Manifest(
            "signed envelope identity differs".to_owned(),
        ));
    }
    if manifest.key_fingerprint_sha256 != contract.public_key_sha256 {
        return Err(UpdateError::Signature(
            "envelope key fingerprint differs from the compiled pin".to_owned(),
        ));
    }
    validate_payload_for_contract(&manifest.payload, contract)?;
    let payload_bytes = to_json_line(&manifest.payload)
        .map_err(|error| UpdateError::Manifest(format!("encode signed payload: {error}")))?;
    let signature = decode_canonical::<64>(&manifest.signature_base64, "signature")
        .map_err(UpdateError::Signature)?;
    verify_ed25519_bytes(payload_bytes.as_bytes(), &signature, &public_key)
        .map_err(|error| UpdateError::Signature(error.to_string()))?;

    Ok(VerifiedUpdateManifest {
        manifest,
        signed_payload_sha256: hex_lower(&Sha256::digest(payload_bytes.as_bytes())),
    })
}

/// Returns `true` only when the signed release is strictly newer.
pub fn select_update(
    current: &CurrentRelease,
    candidate: &UpdatePayload,
) -> Result<bool, UpdateError> {
    validate_release(
        &current.application_version,
        &current.application_build,
        "current release",
    )?;
    validate_release(
        &candidate.application_version,
        &candidate.application_build,
        "candidate release",
    )?;
    let version_order =
        compare_dotted_numeric(&candidate.application_version, &current.application_version);
    if version_order != Ordering::Equal {
        return Ok(version_order == Ordering::Greater);
    }
    Ok(
        compare_numeric_text(&candidate.application_build, &current.application_build)
            == Ordering::Greater,
    )
}

/// Generates a fresh raw Ed25519 seed in a mode-0600, no-replace file while
/// returning only the public key and fingerprint.
pub fn generate_update_signing_key(path: &Path) -> Result<UpdateKeyGeneration, UpdateError> {
    validate_absolute_normal_path(path, "private update key")
        .map_err(|error| UpdateError::Key(error.to_string()))?;
    let parent_path = path
        .parent()
        .ok_or_else(|| UpdateError::Key("private key path has no parent".to_owned()))?;
    let name = path
        .file_name()
        .ok_or_else(|| UpdateError::Key("private key path has no filename".to_owned()))?;
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdateError::Key(format!(
            "open private key parent without following a final symlink: {error}"
        ))
    })?;
    let mut seed = [0_u8; 32];
    getrandom(&mut seed, GetRandomFlags::empty())
        .map_err(|error| UpdateError::Key(format!("obtain signing-key entropy: {error}")))?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        UpdateError::Key(format!(
            "create private key with no replacement (parent must already exist): {error}"
        ))
    })?;
    let metadata = fstat(&descriptor)
        .map_err(|error| UpdateError::Key(format!("inspect new private key: {error}")))?;
    let identity = FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        bytes: 0,
        mode: metadata.st_mode,
    };
    let mut file = File::from(descriptor);
    let write_result = (|| -> Result<(), UpdateError> {
        fchmod(&file, Mode::from_raw_mode(0o600))
            .map_err(|error| UpdateError::Key(format!("set private key mode: {error}")))?;
        file.write_all(&seed)
            .map_err(|error| UpdateError::Key(format!("write private key: {error}")))?;
        file.sync_all()
            .map_err(|error| UpdateError::Key(format!("fsync private key: {error}")))?;
        fsync(&parent)
            .map_err(|error| UpdateError::Key(format!("fsync private key parent: {error}")))
    })();
    if let Err(error) = write_result {
        let cleanup = cleanup_created_name(&parent, name, &identity);
        seed.fill(0);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(UpdateError::Key(format!(
                "{error}; safe key cleanup was refused: {cleanup}"
            ))),
        };
    }
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let public_key = signing_key.verifying_key().to_bytes();
    Ok(UpdateKeyGeneration {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_update_key_generation",
        private_key_path: path.to_owned(),
        public_key_base64: BASE64_STANDARD.encode(public_key),
        public_key_sha256: hex_lower(&Sha256::digest(public_key)),
        private_key_mode: "0600",
    })
}

/// Reconciles an exact AppImage with canonical provenance, signs its immutable
/// release identity with the independently pinned key, and publishes the
/// schema-1 manifest without replacement.
pub fn sign_update_release(
    request: &UpdateSigningRequest,
) -> Result<UpdateManifestPublication, UpdateError> {
    for (path, label) in [
        (&request.appimage, "AppImage"),
        (&request.provenance, "AppImage provenance"),
        (&request.private_key, "private update key"),
        (&request.output, "signed manifest output"),
    ] {
        validate_absolute_normal_path(path, label)
            .map_err(|error| UpdateError::Signing(error.to_string()))?;
    }
    if request.output == request.appimage
        || request.output == request.provenance
        || request.output == request.private_key
    {
        return Err(UpdateError::Signing(
            "signed manifest output aliases an input".to_owned(),
        ));
    }
    let contract =
        embedded_update_contract().map_err(|error| UpdateError::Signing(error.to_string()))?;
    let provenance_bytes = read_bounded_regular_input(
        &request.provenance,
        4 * 1024 * 1024,
        0o644,
        "AppImage provenance",
    )?;
    let provenance: AppImageManifest = serde_json::from_slice(&provenance_bytes)
        .map_err(|error| UpdateError::Signing(format!("parse AppImage provenance: {error}")))?;
    let canonical_provenance = to_json_line(&provenance).map_err(|error| {
        UpdateError::Signing(format!("canonicalize AppImage provenance: {error}"))
    })?;
    if canonical_provenance.as_bytes() != provenance_bytes {
        return Err(UpdateError::Signing(
            "AppImage provenance is not canonical schema-1 JSON".to_owned(),
        ));
    }
    if provenance.schema != SCHEMA_VERSION
        || provenance.producer != PRODUCER_IDENTIFIER
        || provenance.kind != "linux_x86_64_appimage"
        || provenance.artifact.path != contract.artifact_name
        || provenance.artifact.mode != "0755"
    {
        return Err(UpdateError::Signing(
            "AppImage provenance identity differs from the release contract".to_owned(),
        ));
    }
    validate_release(
        &provenance.application_version,
        &provenance.application_build,
        "AppImage provenance release",
    )?;

    let mut image = open_regular(&request.appimage, false, "release AppImage")
        .map_err(|error| UpdateError::Signing(error.to_string()))?;
    let image_identity = file_identity(&image, "release AppImage")
        .map_err(|error| UpdateError::Signing(error.to_string()))?;
    if image_identity.bytes > contract.max_appimage_bytes || image_identity.mode & 0o7777 != 0o755 {
        return Err(UpdateError::Signing(
            "release AppImage exceeds its bound or is not mode 0755".to_owned(),
        ));
    }
    let (image_sha256, image_prefix) =
        hash_regular(&mut image, image_identity.bytes, "release AppImage")
            .map_err(|error| UpdateError::Signing(error.to_string()))?;
    validate_type2_appimage_prefix(&image_prefix, "release AppImage")
        .map_err(|error| UpdateError::Signing(error.to_string()))?;
    if provenance.artifact.sha256 != image_sha256
        || provenance.artifact.bytes != image_identity.bytes
    {
        return Err(UpdateError::Signing(
            "complete AppImage differs from its provenance identity".to_owned(),
        ));
    }
    let mut private_seed =
        read_bounded_regular_input(&request.private_key, 32, 0o600, "private update key")?;
    let mut seed: [u8; 32] = private_seed.as_slice().try_into().map_err(|_| {
        UpdateError::Signing("private update key is not exactly 32 bytes".to_owned())
    })?;
    private_seed.fill(0);
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if BASE64_STANDARD.encode(public_key) != contract.public_key_base64
        || hex_lower(&Sha256::digest(public_key)) != contract.public_key_sha256
    {
        seed.fill(0);
        return Err(UpdateError::Signing(
            "private update key does not match the embedded public pin".to_owned(),
        ));
    }
    let release_tag = format!(
        "codex-app-{}-{}",
        provenance.application_version, provenance.application_build
    );
    let payload = UpdatePayload {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: UPDATE_PAYLOAD_KIND.to_owned(),
        channel: contract.channel.clone(),
        target: contract.target.clone(),
        release_tag: release_tag.clone(),
        application_version: provenance.application_version.clone(),
        application_build: provenance.application_build.clone(),
        source_commit: request.source_commit.clone(),
        published_at: request.published_at.clone(),
        artifact: UpdateArtifact {
            name: contract.artifact_name.clone(),
            url: format!(
                "https://github.com/{}/releases/download/{release_tag}/{}",
                contract.release_repository, contract.artifact_name
            ),
            bytes: image_identity.bytes,
            sha256: image_sha256,
            provenance_sha256: hex_lower(&Sha256::digest(&provenance_bytes)),
        },
    };
    let manifest_result = create_signed_update_manifest(&payload, &seed);
    seed.fill(0);
    let manifest = manifest_result?;
    let encoded = to_json_line(&manifest)
        .map_err(|error| UpdateError::Signing(format!("encode signed update manifest: {error}")))?;
    verify_signed_update_manifest(encoded.as_bytes(), &contract)
        .map_err(|error| UpdateError::Signing(format!("self-verify signed manifest: {error}")))?;
    publish_regular_no_replace(&request.output, encoded.as_bytes(), 0o644)?;
    Ok(UpdateManifestPublication {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_update_manifest_publication",
        output: request.output.clone(),
        manifest_sha256: hex_lower(&Sha256::digest(encoded.as_bytes())),
        manifest,
    })
}

/// Atomically exchanges a verified replacement with the current AppImage and
/// publishes the old bytes under a no-replace rollback name.
pub fn activate_appimage(request: &ActivationRequest) -> Result<ActivationReceipt, UpdateError> {
    validate_activation_request(request)?;
    let parent_path = request
        .current_appimage
        .parent()
        .ok_or_else(|| UpdateError::Activation("current path has no parent".to_owned()))?;
    let current_name = request
        .current_appimage
        .file_name()
        .ok_or_else(|| UpdateError::Activation("current path has no filename".to_owned()))?;
    let replacement_name = request
        .replacement
        .file_name()
        .ok_or_else(|| UpdateError::Activation("replacement path has no filename".to_owned()))?;
    let current_name_utf8 = current_name
        .to_str()
        .ok_or_else(|| UpdateError::Activation("current filename is not UTF-8".to_owned()))?;
    if matches!(current_name_utf8, "." | "..") {
        return Err(UpdateError::Activation(
            "current filename is a dot component".to_owned(),
        ));
    }
    let rollback_name = OsString::from(format!(
        "{current_name_utf8}.rollback-{}-{}",
        request.current_version, request.current_build
    ));
    let rollback_path = parent_path.join(&rollback_name);

    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdateError::Activation(format!(
            "open AppImage parent without following a final symlink: {error}"
        ))
    })?;
    require_absent(&parent, &rollback_name, "rollback destination")?;

    let mut current = open_regular(&request.current_appimage, false, "current AppImage")?;
    let mut replacement = open_regular(&request.replacement, true, "replacement AppImage")?;
    let current_identity = file_identity(&current, "current AppImage")?;
    let replacement_identity = file_identity(&replacement, "replacement AppImage")?;
    if current_identity.device == replacement_identity.device
        && current_identity.inode == replacement_identity.inode
    {
        return Err(UpdateError::Activation(
            "current and replacement AppImages alias one inode".to_owned(),
        ));
    }
    if replacement_identity.bytes != request.replacement_bytes {
        return Err(UpdateError::Activation(
            "replacement length differs from its signed manifest".to_owned(),
        ));
    }
    let (previous_sha256, current_prefix) =
        hash_regular(&mut current, current_identity.bytes, "current AppImage")?;
    let (replacement_sha256, replacement_prefix) = hash_regular(
        &mut replacement,
        replacement_identity.bytes,
        "replacement AppImage",
    )?;
    validate_type2_appimage_prefix(&current_prefix, "current AppImage")?;
    validate_type2_appimage_prefix(&replacement_prefix, "replacement AppImage")?;
    if replacement_sha256 != request.replacement_sha256 {
        return Err(UpdateError::Activation(
            "replacement digest differs from its signed manifest".to_owned(),
        ));
    }
    validate_name_identity(&parent, current_name, &current_identity, "current AppImage")?;
    validate_name_identity(
        &parent,
        replacement_name,
        &replacement_identity,
        "replacement AppImage",
    )?;

    let replacement_original_mode = replacement_identity.mode;
    fchmod(&replacement, Mode::from_raw_mode(0o755)).map_err(|error| {
        UpdateError::Activation(format!("set replacement executable mode: {error}"))
    })?;
    replacement.sync_all().map_err(|error| {
        let _ = fchmod(
            &replacement,
            Mode::from_raw_mode(replacement_original_mode & 0o7777),
        );
        UpdateError::Activation(format!("fsync executable replacement: {error}"))
    })?;

    if let Err(error) = renameat_with(
        &parent,
        current_name,
        &parent,
        replacement_name,
        RenameFlags::EXCHANGE,
    ) {
        let _ = fchmod(
            &replacement,
            Mode::from_raw_mode(replacement_original_mode & 0o7777),
        );
        return Err(UpdateError::Activation(format!(
            "atomically exchange current and replacement AppImages: {error}"
        )));
    }
    if let Err(error) = validate_exchanged_names(
        &parent,
        current_name,
        replacement_name,
        &current_identity,
        &replacement_identity,
    )
    .and_then(|()| {
        renameat_with(
            &parent,
            replacement_name,
            &parent,
            &rollback_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            UpdateError::Activation(format!("publish prior AppImage as rollback: {error}"))
        })
    }) {
        return Err(rollback_exchange(
            &parent,
            current_name,
            replacement_name,
            &replacement,
            replacement_original_mode,
            error,
        ));
    }
    fsync(&parent).map_err(|error| {
        UpdateError::PostCommitDurability(format!(
            "fsync AppImage parent after exchange and rollback publication: {error}"
        ))
    })?;

    Ok(ActivationReceipt {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_appimage_activation",
        publication_scope: "bytes_at_durable_commit_boundary_under_documented_threat_model",
        current_appimage: request.current_appimage.clone(),
        rollback_appimage: rollback_path,
        replacement_version: request.replacement_version.clone(),
        replacement_build: request.replacement_build.clone(),
        replacement_sha256,
        previous_sha256,
        commit_primitive: "renameat2_RENAME_EXCHANGE_then_no_replace_rollback_publish",
    })
}

#[derive(Debug, Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
}

fn validate_activation_request(request: &ActivationRequest) -> Result<(), UpdateError> {
    validate_absolute_normal_path(&request.current_appimage, "current AppImage")?;
    validate_absolute_normal_path(&request.replacement, "replacement AppImage")?;
    if request.current_appimage == request.replacement
        || request.current_appimage.parent() != request.replacement.parent()
    {
        return Err(UpdateError::Activation(
            "current and replacement must be distinct names in one directory".to_owned(),
        ));
    }
    validate_release(
        &request.current_version,
        &request.current_build,
        "current activation release",
    )?;
    validate_release(
        &request.replacement_version,
        &request.replacement_build,
        "replacement activation release",
    )?;
    let version_order =
        compare_dotted_numeric(&request.replacement_version, &request.current_version);
    let build_order = compare_numeric_text(&request.replacement_build, &request.current_build);
    if version_order == Ordering::Less
        || (version_order == Ordering::Equal && build_order != Ordering::Greater)
    {
        return Err(UpdateError::Activation(
            "replacement release is not strictly newer".to_owned(),
        ));
    }
    validate_digest(&request.replacement_sha256, "replacement SHA-256")
        .map_err(UpdateError::Activation)?;
    if request.replacement_bytes == 0 || request.replacement_bytes > MAX_CONTRACT_APPIMAGE_BYTES {
        return Err(UpdateError::Activation(
            "replacement byte length is outside the implementation bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_absolute_normal_path(path: &Path, label: &str) -> Result<(), UpdateError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir))
        || components.clone().count() < 2
        || !components.all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(UpdateError::Activation(format!(
            "{label} path must be absolute and lexically normalized"
        )));
    }
    Ok(())
}

fn open_regular(path: &Path, writable: bool, label: &str) -> Result<File, UpdateError> {
    let mut flags = OFlags::CLOEXEC | OFlags::NOFOLLOW;
    flags |= if writable {
        OFlags::RDWR
    } else {
        OFlags::RDONLY
    };
    let descriptor = open(path, flags, Mode::empty())
        .map_err(|error| UpdateError::Activation(format!("open {label}: {error}")))?;
    let metadata = fstat(&descriptor)
        .map_err(|error| UpdateError::Activation(format!("inspect {label}: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(UpdateError::Activation(format!(
            "{label} is not a regular file"
        )));
    }
    Ok(File::from(descriptor))
}

fn file_identity(file: &File, label: &str) -> Result<FileIdentity, UpdateError> {
    let metadata = fstat(file)
        .map_err(|error| UpdateError::Activation(format!("inspect {label}: {error}")))?;
    let bytes = u64::try_from(metadata.st_size)
        .map_err(|_| UpdateError::Activation(format!("{label} size is negative")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || bytes == 0
        || bytes > MAX_CONTRACT_APPIMAGE_BYTES
    {
        return Err(UpdateError::Activation(format!(
            "{label} is not a bounded regular file"
        )));
    }
    Ok(FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        bytes,
        mode: metadata.st_mode,
    })
}

fn hash_regular(
    file: &mut File,
    expected_bytes: u64,
    label: &str,
) -> Result<(String, [u8; 20]), UpdateError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| UpdateError::Activation(format!("rewind {label}: {error}")))?;
    let mut hasher = Sha256::new();
    let mut prefix = [0_u8; 20];
    let mut prefix_bytes = 0_usize;
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| UpdateError::Activation(format!("read {label}: {error}")))?;
        if count == 0 {
            break;
        }
        let count_u64 = u64::try_from(count)
            .map_err(|_| UpdateError::Activation(format!("{label} chunk is too large")))?;
        total = total
            .checked_add(count_u64)
            .ok_or_else(|| UpdateError::Activation(format!("{label} length overflowed")))?;
        if total > expected_bytes {
            return Err(UpdateError::Activation(format!(
                "{label} grew while being hashed"
            )));
        }
        if prefix_bytes < prefix.len() {
            let copied = (prefix.len() - prefix_bytes).min(count);
            prefix[prefix_bytes..prefix_bytes + copied].copy_from_slice(&buffer[..copied]);
            prefix_bytes += copied;
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected_bytes || prefix_bytes != prefix.len() {
        return Err(UpdateError::Activation(format!(
            "{label} changed length while being hashed"
        )));
    }
    let after = file_identity(file, label)?;
    if after.bytes != expected_bytes {
        return Err(UpdateError::Activation(format!(
            "{label} identity changed while being hashed"
        )));
    }
    Ok((hex_lower(&hasher.finalize()), prefix))
}

fn validate_type2_appimage_prefix(prefix: &[u8; 20], label: &str) -> Result<(), UpdateError> {
    if prefix.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || prefix.get(8..12) != Some(b"AI\x02\0")
        || prefix.get(18..20) != Some(&62_u16.to_le_bytes())
    {
        return Err(UpdateError::Activation(format!(
            "{label} is not a Linux x86_64 Type-2 AppImage"
        )));
    }
    Ok(())
}

fn require_absent(parent: &OwnedFd, name: &OsStr, label: &str) -> Result<(), UpdateError> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(_) => Err(UpdateError::Activation(format!(
            "{label} already exists and will not be replaced"
        ))),
        Err(error) => Err(UpdateError::Activation(format!("inspect {label}: {error}"))),
    }
}

fn validate_name_identity(
    parent: &OwnedFd,
    name: &OsStr,
    expected: &FileIdentity,
    label: &str,
) -> Result<(), UpdateError> {
    let metadata = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| UpdateError::Activation(format!("reinspect {label} name: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_dev != expected.device
        || metadata.st_ino != expected.inode
        || u64::try_from(metadata.st_size).ok() != Some(expected.bytes)
    {
        return Err(UpdateError::Activation(format!(
            "{label} pathname was substituted"
        )));
    }
    Ok(())
}

fn validate_exchanged_names(
    parent: &OwnedFd,
    current_name: &OsStr,
    replacement_name: &OsStr,
    previous: &FileIdentity,
    replacement: &FileIdentity,
) -> Result<(), UpdateError> {
    validate_name_identity(parent, current_name, replacement, "exchanged replacement")?;
    validate_name_identity(
        parent,
        replacement_name,
        previous,
        "exchanged prior AppImage",
    )
}

fn rollback_exchange(
    parent: &OwnedFd,
    current_name: &OsStr,
    replacement_name: &OsStr,
    replacement: &File,
    replacement_original_mode: u32,
    cause: UpdateError,
) -> UpdateError {
    match renameat_with(
        parent,
        current_name,
        parent,
        replacement_name,
        RenameFlags::EXCHANGE,
    ) {
        Ok(()) => {
            let mode_result = fchmod(
                replacement,
                Mode::from_raw_mode(replacement_original_mode & 0o7777),
            );
            let sync_result = fsync(parent);
            if mode_result.is_ok() && sync_result.is_ok() {
                UpdateError::Activation(format!("{cause}; atomic exchange was rolled back"))
            } else {
                UpdateError::Activation(format!(
                    "{cause}; exchange was rolled back but mode or directory durability restoration failed"
                ))
            }
        }
        Err(rollback) => UpdateError::Activation(format!(
            "{cause}; CRITICAL: atomic rollback exchange failed: {rollback}"
        )),
    }
}

fn cleanup_created_name(
    parent: &OwnedFd,
    name: &OsStr,
    expected: &FileIdentity,
) -> Result<(), UpdateError> {
    let metadata = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| UpdateError::Key(format!("inspect owned key for cleanup: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_dev != expected.device
        || metadata.st_ino != expected.inode
    {
        return Err(UpdateError::Key(
            "created key name was substituted".to_owned(),
        ));
    }
    unlinkat(parent, name, AtFlags::empty())
        .map_err(|error| UpdateError::Key(format!("remove owned incomplete key: {error}")))
}

fn read_bounded_regular_input(
    path: &Path,
    maximum: u64,
    expected_mode: u32,
    label: &str,
) -> Result<Vec<u8>, UpdateError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| UpdateError::Signing(format!("open {label}: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| UpdateError::Signing(format!("inspect {label}: {error}")))?;
    let bytes = u64::try_from(before.st_size)
        .map_err(|_| UpdateError::Signing(format!("{label} size is negative")))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || bytes == 0
        || bytes > maximum
        || before.st_mode & 0o7777 != expected_mode
    {
        return Err(UpdateError::Signing(format!(
            "{label} has the wrong type, size, or mode"
        )));
    }
    let capacity = usize::try_from(bytes)
        .map_err(|_| UpdateError::Signing(format!("{label} does not fit this host")))?;
    let mut file = File::from(descriptor);
    let mut content = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(bytes.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|error| UpdateError::Signing(format!("read {label}: {error}")))?;
    let after = fstat(&file)
        .map_err(|error| UpdateError::Signing(format!("reinspect {label}: {error}")))?;
    if content.len() != capacity
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(UpdateError::Signing(format!(
            "{label} identity changed while reading"
        )));
    }
    Ok(content)
}

fn publish_regular_no_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), UpdateError> {
    let parent_path = path
        .parent()
        .ok_or_else(|| UpdateError::Signing("manifest output has no parent".to_owned()))?;
    let name = path
        .file_name()
        .ok_or_else(|| UpdateError::Signing("manifest output has no filename".to_owned()))?;
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdateError::Signing(format!(
            "open manifest output parent without following a final symlink: {error}"
        ))
    })?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(mode),
    )
    .map_err(|error| {
        UpdateError::Signing(format!(
            "create signed manifest without replacement: {error}"
        ))
    })?;
    let metadata = fstat(&descriptor)
        .map_err(|error| UpdateError::Signing(format!("inspect new signed manifest: {error}")))?;
    let identity = FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        bytes: 0,
        mode: metadata.st_mode,
    };
    let mut file = File::from(descriptor);
    let result = (|| -> Result<(), UpdateError> {
        fchmod(&file, Mode::from_raw_mode(mode))
            .map_err(|error| UpdateError::Signing(format!("set signed manifest mode: {error}")))?;
        file.write_all(bytes)
            .map_err(|error| UpdateError::Signing(format!("write signed manifest: {error}")))?;
        file.sync_all()
            .map_err(|error| UpdateError::Signing(format!("fsync signed manifest: {error}")))?;
        fsync(&parent)
            .map_err(|error| UpdateError::Signing(format!("fsync manifest parent: {error}")))
    })();
    if let Err(error) = result {
        let cleanup = cleanup_created_regular(&parent, name, &identity);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(UpdateError::Signing(format!(
                "{error}; safe manifest cleanup was refused: {cleanup}"
            ))),
        };
    }
    Ok(())
}

fn cleanup_created_regular(
    parent: &OwnedFd,
    name: &OsStr,
    expected: &FileIdentity,
) -> Result<(), UpdateError> {
    let metadata = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| UpdateError::Signing(format!("inspect publication cleanup: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_dev != expected.device
        || metadata.st_ino != expected.inode
    {
        return Err(UpdateError::Signing(
            "signed manifest output was substituted".to_owned(),
        ));
    }
    unlinkat(parent, name, AtFlags::empty())
        .map_err(|error| UpdateError::Signing(format!("remove incomplete manifest: {error}")))
}

fn validate_contract(contract: &UpdateContract) -> Result<[u8; 32], UpdateError> {
    if contract.schema != SCHEMA_VERSION
        || contract.producer != PRODUCER_IDENTIFIER
        || contract.kind != UPDATE_CONTRACT_KIND
        || contract.channel != UPDATE_CHANNEL
        || contract.target != UPDATE_TARGET
        || contract.artifact_name != UPDATE_ASSET_NAME
    {
        return Err(UpdateError::Contract(
            "schema, producer, kind, channel, target, or asset name differs".to_owned(),
        ));
    }
    validate_repository(&contract.release_repository)?;
    let expected_manifest_url = format!(
        "https://github.com/{}/releases/latest/download/{UPDATE_MANIFEST_NAME}",
        contract.release_repository
    );
    if contract.manifest_url != expected_manifest_url {
        return Err(UpdateError::Contract(
            "manifest URL is not the exact fixed GitHub release URL".to_owned(),
        ));
    }
    if !(1..=MAX_CONTRACT_MANIFEST_BYTES).contains(&contract.max_manifest_bytes)
        || !(1..=MAX_CONTRACT_APPIMAGE_BYTES).contains(&contract.max_appimage_bytes)
    {
        return Err(UpdateError::Contract(
            "resource bounds are empty or exceed implementation limits".to_owned(),
        ));
    }
    validate_digest(&contract.public_key_sha256, "public key fingerprint")
        .map_err(UpdateError::Contract)?;
    let public_key = decode_canonical::<32>(&contract.public_key_base64, "public key")
        .map_err(UpdateError::Contract)?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| UpdateError::Contract("public key is not a valid Ed25519 key".to_owned()))?;
    if hex_lower(&Sha256::digest(public_key)) != contract.public_key_sha256 {
        return Err(UpdateError::Contract(
            "public key does not match its pinned fingerprint".to_owned(),
        ));
    }
    Ok(public_key)
}

fn validate_payload_for_contract(
    payload: &UpdatePayload,
    contract: &UpdateContract,
) -> Result<(), UpdateError> {
    validate_payload_identity(payload)?;
    if payload.channel != contract.channel
        || payload.target != contract.target
        || payload.artifact.name != contract.artifact_name
        || payload.artifact.bytes > contract.max_appimage_bytes
    {
        return Err(UpdateError::Manifest(
            "payload channel, target, asset, or resource bound differs".to_owned(),
        ));
    }
    let expected_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        contract.release_repository, payload.release_tag, payload.artifact.name
    );
    if payload.artifact.url != expected_url {
        return Err(UpdateError::Manifest(
            "artifact URL is not exact for the immutable release tag".to_owned(),
        ));
    }
    Ok(())
}

fn validate_payload_identity(payload: &UpdatePayload) -> Result<(), UpdateError> {
    if payload.schema != SCHEMA_VERSION
        || payload.producer != PRODUCER_IDENTIFIER
        || payload.kind != UPDATE_PAYLOAD_KIND
        || payload.channel != UPDATE_CHANNEL
        || payload.target != UPDATE_TARGET
        || payload.artifact.name != UPDATE_ASSET_NAME
    {
        return Err(UpdateError::Manifest(
            "signed payload identity differs".to_owned(),
        ));
    }
    validate_release(
        &payload.application_version,
        &payload.application_build,
        "payload release",
    )?;
    let expected_tag = format!(
        "codex-app-{}-{}",
        payload.application_version, payload.application_build
    );
    if payload.release_tag != expected_tag {
        return Err(UpdateError::Manifest(
            "release tag differs from application version/build".to_owned(),
        ));
    }
    if payload.source_commit.len() != 40
        || !payload
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpdateError::Manifest(
            "source commit is not 40 lowercase hexadecimal characters".to_owned(),
        ));
    }
    if !is_canonical_utc_timestamp(&payload.published_at) {
        return Err(UpdateError::Manifest(
            "published timestamp is not canonical UTC seconds".to_owned(),
        ));
    }
    if payload.artifact.bytes == 0 {
        return Err(UpdateError::Manifest(
            "artifact byte length must be positive".to_owned(),
        ));
    }
    validate_digest(&payload.artifact.sha256, "artifact SHA-256").map_err(UpdateError::Manifest)?;
    validate_digest(&payload.artifact.provenance_sha256, "provenance SHA-256")
        .map_err(UpdateError::Manifest)?;
    Ok(())
}

fn validate_release(version: &str, build: &str, label: &str) -> Result<(), UpdateError> {
    if !is_dotted_numeric(version)
        || build.is_empty()
        || build.len() > 32
        || !build.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(UpdateError::Release(format!(
            "{label} version/build is not bounded dotted-numeric identity"
        )));
    }
    Ok(())
}

fn is_dotted_numeric(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.contains('.')
        && value.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 20
                && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn compare_dotted_numeric(left: &str, right: &str) -> Ordering {
    let mut left_components = left.split('.');
    let mut right_components = right.split('.');
    loop {
        match (left_components.next(), right_components.next()) {
            (Some(left_component), Some(right_component)) => {
                let order = compare_numeric_text(left_component, right_component);
                if order != Ordering::Equal {
                    return order;
                }
            }
            (Some(left_component), None) => {
                if compare_numeric_text(left_component, "0") != Ordering::Equal
                    || left_components
                        .any(|component| compare_numeric_text(component, "0") != Ordering::Equal)
                {
                    return Ordering::Greater;
                }
                return Ordering::Equal;
            }
            (None, Some(right_component)) => {
                if compare_numeric_text(right_component, "0") != Ordering::Equal
                    || right_components
                        .any(|component| compare_numeric_text(component, "0") != Ordering::Equal)
                {
                    return Ordering::Less;
                }
                return Ordering::Equal;
            }
            (None, None) => return Ordering::Equal,
        }
    }
}

fn compare_numeric_text(left: &str, right: &str) -> Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn validate_repository(repository: &str) -> Result<(), UpdateError> {
    let mut components = repository.split('/');
    let owner = components.next().unwrap_or_default();
    let name = components.next().unwrap_or_default();
    if components.next().is_some()
        || !is_repository_component(owner)
        || !is_repository_component(name)
    {
        return Err(UpdateError::Contract(
            "release repository is not a safe owner/name".to_owned(),
        ));
    }
    Ok(())
}

fn is_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
        && value != "."
        && value != ".."
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} is not 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn decode_canonical<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = BASE64_STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| format!("{label} is not canonical base64"))?;
    let decoded: [u8; N] = decoded
        .try_into()
        .map_err(|_| format!("{label} has the wrong decoded length"))?;
    if BASE64_STANDARD.encode(decoded) != encoded {
        return Err(format!("{label} is not canonical base64"));
    }
    Ok(decoded)
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
