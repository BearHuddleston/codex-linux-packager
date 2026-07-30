//! Runtime self-update orchestration for packaged Linux x86_64 AppImages.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, fchmod, flock, fstat, open, openat, statat,
    unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use ureq::Agent;
use ureq::ResponseExt as _;

use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use crate::update::{
    ActivationReceipt, ActivationRequest, CurrentRelease, UpdateContract, UpdateError,
    activate_appimage, embedded_update_contract, select_update, verify_signed_update_manifest,
};

const UPDATE_CONFIG_KIND: &str = "linux_x86_64_runtime_update_config";
const UPDATE_BEHAVIOR: &str =
    "background_full_download_activate_for_next_launch_keep_versioned_rollback";

/// Immutable release identity and trust references embedded in one AppDir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRuntimeConfig {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: String,
    /// Stable document kind.
    pub kind: String,
    /// Accepted release channel.
    pub channel: String,
    /// Exact supported target.
    pub target: String,
    /// Current Codex desktop version.
    pub application_version: String,
    /// Current Codex desktop build.
    pub application_build: String,
    /// Fixed signed-manifest URL.
    pub manifest_url: String,
    /// Fingerprint of the independently compiled release key.
    pub public_key_sha256: String,
    /// Truthful background activation behavior.
    pub behavior: String,
}

/// Packaged update configuration or runtime failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UpdaterError {
    /// Embedded or AppDir configuration is invalid.
    #[error("invalid packaged updater configuration: {0}")]
    Config(String),
    /// HTTPS or HTTP response validation failed.
    #[error("update transport failed: {0}")]
    Network(String),
    /// Private download construction or cleanup failed.
    #[error("update download transaction failed: {0}")]
    Transaction(String),
    /// Another updater owns the adjacent advisory lock.
    #[error("another updater is already running")]
    AlreadyRunning,
    /// Signed update metadata or atomic activation failed.
    #[error("verified AppImage update failed: {0}")]
    Update(String),
}

/// Auditable facts for one accepted update response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateTransportReceipt {
    /// Exact final URL after tightly constrained redirects.
    pub final_url: String,
    /// Accepted media type.
    pub content_type: String,
    /// Complete response bytes.
    pub bytes: u64,
}

/// Result of one packaged background update attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateRunReport {
    /// Rust-owned schema.
    pub schema: u32,
    /// Unambiguous producer.
    pub producer: &'static str,
    /// Stable report kind.
    pub kind: &'static str,
    /// `current`, `already_running`, or `updated_for_next_launch`.
    pub action: &'static str,
    /// Release that was running when the check began.
    pub current_release: CurrentRelease,
    /// Strictly newer signed release, when available.
    pub candidate_release: Option<CurrentRelease>,
    /// Accepted signed-manifest transport facts.
    pub manifest_response: Option<UpdateTransportReceipt>,
    /// Accepted complete AppImage transport facts.
    pub artifact_response: Option<UpdateTransportReceipt>,
    /// Atomic activation proof when a replacement was installed.
    pub activation: Option<ActivationReceipt>,
}

struct BoundedDownload {
    bytes: Vec<u8>,
    receipt: UpdateTransportReceipt,
}

struct PrivateAsset {
    name: OsString,
    path: PathBuf,
    identity: DownloadIdentity,
    receipt: UpdateTransportReceipt,
}

#[derive(Debug, Clone, Copy)]
struct DownloadIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
}

/// Constructs the deterministic updater config embedded beside one runtime.
pub fn create_runtime_update_config(
    application_version: &str,
    application_build: &str,
) -> Result<UpdateRuntimeConfig, UpdaterError> {
    let contract =
        embedded_update_contract().map_err(|error| UpdaterError::Config(error.to_string()))?;
    let config = UpdateRuntimeConfig {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: UPDATE_CONFIG_KIND.to_owned(),
        channel: contract.channel.clone(),
        target: contract.target.clone(),
        application_version: application_version.to_owned(),
        application_build: application_build.to_owned(),
        manifest_url: contract.manifest_url.clone(),
        public_key_sha256: contract.public_key_sha256.clone(),
        behavior: UPDATE_BEHAVIOR.to_owned(),
    };
    validate_runtime_update_config(&config, &contract)?;
    Ok(config)
}

/// Checks that AppDir configuration cannot rotate or redirect compiled trust.
pub fn validate_runtime_update_config(
    config: &UpdateRuntimeConfig,
    contract: &UpdateContract,
) -> Result<(), UpdaterError> {
    if config.schema != SCHEMA_VERSION
        || config.producer != PRODUCER_IDENTIFIER
        || config.kind != UPDATE_CONFIG_KIND
        || config.channel != contract.channel
        || config.target != contract.target
        || config.manifest_url != contract.manifest_url
        || config.public_key_sha256 != contract.public_key_sha256
        || config.behavior != UPDATE_BEHAVIOR
    {
        return Err(UpdaterError::Config(
            "schema, identity, URL, key pin, or behavior differs".to_owned(),
        ));
    }
    validate_release(&config.application_version, &config.application_build)?;
    Ok(())
}

/// Checks the pinned release channel, downloads and authenticates a complete
/// newer AppImage, and atomically installs it for the next launch.
pub fn run_packaged_update(
    current_appimage: &Path,
    config_path: &Path,
) -> Result<UpdateRunReport, UpdaterError> {
    let contract =
        embedded_update_contract().map_err(|error| UpdaterError::Config(error.to_string()))?;
    let config = read_runtime_config(config_path, &contract)?;
    let current_release = CurrentRelease {
        application_version: config.application_version.clone(),
        application_build: config.application_build.clone(),
    };
    let _lock = match acquire_update_lock(current_appimage) {
        Ok(lock) => lock,
        Err(UpdaterError::AlreadyRunning) => {
            return Ok(UpdateRunReport {
                schema: SCHEMA_VERSION,
                producer: PRODUCER_IDENTIFIER,
                kind: "linux_x86_64_update_run",
                action: "already_running",
                current_release,
                candidate_release: None,
                manifest_response: None,
                artifact_response: None,
                activation: None,
            });
        }
        Err(error) => return Err(error),
    };
    let downloaded_manifest =
        download_bounded_bytes(&contract.manifest_url, contract.max_manifest_bytes, true)?;
    let verified = verify_signed_update_manifest(&downloaded_manifest.bytes, &contract)
        .map_err(|error| UpdaterError::Update(error.to_string()))?;
    let candidate_release = CurrentRelease {
        application_version: verified.manifest.payload.application_version.clone(),
        application_build: verified.manifest.payload.application_build.clone(),
    };
    if !select_update(&current_release, &verified.manifest.payload)
        .map_err(|error| UpdaterError::Update(error.to_string()))?
    {
        return Ok(UpdateRunReport {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER,
            kind: "linux_x86_64_update_run",
            action: "current",
            current_release,
            candidate_release: Some(candidate_release),
            manifest_response: Some(downloaded_manifest.receipt),
            artifact_response: None,
            activation: None,
        });
    }
    let parent = current_appimage.parent().ok_or_else(|| {
        UpdaterError::Config("current AppImage path has no parent directory".to_owned())
    })?;
    let payload = &verified.manifest.payload;
    let downloaded_asset = download_verified_asset(
        &payload.artifact.url,
        payload.artifact.bytes,
        &payload.artifact.sha256,
        parent,
        true,
    )?;
    let request = ActivationRequest {
        current_appimage: current_appimage.to_owned(),
        replacement: downloaded_asset.path.clone(),
        current_version: current_release.application_version.clone(),
        current_build: current_release.application_build.clone(),
        replacement_version: payload.application_version.clone(),
        replacement_build: payload.application_build.clone(),
        replacement_sha256: payload.artifact.sha256.clone(),
        replacement_bytes: payload.artifact.bytes,
    };
    let activation = match activate_appimage(&request) {
        Ok(receipt) => receipt,
        Err(error @ UpdateError::Activation(_)) => {
            let cleanup = cleanup_download_after_activation_failure(&downloaded_asset);
            return match cleanup {
                Ok(()) => Err(UpdaterError::Update(error.to_string())),
                Err(cleanup) => Err(UpdaterError::Transaction(format!(
                    "{error}; safe replacement cleanup was refused: {cleanup}"
                ))),
            };
        }
        Err(error) => return Err(UpdaterError::Update(error.to_string())),
    };
    Ok(UpdateRunReport {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "linux_x86_64_update_run",
        action: "updated_for_next_launch",
        current_release,
        candidate_release: Some(candidate_release),
        manifest_response: Some(downloaded_manifest.receipt),
        artifact_response: Some(downloaded_asset.receipt),
        activation: Some(activation),
    })
}

fn validate_release(version: &str, build: &str) -> Result<(), UpdaterError> {
    let valid_version = !version.is_empty()
        && version.len() <= 64
        && version.contains('.')
        && version.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 20
                && component.bytes().all(|byte| byte.is_ascii_digit())
        });
    let valid_build =
        !build.is_empty() && build.len() <= 32 && build.bytes().all(|byte| byte.is_ascii_digit());
    if !valid_version || !valid_build {
        return Err(UpdaterError::Config(
            "application version/build is not bounded dotted-numeric identity".to_owned(),
        ));
    }
    Ok(())
}

fn read_runtime_config(
    path: &Path,
    contract: &UpdateContract,
) -> Result<UpdateRuntimeConfig, UpdaterError> {
    if !path.is_absolute() {
        return Err(UpdaterError::Config(
            "runtime update config path must be absolute".to_owned(),
        ));
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| UpdaterError::Config(format!("open runtime update config: {error}")))?;
    let before = fstat(&descriptor)
        .map_err(|error| UpdaterError::Config(format!("inspect runtime update config: {error}")))?;
    let bytes = u64::try_from(before.st_size)
        .map_err(|_| UpdaterError::Config("runtime update config size is negative".to_owned()))?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || bytes == 0
        || bytes > 64 * 1024
        || before.st_mode & 0o7777 != 0o644
    {
        return Err(UpdaterError::Config(
            "runtime update config is not a bounded mode-0644 regular file".to_owned(),
        ));
    }
    let capacity = usize::try_from(bytes)
        .map_err(|_| UpdaterError::Config("runtime config size does not fit host".to_owned()))?;
    let mut file = File::from(descriptor);
    let mut encoded = Vec::with_capacity(capacity);
    file.read_to_end(&mut encoded)
        .map_err(|error| UpdaterError::Config(format!("read runtime update config: {error}")))?;
    let after = fstat(&file).map_err(|error| {
        UpdaterError::Config(format!("reinspect runtime update config: {error}"))
    })?;
    if encoded.len() != capacity
        || after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
    {
        return Err(UpdaterError::Config(
            "runtime update config identity changed while reading".to_owned(),
        ));
    }
    let config: UpdateRuntimeConfig = serde_json::from_slice(&encoded)
        .map_err(|error| UpdaterError::Config(format!("parse runtime update config: {error}")))?;
    let canonical = to_json_line(&config)
        .map_err(|error| UpdaterError::Config(format!("encode runtime update config: {error}")))?;
    if canonical.as_bytes() != encoded {
        return Err(UpdaterError::Config(
            "runtime update config is not canonical schema-1 JSON".to_owned(),
        ));
    }
    validate_runtime_update_config(&config, contract)?;
    Ok(config)
}

fn acquire_update_lock(current_appimage: &Path) -> Result<OwnedFd, UpdaterError> {
    if !current_appimage.is_absolute() {
        return Err(UpdaterError::Config(
            "current AppImage path must be absolute".to_owned(),
        ));
    }
    let parent_path = current_appimage
        .parent()
        .ok_or_else(|| UpdaterError::Config("current AppImage has no parent".to_owned()))?;
    let filename = current_appimage
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| UpdaterError::Config("current AppImage filename is not UTF-8".to_owned()))?;
    if filename.is_empty() || filename.len() > 180 || matches!(filename, "." | "..") {
        return Err(UpdaterError::Config(
            "current AppImage filename is invalid or oversized".to_owned(),
        ));
    }
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdaterError::Transaction(format!(
            "open AppImage parent for updater lock without following a final symlink: {error}"
        ))
    })?;
    let lock_name = OsString::from(format!(".{filename}.codex-update.lock"));
    let descriptor = openat(
        &parent,
        &lock_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| UpdaterError::Transaction(format!("open adjacent update lock: {error}")))?;
    let metadata = fstat(&descriptor)
        .map_err(|error| UpdaterError::Transaction(format!("inspect update lock: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(UpdaterError::Transaction(
            "adjacent update lock is not a regular file".to_owned(),
        ));
    }
    fchmod(&descriptor, Mode::from_raw_mode(0o600))
        .map_err(|error| UpdaterError::Transaction(format!("set update lock mode: {error}")))?;
    match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(descriptor),
        Err(error)
            if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
        {
            Err(UpdaterError::AlreadyRunning)
        }
        Err(error) => Err(UpdaterError::Transaction(format!(
            "acquire exclusive update lock: {error}"
        ))),
    }
}

fn cleanup_download_after_activation_failure(asset: &PrivateAsset) -> Result<(), UpdaterError> {
    let parent_path = asset
        .path
        .parent()
        .ok_or_else(|| UpdaterError::Transaction("private asset has no parent".to_owned()))?;
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdaterError::Transaction(format!("reopen AppImage parent for cleanup: {error}"))
    })?;
    cleanup_private_asset(&parent, &asset.name, &asset.identity)
}

fn download_bounded_bytes(
    url: &str,
    maximum_bytes: u64,
    https_only: bool,
) -> Result<BoundedDownload, UpdaterError> {
    if maximum_bytes == 0 || maximum_bytes > 1024 * 1024 {
        return Err(UpdaterError::Config(
            "manifest response bound is outside 1..=1048576".to_owned(),
        ));
    }
    validate_requested_url(url, https_only)?;
    let response = update_agent(https_only)
        .get(url)
        .header("accept", "application/json, application/octet-stream")
        .header("accept-encoding", "identity")
        .header(
            "user-agent",
            "codex-linux-packager-updater/0.1 (+https://github.com/BearHuddleston/codex-linux-packager)",
        )
        .call()
        .map_err(|error| UpdaterError::Network(format!("request signed manifest: {error}")))?;
    validate_status_and_headers(&response, url, maximum_bytes, None, https_only, true)?;
    let final_url = response.get_uri().to_string();
    let content_type = one_header(response.headers(), "content-type")?.to_owned();
    let content_length = parse_content_length(response.headers())?;
    let limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| UpdaterError::Config("manifest bound cannot be incremented".to_owned()))?;
    let mut response = response;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|error| UpdaterError::Network(format!("read signed manifest: {error}")))?;
    if u64::try_from(bytes.len()).ok() != Some(content_length) {
        return Err(UpdaterError::Network(
            "manifest body length differs from Content-Length".to_owned(),
        ));
    }
    Ok(BoundedDownload {
        bytes,
        receipt: UpdateTransportReceipt {
            final_url,
            content_type,
            bytes: content_length,
        },
    })
}

fn download_verified_asset(
    url: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    output_parent: &Path,
    https_only: bool,
) -> Result<PrivateAsset, UpdaterError> {
    if expected_bytes == 0 || expected_bytes > 2 * 1024 * 1024 * 1024 {
        return Err(UpdaterError::Config(
            "AppImage response length is outside its implementation bound".to_owned(),
        ));
    }
    validate_digest(expected_sha256, "signed AppImage digest")?;
    validate_requested_url(url, https_only)?;
    if !output_parent.is_absolute() {
        return Err(UpdaterError::Config(
            "AppImage output parent must be absolute".to_owned(),
        ));
    }
    let parent = open(
        output_parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        UpdaterError::Transaction(format!(
            "open AppImage parent without following a final symlink: {error}"
        ))
    })?;
    let (name, descriptor, identity) = create_private_asset(&parent)?;
    let path = output_parent.join(&name);
    let mut file = File::from(descriptor);
    let result = (|| -> Result<PrivateAsset, UpdaterError> {
        let response = update_agent(https_only)
            .get(url)
            .header("accept", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header(
                "user-agent",
                "codex-linux-packager-updater/0.1 (+https://github.com/BearHuddleston/codex-linux-packager)",
            )
            .call()
            .map_err(|error| UpdaterError::Network(format!("request AppImage: {error}")))?;
        validate_status_and_headers(
            &response,
            url,
            expected_bytes,
            Some(expected_bytes),
            https_only,
            false,
        )?;
        let final_url = response.get_uri().to_string();
        let content_type = one_header(response.headers(), "content-type")?.to_owned();
        let (_, body) = response.into_parts();
        let mut reader = body.into_reader();
        let mut hasher = Sha256::new();
        let mut prefix = [0_u8; 20];
        let mut prefix_bytes = 0_usize;
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| UpdaterError::Network(format!("read AppImage: {error}")))?;
            if count == 0 {
                break;
            }
            let count_u64 = u64::try_from(count)
                .map_err(|_| UpdaterError::Network("response chunk is too large".to_owned()))?;
            total = total
                .checked_add(count_u64)
                .ok_or_else(|| UpdaterError::Network("response length overflowed".to_owned()))?;
            if total > expected_bytes {
                return Err(UpdaterError::Network(
                    "AppImage response exceeds signed length".to_owned(),
                ));
            }
            if prefix_bytes < prefix.len() {
                let copied = (prefix.len() - prefix_bytes).min(count);
                prefix[prefix_bytes..prefix_bytes + copied].copy_from_slice(&buffer[..copied]);
                prefix_bytes += copied;
            }
            hasher.update(&buffer[..count]);
            file.write_all(&buffer[..count]).map_err(|error| {
                UpdaterError::Transaction(format!("write private AppImage: {error}"))
            })?;
        }
        if total != expected_bytes {
            return Err(UpdaterError::Network(format!(
                "AppImage body length {total} differs from signed length {expected_bytes}"
            )));
        }
        validate_type2_prefix(&prefix, prefix_bytes)?;
        let actual_sha256 = hex_lower(&hasher.finalize());
        if actual_sha256 != expected_sha256 {
            return Err(UpdaterError::Network(
                "AppImage SHA-256 differs from signed manifest".to_owned(),
            ));
        }
        file.sync_all().map_err(|error| {
            UpdaterError::Transaction(format!("fsync private AppImage: {error}"))
        })?;
        let after = fstat(&file).map_err(|error| {
            UpdaterError::Transaction(format!("reinspect private AppImage: {error}"))
        })?;
        let final_identity = DownloadIdentity {
            device: after.st_dev,
            inode: after.st_ino,
            bytes: u64::try_from(after.st_size).unwrap_or(u64::MAX),
        };
        if FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
            || final_identity.device != identity.device
            || final_identity.inode != identity.inode
            || final_identity.bytes != expected_bytes
        {
            return Err(UpdaterError::Transaction(
                "private AppImage identity changed during download".to_owned(),
            ));
        }
        validate_download_name(&parent, &name, &final_identity)?;
        Ok(PrivateAsset {
            name: name.clone(),
            path,
            identity: final_identity,
            receipt: UpdateTransportReceipt {
                final_url,
                content_type,
                bytes: total,
            },
        })
    })();
    match result {
        Ok(asset) => Ok(asset),
        Err(error) => match cleanup_private_asset(&parent, &name, &identity) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(UpdaterError::Transaction(format!(
                "{error}; safe private-download cleanup was refused: {cleanup}"
            ))),
        },
    }
}

fn update_agent(https_only: bool) -> Agent {
    let config = Agent::config_builder()
        .https_only(https_only)
        .http_status_as_error(false)
        .max_redirects(5)
        .max_response_header_size(32 * 1024)
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .build();
    Agent::new_with_config(config)
}

fn validate_status_and_headers(
    response: &ureq::http::Response<ureq::Body>,
    requested_url: &str,
    maximum_bytes: u64,
    exact_bytes: Option<u64>,
    https_only: bool,
    manifest: bool,
) -> Result<(), UpdaterError> {
    if response.status() != ureq::http::StatusCode::OK {
        return Err(UpdaterError::Network(format!(
            "expected status 200, received {}",
            response.status().as_u16()
        )));
    }
    validate_final_url(response.get_uri(), requested_url, https_only)?;
    if response.headers().contains_key("content-encoding") {
        return Err(UpdaterError::Network(
            "content encoding is forbidden".to_owned(),
        ));
    }
    if response.headers().contains_key("transfer-encoding") {
        return Err(UpdaterError::Network(
            "transfer encoding is forbidden".to_owned(),
        ));
    }
    let content_type = one_header(response.headers(), "content-type")?;
    let accepted = if manifest {
        matches!(
            content_type,
            "application/json" | "application/octet-stream"
        )
    } else {
        content_type == "application/octet-stream"
    };
    if !accepted {
        return Err(UpdaterError::Network(format!(
            "unexpected response content type {content_type:?}"
        )));
    }
    let content_length = parse_content_length(response.headers())?;
    if content_length == 0 || content_length > maximum_bytes {
        return Err(UpdaterError::Network(
            "Content-Length is outside the configured bound".to_owned(),
        ));
    }
    if exact_bytes.is_some_and(|expected| expected != content_length) {
        return Err(UpdaterError::Network(
            "Content-Length differs from the signed artifact length".to_owned(),
        ));
    }
    Ok(())
}

fn validate_requested_url(url: &str, https_only: bool) -> Result<(), UpdaterError> {
    let expected_prefix = if https_only { "https://" } else { "http://" };
    if !url.starts_with(expected_prefix)
        || url.len() > 4096
        || !url.is_ascii()
        || url.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(UpdaterError::Config(
            "update URL has an invalid scheme, length, or encoding".to_owned(),
        ));
    }
    Ok(())
}

fn validate_final_url(
    final_uri: &ureq::http::Uri,
    requested_url: &str,
    https_only: bool,
) -> Result<(), UpdaterError> {
    let final_url = final_uri.to_string();
    if !https_only {
        if final_url != requested_url {
            return Err(UpdaterError::Network(
                "local-test response redirected".to_owned(),
            ));
        }
        return Ok(());
    }
    if final_uri.scheme_str() != Some("https")
        || !matches!(
            final_uri.host(),
            Some(
                "github.com"
                    | "objects.githubusercontent.com"
                    | "release-assets.githubusercontent.com"
            )
        )
    {
        return Err(UpdaterError::Network(format!(
            "final response URL is outside the allowed GitHub HTTPS origins: {final_url}"
        )));
    }
    Ok(())
}

fn parse_content_length(headers: &ureq::http::HeaderMap) -> Result<u64, UpdaterError> {
    let value = one_header(headers, "content-length")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UpdaterError::Network(
            "Content-Length is not a strict unsigned decimal".to_owned(),
        ));
    }
    value
        .parse()
        .map_err(|_| UpdaterError::Network("Content-Length is not representable".to_owned()))
}

fn one_header<'a>(headers: &'a ureq::http::HeaderMap, name: &str) -> Result<&'a str, UpdaterError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| UpdaterError::Network(format!("missing {name} header")))?;
    if values.next().is_some() {
        return Err(UpdaterError::Network(format!("duplicate {name} header")));
    }
    value
        .to_str()
        .map_err(|_| UpdaterError::Network(format!("{name} header is not valid ASCII")))
}

fn create_private_asset(
    parent: &OwnedFd,
) -> Result<(OsString, OwnedFd, DownloadIdentity), UpdaterError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom(&mut random, GetRandomFlags::empty()).map_err(|error| {
            UpdaterError::Transaction(format!("obtain private-download entropy: {error}"))
        })?;
        let name = OsString::from(format!(
            ".codex-linux-packager-update-{}",
            hex_lower(&random)
        ));
        match openat(
            parent,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => {
                let metadata = fstat(&descriptor).map_err(|error| {
                    UpdaterError::Transaction(format!(
                        "inspect new private AppImage: {error}; cleanup was refused because its identity could not be established"
                    ))
                })?;
                let identity = DownloadIdentity {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                    bytes: 0,
                };
                if let Err(error) = fchmod(&descriptor, Mode::from_raw_mode(0o600)) {
                    let cleanup = cleanup_private_asset(parent, &name, &identity);
                    return match cleanup {
                        Ok(()) => Err(UpdaterError::Transaction(format!(
                            "set private AppImage mode: {error}"
                        ))),
                        Err(cleanup) => Err(UpdaterError::Transaction(format!(
                            "set private AppImage mode: {error}; safe cleanup was refused: {cleanup}"
                        ))),
                    };
                }
                return Ok((name, descriptor, identity));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(UpdaterError::Transaction(format!(
                    "create private AppImage: {error}"
                )));
            }
        }
    }
    Err(UpdaterError::Transaction(
        "could not allocate a unique private AppImage name".to_owned(),
    ))
}

fn validate_download_name(
    parent: &OwnedFd,
    name: &OsStr,
    expected: &DownloadIdentity,
) -> Result<(), UpdaterError> {
    let metadata = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| UpdaterError::Transaction(format!("inspect private AppImage: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_dev != expected.device
        || metadata.st_ino != expected.inode
        || u64::try_from(metadata.st_size).ok() != Some(expected.bytes)
    {
        return Err(UpdaterError::Transaction(
            "private AppImage pathname was substituted".to_owned(),
        ));
    }
    Ok(())
}

fn cleanup_private_asset(
    parent: &OwnedFd,
    name: &OsStr,
    expected: &DownloadIdentity,
) -> Result<(), UpdaterError> {
    let metadata = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| UpdaterError::Transaction(format!("inspect cleanup target: {error}")))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_dev != expected.device
        || metadata.st_ino != expected.inode
    {
        return Err(UpdaterError::Transaction(
            "private cleanup target was substituted".to_owned(),
        ));
    }
    unlinkat(parent, name, AtFlags::empty())
        .map_err(|error| UpdaterError::Transaction(format!("remove private AppImage: {error}")))
}

fn validate_type2_prefix(prefix: &[u8; 20], available: usize) -> Result<(), UpdaterError> {
    if available != prefix.len()
        || prefix.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || prefix.get(8..12) != Some(b"AI\x02\0")
        || prefix.get(18..20) != Some(&62_u16.to_le_bytes())
    {
        return Err(UpdaterError::Network(
            "download is not a Linux x86_64 Type-2 AppImage".to_owned(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), UpdaterError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpdaterError::Config(format!(
            "{label} is not 64 lowercase hexadecimal characters"
        )));
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
    use std::fs;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    use sha2::{Digest as _, Sha256};

    use super::{download_bounded_bytes, download_verified_asset};

    #[test]
    fn bounded_transport_rejects_truncation_oversize_and_wrong_asset_digest() {
        let truncated = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\nshort",
        );
        assert!(download_bounded_bytes(&truncated, 64, false).is_err());

        let oversized = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 65\r\nConnection: close\r\n\r\n",
        );
        assert!(download_bounded_bytes(&oversized, 64, false).is_err());

        let temporary = tempfile::tempdir().expect("temporary directory");
        let bytes = synthetic_appimage();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        let url = serve_parts(response.into_bytes(), bytes.clone());
        assert!(
            download_verified_asset(
                &url,
                u64::try_from(bytes.len()).expect("fixture length"),
                &"00".repeat(32),
                temporary.path(),
                false,
            )
            .is_err()
        );
        assert_eq!(
            fs::read_dir(temporary.path())
                .expect("enumerate destination")
                .count(),
            0,
            "a failed digest must clean only its owned private download"
        );
    }

    #[test]
    fn bounded_transport_accepts_one_exact_complete_response() {
        let url = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}\n",
        );
        let downloaded = download_bounded_bytes(&url, 64, false).expect("bounded response");
        assert_eq!(downloaded.bytes, b"{}\n");
        assert_eq!(downloaded.receipt.final_url, url);
        assert_eq!(downloaded.receipt.bytes, 3);
    }

    fn serve_once(response: &'static [u8]) -> String {
        serve_parts(response.to_vec(), Vec::new())
    }

    fn serve_parts(headers: Vec<u8>, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
        let address = listener.local_addr().expect("server address");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read request");
            stream.write_all(&headers).expect("write headers");
            stream.write_all(&body).expect("write body");
        });
        format!("http://{address}/fixture")
    }

    fn synthetic_appimage() -> Vec<u8> {
        let mut bytes = vec![0x44; 256];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[8..12].copy_from_slice(b"AI\x02\0");
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let digest = Sha256::digest(&bytes);
        assert_ne!(digest.as_slice(), &[0_u8; 32]);
        bytes
    }
}
