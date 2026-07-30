//! Bounded HTTP retrieval for the official Sparkle feed and its selected
//! artifact.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, fchmod, fstat, fsync, open, openat,
    renameat_with, statat, unlinkat,
};
use rustix::rand::{GetRandomFlags, getrandom};
use serde::Serialize;
use thiserror::Error;
use ureq::Agent;
use ureq::ResponseExt as _;

use crate::archive::{
    ArtifactContract, ArtifactInspection, ArtifactTrust, MAX_ARTIFACT_BYTES, inspect_artifact_bytes,
};
use crate::feed::{MAX_FEED_BYTES, OFFICIAL_FEED_URL};
use crate::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION};

const OFFICIAL_ARTIFACT_PREFIX: &str =
    "https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-";

/// Complete bytes returned from the exact official feed endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedFeed {
    /// Exact final response URL.
    pub final_url: String,
    /// Complete response body.
    pub bytes: Vec<u8>,
}

/// Rejections produced by the feed transport boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DownloadError {
    /// The server attempted to redirect the fixed request.
    #[error("feed redirects are forbidden")]
    Redirect,

    /// A response violated the bounded HTTP contract.
    #[error("invalid feed HTTP response: {0}")]
    Response(String),

    /// The transport failed before a valid response was available.
    #[error("feed transport failed: {0}")]
    Transport(String),
}

/// Strict HTTP facts for one complete artifact response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactResponseReceipt {
    /// Exact final response URL.
    pub final_url: String,
    /// Exact accepted response media type.
    pub content_type: String,
    /// Complete response body bytes.
    pub bytes: u64,
}

/// Deterministic receipt for a downloaded and authenticated source artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactAcquisition {
    /// Rust-owned document schema.
    pub schema: u32,
    /// Unambiguous producer identifier.
    pub producer: &'static str,
    /// Stable document kind.
    pub kind: &'static str,
    /// Strict transport facts.
    pub response: ArtifactResponseReceipt,
    /// Complete exact-byte authentication and archive inspection.
    pub inspection: ArtifactInspection,
}

/// Rejections produced by the artifact transport/publication boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArtifactDownloadError {
    /// The selected endpoint attempted to redirect.
    #[error("artifact redirects are forbidden")]
    Redirect,
    /// The request or destination contract is invalid.
    #[error("invalid artifact download request: {0}")]
    Request(String),
    /// A response violated the strict bounded HTTP contract.
    #[error("invalid artifact HTTP response: {0}")]
    Response(String),
    /// The transport failed before a valid response was available.
    #[error("artifact transport failed: {0}")]
    Transport(String),
    /// Exact-byte authentication or archive validation failed.
    #[error("downloaded artifact authentication failed: {0}")]
    Authentication(String),
    /// Private file construction or validation failed.
    #[error("artifact download transaction failed: {0}")]
    Transaction(String),
    /// No-replace publication failed before commit.
    #[error("artifact download publication failed before commit: {0}")]
    Publication(String),
    /// The name committed but parent durability is uncertain.
    #[error("artifact download committed but parent durability is uncertain: {0}")]
    PostCommitDurability(String),
}

#[derive(Debug, Clone, Copy)]
struct DownloadIdentity {
    device: u64,
    inode: u64,
}

/// Downloads the fixed official x86_64 feed without following redirects.
pub fn download_official_feed() -> Result<DownloadedFeed, DownloadError> {
    download_feed(OFFICIAL_FEED_URL, true)
}

/// Downloads one exact feed-selected artifact, authenticates and preflights its
/// complete bytes in a private file, then publishes it without replacement.
pub fn acquire_official_artifact(
    url: &str,
    output: &Path,
    contract: &ArtifactContract,
    trust: &ArtifactTrust,
) -> Result<ArtifactAcquisition, ArtifactDownloadError> {
    if !is_dotted_numeric(&contract.version, 64)
        || contract.build.is_empty()
        || contract.build.len() > 32
        || !contract.build.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ArtifactDownloadError::Request(
            "artifact version/build identity is invalid".to_owned(),
        ));
    }
    let expected_url = format!("{OFFICIAL_ARTIFACT_PREFIX}{}.zip", contract.version);
    if url != expected_url {
        return Err(ArtifactDownloadError::Request(
            "artifact URL is not the exact official x86_64 URL for the contracted version"
                .to_owned(),
        ));
    }
    if contract.expected_length == 0 || contract.expected_length > MAX_ARTIFACT_BYTES {
        return Err(ArtifactDownloadError::Request(format!(
            "artifact length is outside the 1..={MAX_ARTIFACT_BYTES} byte bound"
        )));
    }
    let (response, inspection) =
        download_artifact_response(url, contract.expected_length, output, true, |file| {
            let capacity = usize::try_from(contract.expected_length).map_err(|_| {
                ArtifactDownloadError::Authentication(
                    "artifact length does not fit this platform".to_owned(),
                )
            })?;
            let mut bytes = Vec::with_capacity(capacity);
            file.take(contract.expected_length.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    ArtifactDownloadError::Authentication(format!(
                        "read complete private artifact: {error}"
                    ))
                })?;
            if bytes.len() != capacity {
                return Err(ArtifactDownloadError::Authentication(
                    "private artifact length changed before authentication".to_owned(),
                ));
            }
            inspect_artifact_bytes(&bytes, contract, trust)
                .map_err(|error| ArtifactDownloadError::Authentication(error.to_string()))
        })?;
    Ok(ArtifactAcquisition {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER,
        kind: "artifact_acquisition",
        response,
        inspection,
    })
}

fn download_artifact_response<T>(
    url: &str,
    expected_length: u64,
    output: &Path,
    https_only: bool,
    validator: impl FnOnce(&mut File) -> Result<T, ArtifactDownloadError>,
) -> Result<(ArtifactResponseReceipt, T), ArtifactDownloadError> {
    if !output.is_absolute() {
        return Err(ArtifactDownloadError::Request(
            "output path must be absolute".to_owned(),
        ));
    }
    if expected_length == 0 {
        return Err(ArtifactDownloadError::Request(
            "expected length must be positive".to_owned(),
        ));
    }
    let parent_path = output.parent().filter(|path| !path.as_os_str().is_empty());
    let parent_path = parent_path.ok_or_else(|| {
        ArtifactDownloadError::Request("output must have a parent directory".to_owned())
    })?;
    let final_name = output
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| {
            ArtifactDownloadError::Request("output must name one non-dot regular file".to_owned())
        })?
        .to_owned();
    let parent = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        ArtifactDownloadError::Transaction(format!(
            "open output parent without following a final symlink: {error}"
        ))
    })?;

    let config = Agent::config_builder()
        .https_only(https_only)
        .http_status_as_error(false)
        .max_redirects(0)
        .max_response_header_size(32 * 1024)
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .build();
    let agent = Agent::new_with_config(config);
    let response = agent
        .get(url)
        .header("accept", "application/zip, application/octet-stream")
        .header("accept-encoding", "identity")
        .call()
        .map_err(|error| ArtifactDownloadError::Transport(error.to_string()))?;
    if response.status().is_redirection() {
        return Err(ArtifactDownloadError::Redirect);
    }
    if response.status() != ureq::http::StatusCode::OK {
        return Err(ArtifactDownloadError::Response(format!(
            "expected status 200, received {}",
            response.status().as_u16()
        )));
    }
    let final_url = response.get_uri().to_string();
    if final_url != url {
        return Err(ArtifactDownloadError::Response(
            "final response URL differs from the requested URL".to_owned(),
        ));
    }
    if response.headers().contains_key("content-encoding") {
        return Err(ArtifactDownloadError::Response(
            "content encoding is forbidden".to_owned(),
        ));
    }
    if response.headers().contains_key("transfer-encoding") {
        return Err(ArtifactDownloadError::Response(
            "transfer encoding is forbidden".to_owned(),
        ));
    }
    let content_type = one_artifact_header(response.headers(), "content-type")?.to_owned();
    if content_type != "application/zip" && content_type != "application/octet-stream" {
        return Err(ArtifactDownloadError::Response(format!(
            "unexpected content type {content_type:?}"
        )));
    }
    let content_length = one_artifact_header(response.headers(), "content-length")?;
    if content_length.is_empty() || !content_length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArtifactDownloadError::Response(
            "Content-Length is not a strict unsigned decimal".to_owned(),
        ));
    }
    let content_length = content_length.parse::<u64>().map_err(|_| {
        ArtifactDownloadError::Response("Content-Length is not representable".to_owned())
    })?;
    if content_length != expected_length {
        return Err(ArtifactDownloadError::Response(format!(
            "Content-Length {content_length} differs from expected length {expected_length}"
        )));
    }

    let (temporary_name, descriptor, identity) = create_private_download(&parent)?;
    let mut file = File::from(descriptor);
    let mut committed = false;
    let result = (|| {
        let (_, body) = response.into_parts();
        let mut reader = body.into_reader();
        let mut buffer = [0_u8; 64 * 1024];
        let mut bytes = 0_u64;
        loop {
            let read = reader.read(&mut buffer).map_err(|error| {
                ArtifactDownloadError::Response(format!("read response body: {error}"))
            })?;
            if read == 0 {
                break;
            }
            let read_u64 = u64::try_from(read).map_err(|_| {
                ArtifactDownloadError::Response(
                    "response chunk length is not representable".to_owned(),
                )
            })?;
            bytes = bytes.checked_add(read_u64).ok_or_else(|| {
                ArtifactDownloadError::Response("response byte count overflowed".to_owned())
            })?;
            if bytes > expected_length {
                return Err(ArtifactDownloadError::Response(
                    "response body exceeds expected length".to_owned(),
                ));
            }
            file.write_all(&buffer[..read]).map_err(|error| {
                ArtifactDownloadError::Transaction(format!(
                    "write private artifact download: {error}"
                ))
            })?;
        }
        if bytes != expected_length {
            return Err(ArtifactDownloadError::Response(format!(
                "response body length {bytes} differs from expected length {expected_length}"
            )));
        }
        file.sync_all().map_err(|error| {
            ArtifactDownloadError::Transaction(format!("fsync private artifact download: {error}"))
        })?;
        file.rewind().map_err(|error| {
            ArtifactDownloadError::Transaction(format!("rewind private artifact download: {error}"))
        })?;
        let validated = validator(&mut file)?;
        let after = fstat(&file).map_err(|error| {
            ArtifactDownloadError::Transaction(format!(
                "reinspect private artifact download: {error}"
            ))
        })?;
        if FileType::from_raw_mode(after.st_mode) != FileType::RegularFile
            || after.st_dev != identity.device
            || after.st_ino != identity.inode
            || u64::try_from(after.st_size).ok() != Some(expected_length)
        {
            return Err(ArtifactDownloadError::Transaction(
                "private artifact identity changed during validation".to_owned(),
            ));
        }
        validate_download_name(&parent, &temporary_name, &identity)?;
        renameat_with(
            &parent,
            &temporary_name,
            &parent,
            &final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            ArtifactDownloadError::Publication(format!(
                "commit authenticated artifact without replacement: {error}"
            ))
        })?;
        committed = true;
        fsync(&parent).map_err(|error| {
            ArtifactDownloadError::PostCommitDurability(format!(
                "fsync artifact output parent: {error}"
            ))
        })?;
        Ok((
            ArtifactResponseReceipt {
                final_url,
                content_type,
                bytes,
            },
            validated,
        ))
    })();
    if let Err(error) = result {
        if !committed {
            if let Err(cleanup) = cleanup_private_download(&parent, &temporary_name, &identity) {
                return Err(ArtifactDownloadError::Transaction(format!(
                    "{error}; safe private-download cleanup was refused: {cleanup}"
                )));
            }
        }
        return Err(error);
    }
    result
}

fn create_private_download(
    parent: &OwnedFd,
) -> Result<(OsString, OwnedFd, DownloadIdentity), ArtifactDownloadError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom(&mut random, GetRandomFlags::empty()).map_err(|error| {
            ArtifactDownloadError::Transaction(format!("obtain download entropy: {error}"))
        })?;
        let name = OsString::from(format!(
            ".codex-linux-packager-download-{}",
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
                    ArtifactDownloadError::Transaction(format!(
                        "inspect newly created private download: {error}; cleanup was refused because its identity could not be established"
                    ))
                })?;
                let identity = DownloadIdentity {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                };
                if let Err(error) = fchmod(&descriptor, Mode::from_raw_mode(0o600)) {
                    let cleanup = match cleanup_private_download(parent, &name, &identity) {
                        Ok(()) => "succeeded".to_owned(),
                        Err(cleanup) => format!("was refused: {cleanup}"),
                    };
                    return Err(ArtifactDownloadError::Transaction(format!(
                        "set private download mode: {error}; safe cleanup {cleanup}"
                    )));
                }
                return Ok((name, descriptor, identity));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => {
                return Err(ArtifactDownloadError::Transaction(format!(
                    "create private artifact download: {error}"
                )));
            }
        }
    }
    Err(ArtifactDownloadError::Transaction(
        "could not allocate a unique private download name".to_owned(),
    ))
}

fn validate_download_name(
    parent: &OwnedFd,
    name: &OsStr,
    identity: &DownloadIdentity,
) -> Result<(), ArtifactDownloadError> {
    let current = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
        ArtifactDownloadError::Transaction(format!("inspect private download name: {error}"))
    })?;
    if FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
        || current.st_dev != identity.device
        || current.st_ino != identity.inode
    {
        return Err(ArtifactDownloadError::Transaction(
            "private artifact download name was substituted".to_owned(),
        ));
    }
    Ok(())
}

fn cleanup_private_download(
    parent: &OwnedFd,
    name: &OsStr,
    identity: &DownloadIdentity,
) -> Result<(), ArtifactDownloadError> {
    validate_download_name(parent, name, identity)?;
    unlinkat(parent, name, AtFlags::empty()).map_err(|error| {
        ArtifactDownloadError::Transaction(format!("remove owned private download: {error}"))
    })
}

fn one_artifact_header<'a>(
    headers: &'a ureq::http::HeaderMap,
    name: &str,
) -> Result<&'a str, ArtifactDownloadError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| ArtifactDownloadError::Response(format!("missing {name} header")))?;
    if values.next().is_some() {
        return Err(ArtifactDownloadError::Response(format!(
            "duplicate {name} header"
        )));
    }
    value
        .to_str()
        .map_err(|_| ArtifactDownloadError::Response(format!("{name} header is not valid ASCII")))
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

fn is_dotted_numeric(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
        && value.contains('.')
}

fn download_feed(url: &str, https_only: bool) -> Result<DownloadedFeed, DownloadError> {
    let config = Agent::config_builder()
        .https_only(https_only)
        .http_status_as_error(false)
        .max_redirects(0)
        .max_response_header_size(32 * 1024)
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent = Agent::new_with_config(config);
    let response = agent
        .get(url)
        .header("accept", "application/xml")
        .header("accept-encoding", "identity")
        .call()
        .map_err(|error| DownloadError::Transport(error.to_string()))?;
    if response.status().is_redirection() {
        return Err(DownloadError::Redirect);
    }
    validate_response(response, url)
}

fn validate_response(
    mut response: ureq::http::Response<ureq::Body>,
    requested_url: &str,
) -> Result<DownloadedFeed, DownloadError> {
    if response.status() != ureq::http::StatusCode::OK {
        return Err(DownloadError::Response(format!(
            "expected status 200, received {}",
            response.status().as_u16()
        )));
    }

    let final_url = response.get_uri().to_string();
    if final_url != requested_url {
        return Err(DownloadError::Response(
            "final response URL differs from the requested URL".to_owned(),
        ));
    }
    if response.headers().contains_key("content-encoding") {
        return Err(DownloadError::Response(
            "content encoding is forbidden".to_owned(),
        ));
    }
    if response.headers().contains_key("transfer-encoding") {
        return Err(DownloadError::Response(
            "transfer encoding is forbidden".to_owned(),
        ));
    }

    let content_type = one_header(response.headers(), "content-type")?;
    if content_type != "application/xml" {
        return Err(DownloadError::Response(format!(
            "unexpected content type {content_type:?}"
        )));
    }

    let content_length = one_header(response.headers(), "content-length")?;
    if content_length.is_empty() || !content_length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DownloadError::Response(
            "Content-Length is not a strict unsigned decimal".to_owned(),
        ));
    }
    let content_length = content_length
        .parse::<usize>()
        .map_err(|_| DownloadError::Response("Content-Length is not representable".to_owned()))?;
    if content_length == 0 || content_length > MAX_FEED_BYTES {
        return Err(DownloadError::Response(
            "Content-Length is outside configured bounds".to_owned(),
        ));
    }

    let body_limit = u64::try_from(MAX_FEED_BYTES)
        .map_err(|_| {
            DownloadError::Response("configured feed limit is not representable".to_owned())
        })?
        .checked_add(1)
        .ok_or_else(|| {
            DownloadError::Response("configured feed limit cannot be incremented".to_owned())
        })?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(body_limit)
        .read_to_vec()
        .map_err(|error| DownloadError::Response(error.to_string()))?;
    if bytes.len() != content_length {
        return Err(DownloadError::Response(
            "response body length differs from Content-Length".to_owned(),
        ));
    }

    Ok(DownloadedFeed { final_url, bytes })
}

fn one_header<'a>(
    headers: &'a ureq::http::HeaderMap,
    name: &str,
) -> Result<&'a str, DownloadError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| DownloadError::Response(format!("missing {name} header")))?;
    if values.next().is_some() {
        return Err(DownloadError::Response(format!("duplicate {name} header")));
    }
    value
        .to_str()
        .map_err(|_| DownloadError::Response(format!("{name} header is not valid ASCII")))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{ArtifactDownloadError, DownloadError, download_artifact_response, download_feed};

    #[test]
    fn artifact_response_is_committed_only_after_complete_validation() {
        let body = b"synthetic authenticated later".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.clone())
        .collect();
        let (url, server) = serve_once_at(response, "artifact.zip");
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let output = temporary.path().join("source.zip");

        let (receipt, ()) =
            download_artifact_response(&url, body.len() as u64, &output, false, |file| {
                let metadata = file.metadata().expect("read downloaded metadata");
                assert_eq!(metadata.len(), body.len() as u64);
                Ok(())
            })
            .expect("valid artifact response should commit");
        server.join().expect("server thread should finish");

        assert_eq!(receipt.final_url, url);
        assert_eq!(receipt.content_type, "application/zip");
        assert_eq!(receipt.bytes, body.len() as u64);
        assert_eq!(std::fs::read(output).expect("read output"), body);
    }

    #[test]
    fn artifact_validation_failure_removes_only_the_private_download() {
        let body = b"unauthenticated synthetic body".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.clone())
        .collect();
        let (url, server) = serve_once_at(response, "artifact.zip");
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let output = temporary.path().join("source.zip");

        let result: Result<(_, ()), _> =
            download_artifact_response(&url, body.len() as u64, &output, false, |_| {
                Err(ArtifactDownloadError::Authentication(
                    "synthetic rejection".to_owned(),
                ))
            });
        let error = result.expect_err("validator rejection must fail");
        server.join().expect("server thread should finish");

        assert!(error.to_string().contains("synthetic rejection"));
        assert!(!output.exists());
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("list temporary directory")
                .count(),
            0,
            "private download must be cleaned"
        );
    }

    #[test]
    fn artifact_publication_preserves_an_existing_caller_file() {
        let body = b"new synthetic body".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.clone())
        .collect();
        let (url, server) = serve_once_at(response, "artifact.zip");
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let output = temporary.path().join("source.zip");
        std::fs::write(&output, b"caller-owned").expect("write existing output");

        download_artifact_response(&url, body.len() as u64, &output, false, |_| Ok(()))
            .expect_err("no-replace publication must fail");
        server.join().expect("server thread should finish");

        assert_eq!(
            std::fs::read(&output).expect("read existing output"),
            b"caller-owned"
        );
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("list temporary directory")
                .count(),
            1,
            "only the caller-owned output may remain"
        );
    }

    #[test]
    fn rejects_redirect_without_following_it() {
        let (url, server) = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n".to_vec(),
        );

        let error = download_feed(&url, false).expect_err("redirect response must be rejected");
        server.join().expect("server thread should finish");

        assert!(matches!(error, DownloadError::Redirect));
    }

    #[test]
    fn returns_one_complete_bounded_xml_body() {
        let body = b"<?xml version=\"1.0\"?><rss/>".to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.clone())
        .collect();
        let (url, server) = serve_once(response);

        let downloaded = download_feed(&url, false).expect("valid response should download");
        server.join().expect("server thread should finish");

        assert_eq!(downloaded.final_url, url);
        assert_eq!(downloaded.bytes, body);
    }

    #[test]
    fn rejects_a_truncated_response_body() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 9\r\nConnection: close\r\n\r\nshort"
                .to_vec(),
        );

        download_feed(&url, false).expect_err("truncated response must be rejected");
        server.join().expect("server thread should finish");
    }

    #[test]
    fn rejects_duplicate_content_length_headers() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
                .to_vec(),
        );

        download_feed(&url, false).expect_err("duplicate Content-Length must be rejected");
        server.join().expect("server thread should finish");
    }

    #[test]
    fn rejects_an_oversized_declared_body_before_reading_it() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 262145\r\nConnection: close\r\n\r\n"
                .to_vec(),
        );

        download_feed(&url, false).expect_err("oversized response must be rejected");
        server.join().expect("server thread should finish");
    }

    fn serve_once(response: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        serve_once_at(response, "appcast.xml")
    }

    fn serve_once_at(response: Vec<u8>, path: &str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("make test server nonblocking");
        let address = listener.local_addr().expect("read test address");
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return;
                    }
                    Err(error) => panic!("accept request: {error}"),
                }
            };
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).expect("read request");
            stream.write_all(&response).expect("write response");
        });
        (format!("http://{address}/{path}"), handle)
    }
}
