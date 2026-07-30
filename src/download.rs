//! Bounded HTTP retrieval for the one official Sparkle feed.

use std::time::Duration;

use thiserror::Error;
use ureq::Agent;
use ureq::ResponseExt as _;

use crate::feed::{MAX_FEED_BYTES, OFFICIAL_FEED_URL};

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

/// Downloads the fixed official x86_64 feed without following redirects.
pub fn download_official_feed() -> Result<DownloadedFeed, DownloadError> {
    download_feed(OFFICIAL_FEED_URL, true)
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

    use super::{DownloadError, download_feed};

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
        (format!("http://{address}/appcast.xml"), handle)
    }
}
