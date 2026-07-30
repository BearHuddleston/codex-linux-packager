#![forbid(unsafe_code)]

use std::path::PathBuf;

use codex_linux_packager::archive::{ArtifactContract, ArtifactTrust, inspect_artifact_bytes};
use codex_linux_packager::asar::inspect_asar_bytes;

#[test]
#[ignore = "requires an explicitly supplied proprietary official artifact"]
fn verifies_and_inspects_an_opt_in_complete_official_artifact() {
    let path = PathBuf::from(
        std::env::var_os("CODEX_PACKAGER_LIVE_ARTIFACT").expect("set CODEX_PACKAGER_LIVE_ARTIFACT"),
    );
    let signature =
        std::env::var("CODEX_PACKAGER_LIVE_SIGNATURE").expect("set CODEX_PACKAGER_LIVE_SIGNATURE");
    let bytes = std::fs::read(path).expect("read explicitly supplied artifact");
    let contract = ArtifactContract {
        expected_length: u64::try_from(bytes.len()).expect("artifact length fits u64"),
        signature_base64: signature,
        version: std::env::var("CODEX_PACKAGER_LIVE_VERSION")
            .expect("set CODEX_PACKAGER_LIVE_VERSION"),
        build: std::env::var("CODEX_PACKAGER_LIVE_BUILD").expect("set CODEX_PACKAGER_LIVE_BUILD"),
    };
    let trust = ArtifactTrust::pinned_production().expect("compiled production trust root");

    let inspection = inspect_artifact_bytes(&bytes, &contract, &trust)
        .expect("official complete artifact must inspect");

    assert!(inspection.signature.verified);
    assert_eq!(inspection.bundle.version, contract.version);
    assert_eq!(inspection.bundle.build, contract.build);
}

#[test]
#[ignore = "requires an explicitly supplied proprietary official app.asar"]
fn verifies_every_packed_digest_in_an_opt_in_official_asar() {
    let path = PathBuf::from(
        std::env::var_os("CODEX_PACKAGER_LIVE_ASAR").expect("set CODEX_PACKAGER_LIVE_ASAR"),
    );
    let bytes = std::fs::read(path).expect("read explicitly supplied app.asar");

    let inspection = inspect_asar_bytes(&bytes).expect("official app.asar must inspect");

    assert!(inspection.packed_integrity_verified);
    assert!(inspection.packed_file_count > 0);
}
