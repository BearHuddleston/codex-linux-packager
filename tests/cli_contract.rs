#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn cargo_run_unambiguously_selects_the_packaging_cli() {
    let manifest = include_str!("../Cargo.toml");

    assert!(
        manifest.contains("default-run = \"codex-linux-packager\""),
        "Cargo.toml must keep plain cargo run usable after adding helper binaries"
    );
}

#[test]
fn help_exposes_every_planned_command_concept() {
    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .arg("--help")
        .output()
        .expect("CLI should start");

    assert!(
        output.status.success(),
        "help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    for command in [
        "inspect",
        "check-upstream",
        "acquire-artifact",
        "inspect-artifact",
        "stage",
        "extract",
        "build-native",
        "assemble-runtime",
        "build-appdir",
        "pack-appimage",
        "generate-update-key",
        "sign-update",
        "prepare-release",
        "verify-release",
        "release-readiness",
    ] {
        assert!(
            stdout
                .lines()
                .any(|line| line.split_whitespace().next() == Some(command)),
            "help did not include {command:?}:\n{stdout}"
        );
    }
}

#[test]
fn acquire_artifact_rejects_a_nonofficial_url_before_network_access() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let output_path = temporary.path().join("source.zip");
    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .arg("acquire-artifact")
        .args([
            "--url",
            "https://attacker.invalid/Codex.zip",
            "--signature",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "--length",
            "1",
            "--version",
            "26.721.81911",
            "--build",
            "5973",
            "--output",
        ])
        .arg(&output_path)
        .output()
        .expect("CLI should start");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be JSON");
    assert_eq!(value["error"]["code"], "artifact_acquisition_failed");
    assert!(!output_path.exists());
}

#[test]
fn check_upstream_fixture_reports_the_guarded_automatic_action() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("feed.xml");
    let signature =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
<channel><title>Codex</title><item>
<title>26.727.40816</title>
<pubDate>Thu, 30 Jul 2026 19:01:19 +0000</pubDate>
<sparkle:version>6067</sparkle:version>
<sparkle:shortVersionString>26.727.40816</sparkle:shortVersionString>
<sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>
<sparkle:hardwareRequirements>x86_64</sparkle:hardwareRequirements>
<enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-26.727.40816.zip" length="548903666" type="application/octet-stream" sparkle:edSignature="{signature}"/>
</item></channel></rss>"#
    );
    std::fs::write(&path, xml).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .args(["check-upstream", "--fixture"])
        .arg(&path)
        .output()
        .expect("CLI should start");

    assert!(
        output.status.success(),
        "check-upstream failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "success must not write to stderr");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["kind"], "upstream_status");
    assert_eq!(value["action"], "current");
    assert_eq!(value["contract_update_required"], false);
    assert_eq!(value["candidate_rebuild_required"], false);
    assert_eq!(value["automatic_rebuild_permitted"], false);
    assert!(output.stdout.ends_with(b"\n"));
}

#[test]
fn inspect_artifact_failure_is_an_explicit_versioned_json_error() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing = temporary.path().join("missing.zip");
    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .arg("inspect-artifact")
        .arg("--artifact")
        .arg(missing)
        .args([
            "--signature",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "--length",
            "1",
            "--version",
            "26.721.81911",
            "--build",
            "5973",
        ])
        .output()
        .expect("CLI should start");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stdout.is_empty(),
        "failures must not write to stdout"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("stderr should be JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "artifact_inspection_failed");
    assert!(output.stderr.ends_with(b"\n"));
}

#[test]
fn inspect_fixture_emits_one_deterministic_success_document() {
    let temporary = tempfile::tempdir().expect("create temporary directory");
    let path = temporary.path().join("feed.xml");
    let signature =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle" version="2.0">
<channel><title>Codex</title><item>
<title>26.721.81911</title>
<pubDate>Wed, 29 Jul 2026 07:00:18 +0000</pubDate>
<sparkle:version>5973</sparkle:version>
<sparkle:shortVersionString>26.721.81911</sparkle:shortVersionString>
<sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>
<sparkle:hardwareRequirements>x86_64</sparkle:hardwareRequirements>
<enclosure url="https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-26.721.81911.zip" length="545069607" type="application/octet-stream" sparkle:edSignature="{signature}"/>
</item></channel></rss>"#
    );
    std::fs::write(&path, xml).expect("write fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_codex-linux-packager"))
        .args(["inspect", "--fixture"])
        .arg(&path)
        .output()
        .expect("CLI should start");

    assert!(
        output.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "success must not write to stderr");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["schema"], 1);
    assert_eq!(value["kind"], "feed_inspection");
    assert_eq!(value["releases"][0]["hardware_requirements"], "x86_64");
    assert!(output.stdout.ends_with(b"\n"));
}
