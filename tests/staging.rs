#![forbid(unsafe_code)]

use std::io::{Cursor, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::archive::{ArtifactContract, ArtifactTrust};
use codex_linux_packager::extract::extract_stage_with_trust;
use codex_linux_packager::staging::{stage_artifact_file, validate_stage_with_trust};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::rand::{GetRandomFlags, getrandom};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

#[test]
fn publishes_only_the_authenticated_archive_asar_and_provenance() {
    let app_asar = synthetic_asar(b"synthetic-staged-asar");
    let (archive, contract, trust) = signed_artifact(&app_asar);
    let temporary = tempfile::tempdir().expect("temporary staging root");
    let source = temporary.path().join("artifact.zip");
    let output = temporary.path().join("generation-1");
    std::fs::write(&source, &archive).expect("write source archive");

    let provenance = stage_artifact_file(&source, &output, &contract, &trust)
        .expect("stage valid authenticated artifact");

    let mut names: Vec<_> = std::fs::read_dir(&output)
        .expect("read stage")
        .map(|entry| {
            entry
                .expect("read stage entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, ["app.asar", "provenance.json", "source.zip"]);
    assert_eq!(std::fs::read(output.join("source.zip")).unwrap(), archive);
    assert_eq!(std::fs::read(output.join("app.asar")).unwrap(), app_asar);
    assert_eq!(provenance.schema, 1);
    assert_eq!(provenance.kind, "artifact_stage");
    let validated = validate_stage_with_trust(&output, &trust).expect("revalidate published stage");
    assert_eq!(validated.provenance, provenance);
}

#[test]
fn rejects_an_authenticated_malformed_asar_before_creating_output() {
    let (archive, contract, trust) = signed_artifact(b"not an ASAR");
    let temporary = tempfile::tempdir().expect("temporary staging root");
    let source = temporary.path().join("artifact.zip");
    let output = temporary.path().join("generation-1");
    std::fs::write(&source, archive).expect("write source archive");

    let error = stage_artifact_file(&source, &output, &contract, &trust)
        .expect_err("malformed authenticated app.asar must be rejected");

    assert!(error.to_string().contains("ASAR"));
    assert!(!output.exists());
}

#[test]
fn preserves_an_existing_committed_destination_on_publication_failure() {
    let app_asar = synthetic_asar(b"candidate that must not replace");
    let (archive, contract, trust) = signed_artifact(&app_asar);
    let temporary = tempfile::tempdir().expect("temporary staging root");
    let source = temporary.path().join("artifact.zip");
    let output = temporary.path().join("generation-1");
    std::fs::write(&source, archive).expect("write source archive");
    std::fs::create_dir(&output).expect("create prior generation");
    std::fs::write(output.join("sentinel"), b"prior committed bytes")
        .expect("write prior generation");

    stage_artifact_file(&source, &output, &contract, &trust)
        .expect_err("no-replace publication must reject an existing destination");

    assert_eq!(
        std::fs::read(output.join("sentinel")).unwrap(),
        b"prior committed bytes"
    );
    let names: Vec<_> = std::fs::read_dir(temporary.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names
            .iter()
            .all(|name| !name.starts_with(".codex-linux-packager-stage-"))
    );
}

#[test]
fn rejects_unknown_or_legacy_stage_schema_instead_of_migrating_it() {
    let app_asar = synthetic_asar(b"schema validation");
    let (archive, contract, trust) = signed_artifact(&app_asar);
    let temporary = tempfile::tempdir().expect("temporary staging root");
    let source = temporary.path().join("artifact.zip");
    let output = temporary.path().join("generation-1");
    std::fs::write(&source, archive).expect("write source archive");
    stage_artifact_file(&source, &output, &contract, &trust).expect("publish stage");
    let provenance_path = output.join("provenance.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&provenance_path).unwrap()).unwrap();
    document["schema"] = serde_json::json!(3);
    std::fs::write(&provenance_path, serde_json::to_vec(&document).unwrap())
        .expect("replace test provenance");

    let error = validate_stage_with_trust(&output, &trust)
        .expect_err("schema 3 must not be consumed by the Rust schema-1 reader");

    assert!(error.to_string().contains("schema"));
}

#[test]
fn extracts_only_integrity_verified_packed_asar_files() {
    let app_asar = synthetic_asar(b"verified packed contents");
    let (archive, contract, trust) = signed_artifact(&app_asar);
    let temporary = tempfile::tempdir().expect("temporary extraction root");
    let source = temporary.path().join("artifact.zip");
    let stage = temporary.path().join("generation-1");
    let output = temporary.path().join("extraction-1");
    std::fs::write(&source, archive).expect("write source archive");
    stage_artifact_file(&source, &stage, &contract, &trust).expect("publish stage");

    let manifest = extract_stage_with_trust(&stage, &output, &trust)
        .expect("extract authenticated packed files");

    assert_eq!(
        std::fs::read(output.join("files/main.js")).unwrap(),
        b"verified packed contents"
    );
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.kind, "asar_extraction");
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].disposition, "extracted_packed");
}

fn signed_artifact(app_asar: &[u8]) -> (Vec<u8>, ArtifactContract, ArtifactTrust) {
    let mut seed = [0_u8; 32];
    getrandom(&mut seed, GetRandomFlags::empty()).expect("obtain ephemeral test entropy");
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let public_key = signing_key.verifying_key().to_bytes();
    let archive = synthetic_bundle(&BASE64_STANDARD.encode(public_key), app_asar);
    let contract = ArtifactContract {
        expected_length: u64::try_from(archive.len()).expect("archive length fits"),
        signature_base64: BASE64_STANDARD.encode(signing_key.sign(&archive).to_bytes()),
        version: "26.721.81911".to_owned(),
        build: "5973".to_owned(),
    };
    (
        archive,
        contract,
        ArtifactTrust::from_public_key(public_key),
    )
}

fn synthetic_asar(contents: &[u8]) -> Vec<u8> {
    let digest = hex_lower(&Sha256::digest(contents));
    let header = format!(
        concat!(
            "{{\"files\":{{\"main.js\":{{",
            "\"size\":{},\"offset\":\"0\",",
            "\"integrity\":{{\"algorithm\":\"SHA256\",",
            "\"hash\":\"{}\",\"blockSize\":4194304,",
            "\"blocks\":[\"{}\"]}}",
            "}}}}}}"
        ),
        contents.len(),
        digest,
        digest
    );
    let json = header.as_bytes();
    let payload = (4 + json.len() + 1 + 3) & !3;
    let header_pickle = 4 + payload;
    let mut output = Vec::new();
    output.extend_from_slice(&4_u32.to_le_bytes());
    output.extend_from_slice(&u32::try_from(header_pickle).unwrap().to_le_bytes());
    output.extend_from_slice(&u32::try_from(payload).unwrap().to_le_bytes());
    output.extend_from_slice(&u32::try_from(json.len()).unwrap().to_le_bytes());
    output.extend_from_slice(json);
    output.push(0);
    output.resize(8 + header_pickle, 0);
    output.extend_from_slice(contents);
    output
}

fn synthetic_bundle(declared_key: &str, app_asar: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o100644);
    let plist = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<plist version=\"1.0\"><dict>",
            "<key>CFBundleIdentifier</key><string>com.openai.codex</string>",
            "<key>CFBundleShortVersionString</key><string>26.721.81911</string>",
            "<key>CFBundleVersion</key><string>5973</string>",
            "<key>CFBundleExecutable</key><string>ChatGPT</string>",
            "<key>SUPublicEDKey</key><string>{}</string>",
            "</dict></plist>"
        ),
        declared_key
    );
    for (name, bytes) in [
        ("ChatGPT.app/Contents/Info.plist", plist.as_bytes()),
        (
            "ChatGPT.app/Contents/MacOS/ChatGPT",
            b"synthetic executable".as_slice(),
        ),
        ("ChatGPT.app/Contents/Resources/app.asar", app_asar),
    ] {
        writer.start_file(name, options).expect("start ZIP member");
        writer.write_all(bytes).expect("write ZIP member");
    }
    writer.finish().expect("finish ZIP").into_inner()
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
