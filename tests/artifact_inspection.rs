#![forbid(unsafe_code)]

use std::io::{Cursor, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::archive::{
    ArtifactContract, ArtifactTrust, inspect_artifact_bytes, inspect_artifact_file,
};
use ed25519_dalek::{Signer as _, SigningKey};
use rustix::rand::{GetRandomFlags, getrandom};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

#[test]
fn authenticates_and_inspects_one_canonical_synthetic_bundle() {
    let mut seed = [0_u8; 32];
    getrandom(&mut seed, GetRandomFlags::empty()).expect("obtain ephemeral test entropy");
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let declared_key = BASE64_STANDARD.encode(verifying_key);
    let app_asar = b"synthetic-asar-for-bounded-test";
    let archive = synthetic_bundle(&declared_key, app_asar);
    let signature = signing_key.sign(&archive).to_bytes();
    let expected_length = u64::try_from(archive.len()).expect("synthetic archive length fits");
    let contract = ArtifactContract {
        expected_length,
        signature_base64: BASE64_STANDARD.encode(signature),
        version: "26.721.81911".to_owned(),
        build: "5973".to_owned(),
    };
    let trust = ArtifactTrust::from_public_key(verifying_key);

    let inspection = inspect_artifact_bytes(&archive, &contract, &trust)
        .expect("valid synthetic bundle should inspect");

    assert_eq!(inspection.schema, 1);
    assert_eq!(inspection.kind, "artifact_inspection");
    assert!(inspection.signature.verified);
    assert_eq!(inspection.bundle.identifier, "com.openai.codex");
    assert_eq!(inspection.bundle.version, contract.version);
    assert_eq!(inspection.bundle.build, contract.build);
    assert_eq!(inspection.bundle.executable, "ChatGPT");
    assert_eq!(inspection.app_asar.bytes, app_asar.len() as u64);
    assert_eq!(inspection.zip.member_count, 3);
}

#[test]
fn rejects_a_critical_root_plist_key_with_a_non_string_value() {
    let mut seed = [0_u8; 32];
    getrandom(&mut seed, GetRandomFlags::empty()).expect("obtain ephemeral test entropy");
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let declared_key = BASE64_STANDARD.encode(verifying_key);
    let plist = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<plist version=\"1.0\"><dict>",
            "<key>CFBundleIdentifier</key><integer>1</integer>",
            "<key>CFBundleShortVersionString</key><string>26.721.81911</string>",
            "<key>CFBundleVersion</key><string>5973</string>",
            "<key>CFBundleExecutable</key><string>ChatGPT</string>",
            "<key>SUPublicEDKey</key><string>{}</string>",
            "</dict></plist>"
        ),
        declared_key
    );
    let archive = synthetic_bundle_with_plist(&plist, b"synthetic-asar");
    let signature = signing_key.sign(&archive).to_bytes();
    let contract = ArtifactContract {
        expected_length: u64::try_from(archive.len()).expect("synthetic archive length fits"),
        signature_base64: BASE64_STANDARD.encode(signature),
        version: "26.721.81911".to_owned(),
        build: "5973".to_owned(),
    };

    let error = inspect_artifact_bytes(
        &archive,
        &contract,
        &ArtifactTrust::from_public_key(verifying_key),
    )
    .expect_err("critical plist values must be strings");

    assert!(error.to_string().contains("is not a string"));
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_artifact_input_without_following_it() {
    use std::os::unix::fs::symlink;

    let (archive, contract, trust) = signed_synthetic_bundle();
    let directory = tempfile::tempdir().expect("temporary artifact directory");
    let regular = directory.path().join("artifact.zip");
    let alias = directory.path().join("artifact-link.zip");
    std::fs::write(&regular, archive).expect("write synthetic artifact");
    symlink(&regular, &alias).expect("create artifact symlink");

    let error = inspect_artifact_file(&alias, &contract, &trust)
        .expect_err("artifact symlink must be rejected");

    assert!(error.to_string().contains("symlink"));
}

fn signed_synthetic_bundle() -> (Vec<u8>, ArtifactContract, ArtifactTrust) {
    let mut seed = [0_u8; 32];
    getrandom(&mut seed, GetRandomFlags::empty()).expect("obtain ephemeral test entropy");
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let archive = synthetic_bundle(
        &BASE64_STANDARD.encode(verifying_key),
        b"synthetic-asar-for-file-input",
    );
    let signature = signing_key.sign(&archive).to_bytes();
    let contract = ArtifactContract {
        expected_length: u64::try_from(archive.len()).expect("synthetic archive length fits"),
        signature_base64: BASE64_STANDARD.encode(signature),
        version: "26.721.81911".to_owned(),
        build: "5973".to_owned(),
    };
    (
        archive,
        contract,
        ArtifactTrust::from_public_key(verifying_key),
    )
}

fn synthetic_bundle(declared_key: &str, app_asar: &[u8]) -> Vec<u8> {
    let plist = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<plist version=\"1.0\"><dict>",
            "<key>CFBundleIdentifier</key><string>com.openai.codex</string>",
            "<key>CFBundleShortVersionString</key>",
            "<string>26.721.81911</string>",
            "<key>CFBundleVersion</key><string>5973</string>",
            "<key>CFBundleExecutable</key><string>ChatGPT</string>",
            "<key>SUPublicEDKey</key><string>{}</string>",
            "</dict></plist>"
        ),
        declared_key
    );
    synthetic_bundle_with_plist(&plist, app_asar)
}

fn synthetic_bundle_with_plist(plist: &str, app_asar: &[u8]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o100644);
    writer
        .start_file("ChatGPT.app/Contents/Info.plist", options)
        .expect("start plist");
    writer
        .write_all(plist.as_bytes())
        .expect("write synthetic plist");
    writer
        .start_file("ChatGPT.app/Contents/MacOS/ChatGPT", options)
        .expect("start executable");
    writer
        .write_all(b"synthetic Mach-O placeholder")
        .expect("write synthetic executable");
    writer
        .start_file("ChatGPT.app/Contents/Resources/app.asar", options)
        .expect("start app.asar");
    writer
        .write_all(app_asar)
        .expect("write synthetic app.asar");

    writer.finish().expect("finish synthetic ZIP").into_inner()
}
