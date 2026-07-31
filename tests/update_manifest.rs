#![forbid(unsafe_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use codex_linux_packager::update::{
    CurrentRelease, SignedUpdateManifest, UpdateArtifact, UpdateContract, UpdatePayload,
    create_signed_update_manifest, select_update, verify_signed_update_manifest,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn fixture() -> (UpdateContract, UpdatePayload, SigningKey) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let fingerprint = digest(&public_key);
    let contract = UpdateContract {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_update_contract".to_owned(),
        channel: "automatic".to_owned(),
        target: "linux-x86_64".to_owned(),
        manifest_url:
            "https://github.com/BearHuddleston/codex-linux-packager/releases/latest/download/codex-linux-x86_64-update.json"
                .to_owned(),
        release_repository: "BearHuddleston/codex-linux-packager".to_owned(),
        artifact_name: "codex-desktop-unofficial-x86_64.AppImage".to_owned(),
        public_key_base64: BASE64_STANDARD.encode(public_key),
        public_key_sha256: fingerprint,
        max_manifest_bytes: 65_536,
        max_appimage_bytes: 1_073_741_824,
    };
    let payload = UpdatePayload {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_update_payload".to_owned(),
        channel: "automatic".to_owned(),
        target: "linux-x86_64".to_owned(),
        release_tag: "codex-app-26.801.10001-6001".to_owned(),
        application_version: "26.801.10001".to_owned(),
        application_build: "6001".to_owned(),
        source_commit: "a1".repeat(20),
        published_at: "2026-07-30T18:00:00Z".to_owned(),
        artifact: UpdateArtifact {
            name: "codex-desktop-unofficial-x86_64.AppImage".to_owned(),
            url: "https://github.com/BearHuddleston/codex-linux-packager/releases/download/codex-app-26.801.10001-6001/codex-desktop-unofficial-x86_64.AppImage".to_owned(),
            bytes: 512_000_000,
            sha256: "ab".repeat(32),
            provenance_sha256: "cd".repeat(32),
        },
    };
    (contract, payload, signing_key)
}

#[test]
fn signed_manifest_is_canonical_pinned_and_selects_only_a_newer_release() {
    let (contract, payload, signing_key) = fixture();
    let manifest = create_signed_update_manifest(&payload, &signing_key.to_bytes())
        .expect("sign synthetic manifest");
    let encoded = to_json_line(&manifest).expect("canonical signed manifest");
    let verified = verify_signed_update_manifest(encoded.as_bytes(), &contract)
        .expect("verify pinned synthetic manifest");

    assert_eq!(verified.manifest, manifest);
    assert_eq!(
        verified.signed_payload_sha256,
        digest(to_json_line(&payload).expect("payload JSON").as_bytes())
    );
    assert!(
        select_update(
            &CurrentRelease {
                application_version: "26.721.81911".to_owned(),
                application_build: "5973".to_owned(),
            },
            &verified.manifest.payload,
        )
        .expect("compare releases")
    );
    assert!(
        !select_update(
            &CurrentRelease {
                application_version: "26.801.10001".to_owned(),
                application_build: "6001".to_owned(),
            },
            &verified.manifest.payload,
        )
        .expect("equal release is current")
    );
    assert!(
        !select_update(
            &CurrentRelease {
                application_version: "27.1.0".to_owned(),
                application_build: "1".to_owned(),
            },
            &verified.manifest.payload,
        )
        .expect("downgrade is rejected")
    );
}

#[test]
fn manifest_rejects_tampering_unknown_fields_and_a_self_supplied_key() {
    let (contract, payload, signing_key) = fixture();
    let manifest = create_signed_update_manifest(&payload, &signing_key.to_bytes())
        .expect("sign synthetic manifest");
    let mut tampered = manifest.clone();
    tampered.payload.artifact.sha256 = "ef".repeat(32);
    let tampered_bytes = to_json_line(&tampered).expect("tampered JSON");
    assert!(verify_signed_update_manifest(tampered_bytes.as_bytes(), &contract).is_err());

    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value.as_object_mut().expect("manifest object").insert(
        "public_key_base64".to_owned(),
        serde_json::json!("attacker"),
    );
    let unknown = format!("{}\n", serde_json::to_string(&value).expect("unknown JSON"));
    assert!(verify_signed_update_manifest(unknown.as_bytes(), &contract).is_err());

    let SignedUpdateManifest {
        signature_base64, ..
    } = manifest;
    assert!(!signature_base64.is_empty());

    let mut invalid_date = payload;
    invalid_date.published_at = "2026-02-29T25:61:61Z".to_owned();
    assert!(
        create_signed_update_manifest(&invalid_date, &signing_key.to_bytes()).is_err(),
        "a digit-shaped but impossible UTC timestamp must be rejected"
    );
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
