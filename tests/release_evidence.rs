#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use codex_linux_packager::appdir::{AppDirEntry, AppDirManifest};
use codex_linux_packager::appimage::{
    AppImageArtifact, AppImageManifest, OlderGlibcAudit, appimage_contract,
};
use codex_linux_packager::manifest::{PRODUCER_IDENTIFIER, SCHEMA_VERSION, to_json_line};
use codex_linux_packager::release::{
    GateStatus, ReleaseAssessmentScope, ReleaseReadinessReport, release_gate_catalog,
};
use codex_linux_packager::release_evidence::{
    ReleaseAttestationEvidence, ReleaseAttestationPayload, ReleaseEvidencePreparationRequest,
    ReleaseEvidenceVerificationRequest, ReleaseMaterialsRequest, ReleaseNoticeRequest,
    ReleaseSbomRequest, ReleaseSubject, SignedReleaseAttestation, build_notice_inventory,
    build_release_materials, build_release_sbom, create_signed_release_attestation,
    prepare_release_evidence_with_contract, publish_release_materials, verify_release_evidence,
    verify_signed_release_attestation,
};
use codex_linux_packager::update::{
    UpdateArtifact, UpdateContract, UpdatePayload, create_signed_update_manifest,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[test]
fn deterministic_spdx_sbom_covers_every_appdir_file_and_normalizes_local_roots() {
    let appdir = synthetic_appdir();
    let first_report = br#"{
        "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
            "licenses": ["MIT", "Apache-2.0"]
        },
        "codex-linux-packager 0.1.0 path+file:///first/private/root": {
            "licenses": ["MIT"]
        }
    }"#;
    let second_report = br#"{
        "codex-linux-packager 0.1.0 path+file:///unrelated/root": {
            "licenses": ["MIT"]
        },
        "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
            "licenses": ["Apache-2.0", "MIT"]
        }
    }"#;

    let first = build_release_sbom(&ReleaseSbomRequest {
        appdir: &appdir,
        appdir_manifest_sha256: DIGEST_A,
        artifact_name: "codex-desktop-unofficial-x86_64.AppImage",
        artifact_sha256: DIGEST_B,
        source_commit: "1111111111111111111111111111111111111111",
        source_tree: "2222222222222222222222222222222222222222",
        created_at: "2026-07-30T21:11:57Z",
        cargo_license_report: first_report,
    })
    .expect("first deterministic SBOM");
    let second = build_release_sbom(&ReleaseSbomRequest {
        appdir: &appdir,
        appdir_manifest_sha256: DIGEST_A,
        artifact_name: "codex-desktop-unofficial-x86_64.AppImage",
        artifact_sha256: DIGEST_B,
        source_commit: "1111111111111111111111111111111111111111",
        source_tree: "2222222222222222222222222222222222222222",
        created_at: "2026-07-30T21:11:57Z",
        cargo_license_report: second_report,
    })
    .expect("second deterministic SBOM");

    assert_eq!(first, second);
    assert_eq!(first.spdx_version, "SPDX-2.3");
    assert_eq!(first.data_license, "CC0-1.0");
    assert_eq!(first.files.len(), appdir.entries.len());
    assert_eq!(first.packages.len(), 3, "AppImage plus two Rust packages");
    assert_eq!(
        first.document_describes.len(),
        first.packages.len() + first.files.len()
    );
    assert_eq!(
        first.document_describes.first().map(String::as_str),
        Some("SPDXRef-Package-AppImage")
    );
    assert!(
        first
            .document_describes
            .contains(&"SPDXRef-File-000001".to_owned())
    );
    assert!(
        first.relationships.is_empty(),
        "filesAnalyzed=false packages must not claim file containment"
    );
    assert_eq!(
        first
            .packages
            .iter()
            .find(|package| package.name == "codex-linux-packager")
            .expect("local package")
            .download_location,
        "NOASSERTION"
    );
    assert_eq!(
        first
            .packages
            .iter()
            .find(|package| package.name == "serde")
            .expect("registry package")
            .license_concluded,
        "NOASSERTION"
    );
    assert_eq!(
        first
            .packages
            .iter()
            .find(|package| package.name == "serde")
            .expect("registry package")
            .license_comments,
        "cargo_deny_observed_license_identifiers=[Apache-2.0,MIT]; no_license_expression_or_conclusion_is_asserted"
    );

    let encoded = to_json_line(&first).expect("canonical JSON");
    assert!(encoded.ends_with('\n'));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&encoded).expect("valid JSON")["files"]
            .as_array()
            .expect("file array")
            .len(),
        appdir.entries.len()
    );

    for ambiguous_report in [
        br#"{
            "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
                "licenses": ["MIT"]
            },
            "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
                "licenses": ["Apache-2.0"]
            }
        }"#
        .as_slice(),
        br#"{
            "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
                "licenses": ["MIT", "MIT"]
            }
        }"#
        .as_slice(),
    ] {
        assert!(
            build_release_sbom(&ReleaseSbomRequest {
                appdir: &appdir,
                appdir_manifest_sha256: DIGEST_A,
                artifact_name: "codex-desktop-unofficial-x86_64.AppImage",
                artifact_sha256: DIGEST_B,
                source_commit: "1111111111111111111111111111111111111111",
                source_tree: "2222222222222222222222222222222222222222",
                created_at: "2026-07-30T21:11:57Z",
                cargo_license_report: ambiguous_report,
            })
            .is_err(),
            "ambiguous Cargo license input must be rejected"
        );
    }
}

#[test]
fn notice_inventory_binds_embedded_notices_and_observed_rust_license_identifiers() {
    let appdir = synthetic_appdir();
    let report = br#"{
        "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
            "licenses": ["MIT", "Apache-2.0"]
        },
        "codex-linux-packager 0.1.0 path+file:///private/root": {
            "licenses": ["MIT"]
        }
    }"#;

    let inventory = build_notice_inventory(&ReleaseNoticeRequest {
        appdir: &appdir,
        appdir_manifest_sha256: DIGEST_A,
        sbom_sha256: DIGEST_B,
        cargo_license_report: report,
    })
    .expect("deterministic notice inventory");

    assert_eq!(inventory.schema, 1);
    assert_eq!(inventory.kind, "linux_x86_64_release_notice_inventory");
    assert_eq!(inventory.embedded_notice_files.len(), 1);
    assert_eq!(
        inventory.embedded_notice_files[0].path,
        "usr/lib/codex-desktop/LICENSE"
    );
    assert_eq!(inventory.rust_packages.len(), 2);
    assert_eq!(inventory.coverage.appdir_entries, 2);
    assert_eq!(inventory.coverage.embedded_notice_files, 1);
    assert_eq!(inventory.coverage.rust_packages, 2);
    assert_eq!(
        inventory.review_status,
        "generated_inventory_requires_independent_license_review"
    );
    assert!(
        inventory
            .rust_packages
            .iter()
            .any(|package| package.name == "serde"
                && package.license_identifiers_observed == ["Apache-2.0", "MIT"])
    );
}

#[test]
fn release_attestation_is_pinned_canonical_and_tamper_evident() {
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let contract = synthetic_update_contract(&signing_key);
    let payload = synthetic_attestation_payload();
    let attestation =
        create_signed_release_attestation(&payload, &signing_key.to_bytes()).expect("sign");
    let encoded = to_json_line(&attestation).expect("canonical attestation");
    let verified = verify_signed_release_attestation(encoded.as_bytes(), &contract)
        .expect("verify with independent pin");
    assert_eq!(verified.attestation, attestation);
    assert_eq!(
        verified.signed_payload_sha256,
        digest(to_json_line(&payload).expect("payload JSON").as_bytes())
    );

    let mut tampered = attestation.clone();
    tampered.payload.source_tree = "33".repeat(20);
    assert!(
        verify_signed_release_attestation(
            to_json_line(&tampered)
                .expect("tampered attestation")
                .as_bytes(),
            &contract,
        )
        .is_err()
    );

    let mut unknown = serde_json::to_value(&attestation).expect("attestation value");
    unknown.as_object_mut().expect("object").insert(
        "public_key_base64".to_owned(),
        serde_json::json!("self-supplied"),
    );
    let unknown = format!(
        "{}\n",
        serde_json::to_string(&unknown).expect("unknown JSON")
    );
    assert!(verify_signed_release_attestation(unknown.as_bytes(), &contract).is_err());

    let attacker = SigningKey::from_bytes(&[10_u8; 32]);
    let attacker_contract = synthetic_update_contract(&attacker);
    assert!(verify_signed_release_attestation(encoded.as_bytes(), &attacker_contract).is_err());

    let mut invalid_date = payload;
    invalid_date.created_at = "2026-02-29T25:61:61Z".to_owned();
    assert!(
        create_signed_release_attestation(&invalid_date, &signing_key.to_bytes()).is_err(),
        "a digit-shaped but impossible UTC timestamp must be rejected"
    );

    let SignedReleaseAttestation {
        signature_base64, ..
    } = attestation;
    assert!(!signature_base64.is_empty());
}

#[test]
fn release_materials_bind_sorted_checksums_sbom_notices_and_attestation() {
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let contract = synthetic_update_contract(&signing_key);
    let appdir = synthetic_appdir();
    let report = br#"{
        "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
            "licenses": ["MIT", "Apache-2.0"]
        },
        "codex-linux-packager 0.1.0 path+file:///private/root": {
            "licenses": ["MIT"]
        }
    }"#;
    let request = ReleaseMaterialsRequest {
        appdir: &appdir,
        appdir_manifest_sha256: DIGEST_A,
        appimage: ReleaseSubject {
            name: "codex-desktop-unofficial-x86_64.AppImage".to_owned(),
            bytes: 512_000_000,
            sha256: "11".repeat(32),
        },
        provenance: ReleaseSubject {
            name: "provenance.json".to_owned(),
            bytes: 11_000,
            sha256: "12".repeat(32),
        },
        update_manifest: ReleaseSubject {
            name: "codex-linux-x86_64-update.json".to_owned(),
            bytes: 1_100,
            sha256: "14".repeat(32),
        },
        appdir_manifest_bytes: 12_000,
        release_readiness_sha256: DIGEST_C,
        release_readiness_bytes: 8_000,
        cargo_lock_sha256: "17".repeat(32),
        cargo_lock_bytes: 4_000,
        source_commit: "11".repeat(20),
        source_tree: "22".repeat(20),
        created_at: "2026-07-30T21:11:57Z",
        cargo_license_report: report,
        signing_seed: &signing_key.to_bytes(),
    };

    let first = build_release_materials(&request).expect("release materials");
    let second = build_release_materials(&request).expect("deterministic release materials");
    assert_eq!(first, second);
    assert_eq!(
        first
            .sha256sums
            .lines()
            .map(|line| &line[66..])
            .collect::<Vec<_>>(),
        vec![
            "Cargo.lock",
            "appdir-manifest.json",
            "codex-desktop-unofficial-x86_64.AppImage",
            "codex-linux-x86_64-update.json",
            "codex-linux-x86_64.spdx.json",
            "provenance.json",
            "release-readiness.json",
            "third-party-notices.json",
        ]
    );

    let attestation_bytes = to_json_line(&first.attestation).expect("attestation JSON");
    let verified = verify_signed_release_attestation(attestation_bytes.as_bytes(), &contract)
        .expect("verify complete materials");
    assert_eq!(verified.attestation, first.attestation);
    assert_eq!(
        first
            .attestation
            .payload
            .subjects
            .iter()
            .find(|subject| subject.name == "SHA256SUMS")
            .expect("checksums subject")
            .sha256,
        digest(first.sha256sums.as_bytes())
    );
    assert_eq!(
        first.attestation.payload.evidence.sbom_sha256,
        digest(to_json_line(&first.sbom).expect("SBOM JSON").as_bytes())
    );
    assert_eq!(
        first.attestation.payload.evidence.notice_inventory_sha256,
        digest(
            to_json_line(&first.notices)
                .expect("notices JSON")
                .as_bytes()
        )
    );
}

#[test]
fn release_material_publication_is_verified_atomic_and_no_replace() {
    let (contract, materials) = synthetic_release_materials();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let output = temporary.path().join("release-evidence");

    let publication =
        publish_release_materials(&materials, &output, &contract).expect("publish materials");
    assert_eq!(publication.output, output);
    assert_eq!(publication.files.len(), 4);
    let names = fs::read_dir(&output)
        .expect("read publication")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .into_string()
                .expect("UTF-8 filename")
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        [
            "SHA256SUMS",
            "codex-linux-x86_64.spdx.json",
            "release-attestation.json",
            "third-party-notices.json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    for name in &names {
        assert_eq!(
            fs::metadata(output.join(name))
                .expect("published metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }
    let before = fs::read(output.join("release-attestation.json")).expect("attestation bytes");
    assert!(publish_release_materials(&materials, &output, &contract).is_err());
    assert_eq!(
        fs::read(output.join("release-attestation.json")).expect("preserved attestation"),
        before
    );

    let mut tampered = materials;
    tampered.sbom.name.push_str("-tampered");
    let rejected = temporary.path().join("rejected");
    assert!(publish_release_materials(&tampered, &rejected, &contract).is_err());
    assert!(!rejected.exists());
}

#[test]
fn complete_synthetic_chain_prepares_one_reconciled_release_evidence_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let contract = synthetic_update_contract(&signing_key);
    let source_commit = "11".repeat(20);
    let source_tree = "22".repeat(20);
    let created_at = "2026-07-30T21:11:57Z";

    let appimage_path = root.join("codex-desktop-unofficial-x86_64.AppImage");
    let mut appimage_bytes = vec![0_u8; 256];
    appimage_bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    appimage_bytes[8..12].copy_from_slice(b"AI\x02\0");
    appimage_bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    fs::write(&appimage_path, &appimage_bytes).expect("synthetic AppImage");
    fs::set_permissions(&appimage_path, fs::Permissions::from_mode(0o755)).expect("AppImage mode");
    let appimage_sha256 = digest(&appimage_bytes);

    let mut appdir = synthetic_appdir();
    appdir.update_manifest_url = contract.manifest_url.clone();
    appdir.update_public_key_sha256 = contract.public_key_sha256.clone();
    let appdir_path = root.join("appdir-manifest.json");
    let appdir_bytes = write_canonical(&appdir_path, &appdir);
    let appdir_sha256 = digest(&appdir_bytes);

    let appimage_contract = appimage_contract().expect("embedded AppImage contract");
    let provenance = AppImageManifest {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_appimage".to_owned(),
        publication_scope:
            "bytes_at_durable_commit_boundary_under_documented_threat_model".to_owned(),
        application_version: appdir.application_version.clone(),
        application_build: appdir.application_build.clone(),
        artifact: AppImageArtifact {
            path: contract.artifact_name.clone(),
            sha256: appimage_sha256.clone(),
            bytes: u64::try_from(appimage_bytes.len()).expect("AppImage length"),
            mode: "0755".to_owned(),
        },
        reproduction_sha256: appimage_sha256.clone(),
        appdir_manifest_sha256: appdir_sha256.clone(),
        reproduction_appdir_manifest_sha256: appdir_sha256.clone(),
        source_date_epoch: appdir.source_date_epoch,
        appimagetool: appimage_contract.appimagetool,
        type2_runtime: appimage_contract.type2_runtime,
        bubblewrap_sha256: DIGEST_A.to_owned(),
        readelf_sha256: DIGEST_B.to_owned(),
        compression: appimage_contract.compression,
        network_isolation:
            "bubblewrap_unshare_net_for_both_builds_extraction_and_host_launches_plus_oci_network_none_for_older_glibc_launch"
                .to_owned(),
        process_containment:
            "bubblewrap_unshare_pid_die_with_parent_and_process_group_timeout_cleanup".to_owned(),
        twice_built_byte_identical: true,
        extracted_tree_verified: true,
        runtime_derivation:
            "exact_pinned_runtime_except_appimagetool_filled_16_byte_digest_md5_section".to_owned(),
        elf_audit: Vec::new(),
        launch_audits: Vec::new(),
        older_glibc_audit: OlderGlibcAudit {
            image_id: format!("sha256:{DIGEST_A}"),
            oci_runtime_sha256: DIGEST_A.to_owned(),
            sudo_sha256: None,
            glibc_version: "2.36".to_owned(),
            package_manifest_sha256: DIGEST_B.to_owned(),
            package_count: 1,
            timed_out_after_success: true,
            packaged_mode: true,
            app_server_handshake: true,
            window_ready: true,
            sandbox_policy:
                "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox_network_disabled_capabilities_dropped"
                    .to_owned(),
            log_sha256: DIGEST_C.to_owned(),
            log_bytes: 1,
        },
        release_status:
            "engineering_candidate_only_legal_branding_signing_matrix_and_release_gates_not_implied"
                .to_owned(),
    };
    let provenance_path = root.join("provenance.json");
    let provenance_bytes = write_canonical(&provenance_path, &provenance);
    let provenance_sha256 = digest(&provenance_bytes);

    let release_tag = format!(
        "codex-app-{}-{}",
        appdir.application_version, appdir.application_build
    );
    let update = create_signed_update_manifest(
        &UpdatePayload {
            schema: SCHEMA_VERSION,
            producer: PRODUCER_IDENTIFIER.to_owned(),
            kind: "linux_x86_64_update_payload".to_owned(),
            channel: contract.channel.clone(),
            target: contract.target.clone(),
            release_tag: release_tag.clone(),
            application_version: appdir.application_version.clone(),
            application_build: appdir.application_build.clone(),
            source_commit: source_commit.clone(),
            published_at: created_at.to_owned(),
            artifact: UpdateArtifact {
                name: contract.artifact_name.clone(),
                url: format!(
                    "https://github.com/{}/releases/download/{release_tag}/{}",
                    contract.release_repository, contract.artifact_name
                ),
                bytes: u64::try_from(appimage_bytes.len()).expect("AppImage length"),
                sha256: appimage_sha256.clone(),
                provenance_sha256: provenance_sha256.clone(),
            },
        },
        &signing_key.to_bytes(),
    )
    .expect("signed update manifest");
    let update_path = root.join("codex-linux-x86_64-update.json");
    write_canonical(&update_path, &update);

    let cargo_lock_path = root.join("Cargo.lock");
    let cargo_lock = b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"codex-linux-packager\"\nversion = \"0.1.0\"\n";
    fs::write(&cargo_lock_path, cargo_lock).expect("Cargo.lock");
    let cargo_lock_sha256 = digest(cargo_lock);
    let license_report_path = root.join("cargo-deny-licenses.json");
    fs::write(
        &license_report_path,
        br#"{"codex-linux-packager 0.1.0 path+file:///synthetic":{"licenses":["MIT"]}}"#,
    )
    .expect("license report");

    let mut gates = release_gate_catalog();
    for gate in gates.iter_mut().take(7) {
        gate.status = GateStatus::Satisfied;
        gate.evidence = "synthetic exact engineering evidence".to_owned();
        gate.required_action = "No further engineering evidence is required for this exact digest set; later byte changes require reassessment.".to_owned();
    }
    let blocking_gate_ids = gates
        .iter()
        .filter(|gate| gate.status == GateStatus::NotSatisfied)
        .map(|gate| gate.id.clone())
        .collect();
    let readiness = ReleaseReadinessReport {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "release_readiness_assessment".to_owned(),
        publication_scope: "bytes_at_durable_commit_boundary_under_documented_threat_model"
            .to_owned(),
        assessment_scope: ReleaseAssessmentScope {
            stage_provenance_sha256: DIGEST_A.to_owned(),
            native_manifest_sha256: DIGEST_A.to_owned(),
            runtime_manifest_sha256: DIGEST_B.to_owned(),
            appdir_manifest_sha256: appdir_sha256,
            appimage_provenance_sha256: provenance_sha256,
            artifact_sha256: appimage_sha256,
            artifact_bytes: u64::try_from(appimage_bytes.len()).expect("AppImage length"),
            cargo_lock_sha256,
        },
        engineering_candidate: true,
        automatic_publication_permitted: true,
        stable_publication_permitted: false,
        gates,
        blocking_gate_ids,
        release_status: "automatic_engineering_publication_permitted_not_stable_approval"
            .to_owned(),
    };
    let readiness_path = root.join("release-readiness.json");
    write_canonical(&readiness_path, &readiness);

    let key_path = root.join("release.seed");
    fs::write(&key_path, signing_key.to_bytes()).expect("private seed");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("private seed mode");
    let output = root.join("release-evidence");
    let publication = prepare_release_evidence_with_contract(
        &ReleaseEvidencePreparationRequest {
            appimage: appimage_path,
            provenance: provenance_path,
            update_manifest: update_path,
            release_readiness: readiness_path,
            appdir_manifest: appdir_path,
            cargo_lock: cargo_lock_path,
            cargo_license_report: license_report_path,
            private_key: key_path,
            source_commit,
            source_tree,
            created_at: created_at.to_owned(),
            output: output.clone(),
        },
        &contract,
    )
    .expect("prepare complete release evidence");

    assert_eq!(publication.output, output);
    let attestation = fs::read(output.join("release-attestation.json")).expect("attestation");
    verify_signed_release_attestation(&attestation, &contract).expect("verify prepared evidence");
    let verification = verify_release_evidence(
        &ReleaseEvidenceVerificationRequest {
            evidence: output.clone(),
            appimage: root.join("codex-desktop-unofficial-x86_64.AppImage"),
            provenance: root.join("provenance.json"),
            update_manifest: root.join("codex-linux-x86_64-update.json"),
            release_readiness: root.join("release-readiness.json"),
            appdir_manifest: root.join("appdir-manifest.json"),
            cargo_lock: root.join("Cargo.lock"),
            source_commit: "11".repeat(20),
            source_tree: "22".repeat(20),
        },
        &contract,
    )
    .expect("keyless verification");
    assert_eq!(
        verification.verification_status,
        "signed_release_evidence_verified_for_automatic_engineering_publication_not_stable_approval"
    );

    let mut forged_readiness = readiness.clone();
    forged_readiness.gates[7].status = GateStatus::Satisfied;
    forged_readiness.gates[7].evidence = "self-asserted operational approval".to_owned();
    forged_readiness.blocking_gate_ids = forged_readiness
        .gates
        .iter()
        .filter(|gate| gate.status == GateStatus::NotSatisfied)
        .map(|gate| gate.id.clone())
        .collect();
    let forged_readiness_path = root.join("forged-release-readiness.json");
    write_canonical(&forged_readiness_path, &forged_readiness);
    assert!(
        prepare_release_evidence_with_contract(
            &ReleaseEvidencePreparationRequest {
                appimage: root.join("codex-desktop-unofficial-x86_64.AppImage"),
                provenance: root.join("provenance.json"),
                update_manifest: root.join("codex-linux-x86_64-update.json"),
                release_readiness: forged_readiness_path,
                appdir_manifest: root.join("appdir-manifest.json"),
                cargo_lock: root.join("Cargo.lock"),
                cargo_license_report: root.join("cargo-deny-licenses.json"),
                private_key: root.join("release.seed"),
                source_commit: "11".repeat(20),
                source_tree: "22".repeat(20),
                created_at: created_at.to_owned(),
                output: root.join("forged-release-evidence"),
            },
            &contract,
        )
        .is_err(),
        "self-asserted satisfaction of an operational gate must be rejected"
    );

    fs::write(
        output.join("codex-linux-x86_64.spdx.json"),
        b"{\"tampered\":true}\n",
    )
    .expect("tamper owned synthetic output");
    assert!(
        verify_release_evidence(
            &ReleaseEvidenceVerificationRequest {
                evidence: output,
                appimage: root.join("codex-desktop-unofficial-x86_64.AppImage"),
                provenance: root.join("provenance.json"),
                update_manifest: root.join("codex-linux-x86_64-update.json"),
                release_readiness: root.join("release-readiness.json"),
                appdir_manifest: root.join("appdir-manifest.json"),
                cargo_lock: root.join("Cargo.lock"),
                source_commit: "11".repeat(20),
                source_tree: "22".repeat(20),
            },
            &contract,
        )
        .is_err()
    );
}

fn synthetic_appdir() -> AppDirManifest {
    AppDirManifest {
        schema: 1,
        producer: "io.github.bearhuddleston.codex-linux-packager.rust".to_owned(),
        kind: "linux_x86_64_appdir".to_owned(),
        publication_scope: "bytes_at_durable_commit_boundary_under_documented_threat_model"
            .to_owned(),
        runtime_manifest_sha256: DIGEST_C.to_owned(),
        application_version: "26.721.81911".to_owned(),
        application_build: "5973".to_owned(),
        updater_sha256: DIGEST_A.to_owned(),
        update_config_sha256: DIGEST_B.to_owned(),
        update_manifest_url: "https://example.invalid/update.json".to_owned(),
        update_public_key_sha256: DIGEST_C.to_owned(),
        update_policy: "background_full_download_activate_for_next_launch_keep_versioned_rollback"
            .to_owned(),
        source_date_epoch: 1_785_445_917,
        packaged_executable: "usr/lib/codex-desktop/codex-desktop".to_owned(),
        display_backend_policy:
            "auto_default_explicit_wayland_or_x11_via_CODEX_LINUX_DISPLAY_BACKEND".to_owned(),
        sandbox_policy: "chromium_user_namespace_sandbox_disable_setuid_sandbox_never_no-sandbox"
            .to_owned(),
        identity_notice:
            "unofficial_and_unaffiliated_tooling_no_payload_redistribution_or_trademark_rights"
                .to_owned(),
        icon_license: "original_generic_non_branding_icon_MIT".to_owned(),
        entries: vec![
            AppDirEntry {
                path: "AppRun".to_owned(),
                source: "generated:AppRun".to_owned(),
                sha256: DIGEST_A.to_owned(),
                bytes: 42,
                mode: "0755".to_owned(),
            },
            AppDirEntry {
                path: "usr/lib/codex-desktop/LICENSE".to_owned(),
                source: "runtime:LICENSE".to_owned(),
                sha256: DIGEST_B.to_owned(),
                bytes: 1_096,
                mode: "0644".to_owned(),
            },
        ],
    }
}

fn synthetic_release_materials() -> (
    UpdateContract,
    codex_linux_packager::release_evidence::ReleaseMaterials,
) {
    let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
    let contract = synthetic_update_contract(&signing_key);
    let appdir = synthetic_appdir();
    let report = br#"{
        "serde 1.0.228 registry+https://github.com/rust-lang/crates.io-index": {
            "licenses": ["MIT", "Apache-2.0"]
        },
        "codex-linux-packager 0.1.0 path+file:///private/root": {
            "licenses": ["MIT"]
        }
    }"#;
    let seed = signing_key.to_bytes();
    let materials = build_release_materials(&ReleaseMaterialsRequest {
        appdir: &appdir,
        appdir_manifest_sha256: DIGEST_A,
        appimage: ReleaseSubject {
            name: "codex-desktop-unofficial-x86_64.AppImage".to_owned(),
            bytes: 512_000_000,
            sha256: "11".repeat(32),
        },
        provenance: ReleaseSubject {
            name: "provenance.json".to_owned(),
            bytes: 11_000,
            sha256: "12".repeat(32),
        },
        update_manifest: ReleaseSubject {
            name: "codex-linux-x86_64-update.json".to_owned(),
            bytes: 1_100,
            sha256: "14".repeat(32),
        },
        appdir_manifest_bytes: 12_000,
        release_readiness_sha256: DIGEST_C,
        release_readiness_bytes: 8_000,
        cargo_lock_sha256: "17".repeat(32),
        cargo_lock_bytes: 4_000,
        source_commit: "11".repeat(20),
        source_tree: "22".repeat(20),
        created_at: "2026-07-30T21:11:57Z",
        cargo_license_report: report,
        signing_seed: &seed,
    })
    .expect("synthetic materials");
    (contract, materials)
}

fn synthetic_attestation_payload() -> ReleaseAttestationPayload {
    let subjects = [
        ("Cargo.lock", 4_000_u64, "17"),
        ("SHA256SUMS", 500_u64, "16"),
        ("appdir-manifest.json", 12_000, "aa"),
        (
            "codex-desktop-unofficial-x86_64.AppImage",
            512_000_000,
            "11",
        ),
        ("codex-linux-x86_64-update.json", 1_100, "14"),
        ("codex-linux-x86_64.spdx.json", 10_000, "15"),
        ("provenance.json", 11_000, "12"),
        ("release-readiness.json", 8_000, "cc"),
        ("third-party-notices.json", 20_000, "13"),
    ]
    .into_iter()
    .map(|(name, bytes, digest_prefix)| ReleaseSubject {
        name: name.to_owned(),
        bytes,
        sha256: digest_prefix.repeat(32),
    })
    .collect();
    ReleaseAttestationPayload {
        schema: SCHEMA_VERSION,
        producer: PRODUCER_IDENTIFIER.to_owned(),
        kind: "linux_x86_64_release_attestation_payload".to_owned(),
        predicate_type: "https://github.com/BearHuddleston/codex-linux-packager/attestation/v1"
            .to_owned(),
        channel: "automatic".to_owned(),
        target: "linux-x86_64".to_owned(),
        release_repository: "BearHuddleston/codex-linux-packager".to_owned(),
        release_tag: "codex-app-26.721.81911-5973".to_owned(),
        application_version: "26.721.81911".to_owned(),
        application_build: "5973".to_owned(),
        source_commit: "11".repeat(20),
        source_tree: "22".repeat(20),
        created_at: "2026-07-30T21:11:57Z".to_owned(),
        subjects,
        evidence: ReleaseAttestationEvidence {
            appdir_manifest_sha256: DIGEST_A.to_owned(),
            appimage_provenance_sha256: "12".repeat(32),
            update_manifest_sha256: "14".repeat(32),
            release_readiness_sha256: DIGEST_C.to_owned(),
            cargo_lock_sha256: "17".repeat(32),
            sbom_sha256: "15".repeat(32),
            notice_inventory_sha256: "13".repeat(32),
            checksums_sha256: "16".repeat(32),
        },
        publication_status:
            "release_evidence_prepared_for_automatic_engineering_publication_not_stable_approval"
                .to_owned(),
    }
}

fn synthetic_update_contract(signing_key: &SigningKey) -> UpdateContract {
    let public_key = signing_key.verifying_key().to_bytes();
    UpdateContract {
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
        public_key_sha256: digest(&public_key),
        max_manifest_bytes: 65_536,
        max_appimage_bytes: 1_073_741_824,
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_canonical(path: &Path, value: &impl serde::Serialize) -> Vec<u8> {
    let bytes = to_json_line(value).expect("canonical JSON").into_bytes();
    fs::write(path, &bytes).expect("write canonical JSON");
    bytes
}
