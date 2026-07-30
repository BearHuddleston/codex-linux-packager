#![forbid(unsafe_code)]

use codex_linux_packager::release::{
    GateStatus, ReleaseAssessmentRequest, assess_release_readiness, release_gate_catalog,
};

#[test]
fn release_gate_catalog_never_implies_external_approval() {
    let gates = release_gate_catalog();
    let identifiers = gates
        .iter()
        .map(|gate| gate.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        identifiers,
        [
            "authenticated_artifact_chain",
            "pinned_supply_chain_inputs",
            "twice_built_reproducibility",
            "native_electron_abi_round_trips",
            "complete_final_elf_audit",
            "host_wayland_x11_extract_and_run",
            "controlled_older_glibc_launch",
            "payload_redistribution_authority",
            "trademark_and_branding_authority",
            "complete_notices_and_deterministic_sbom",
            "signed_checksums_and_protected_keys",
            "signed_attestation_exact_commit_and_artifacts",
            "protected_release_automation",
            "kde_gnome_wayland_x11_fuse_matrix",
            "publication_rollback_and_recovery",
            "frozen_independent_review",
        ]
    );

    for id in [
        "payload_redistribution_authority",
        "trademark_and_branding_authority",
        "complete_notices_and_deterministic_sbom",
        "signed_checksums_and_protected_keys",
        "signed_attestation_exact_commit_and_artifacts",
        "protected_release_automation",
        "kde_gnome_wayland_x11_fuse_matrix",
        "publication_rollback_and_recovery",
        "frozen_independent_review",
    ] {
        let gate = gates
            .iter()
            .find(|gate| gate.id == id)
            .expect("required release gate");
        assert_eq!(gate.status, GateStatus::NotSatisfied);
        assert!(gate.blocking);
    }
}

#[test]
fn release_assessment_rejects_non_absolute_and_malformed_evidence() {
    let request = ReleaseAssessmentRequest {
        stage: "stage".into(),
        native_manifest: "native.json".into(),
        runtime_manifest: "runtime.json".into(),
        appdir_manifest: "appdir.json".into(),
        appimage_provenance: "provenance.json".into(),
        artifact: "candidate.AppImage".into(),
        cargo_lock: "Cargo.lock".into(),
    };

    let error = assess_release_readiness(&request).expect_err("relative evidence must fail");
    assert!(error.to_string().contains("must be absolute"));
}
