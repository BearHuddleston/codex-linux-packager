#![forbid(unsafe_code)]

use codex_linux_packager::feed::{ArtifactMetadata, FeedInspection, FeedSource, ReleaseMetadata};
use codex_linux_packager::runtime::RuntimeApplicationContract;
use codex_linux_packager::upstream::{
    EngineeringCandidateIdentity, UpstreamAction, assess_upstream_status,
    engineering_candidate_record,
};

#[test]
fn embedded_candidate_record_is_bound_to_the_last_assessed_artifact() {
    let record =
        engineering_candidate_record().expect("embedded engineering candidate must validate");

    assert_eq!(record.schema, 1);
    assert_eq!(
        record.producer,
        "io.github.bearhuddleston.codex-linux-packager.rust"
    );
    assert_eq!(record.kind, "engineering_candidate_record");
    assert_eq!(record.source_commit.len(), 40);
    assert!(!record.application.version.is_empty());
    assert!(!record.application.build.is_empty());
    assert_eq!(record.assessment_scope.artifact_sha256.len(), 64);
    assert!(record.assessment_scope.artifact_bytes > 0);
    assert!(record.engineering_candidate);
    assert!(!record.stable_publication_permitted);
    assert_eq!(
        record.automatic_publication_permitted,
        record.release_status == "automatic_engineering_publication_permitted_not_stable_approval"
    );
    if !record.automatic_publication_permitted {
        assert_eq!(record.release_status, "not_release_approved_do_not_publish");
    }
}

#[test]
fn upstream_state_machine_never_rebuilds_an_unreviewed_contract() {
    let candidate = EngineeringCandidateIdentity {
        version: "26.721.81911".to_owned(),
        build: "5973".to_owned(),
    };
    let current_contract = contract("26.721.81911", "5973");

    let current =
        assess_upstream_status(&feed("26.721.81911", "5973"), &current_contract, &candidate)
            .expect("current status");
    assert_eq!(current.action, UpstreamAction::Current);
    assert!(!current.contract_update_required);
    assert!(!current.candidate_rebuild_required);
    assert!(!current.automatic_rebuild_permitted);

    let unreviewed =
        assess_upstream_status(&feed("26.801.10001", "6001"), &current_contract, &candidate)
            .expect("new upstream status");
    assert_eq!(unreviewed.action, UpstreamAction::ReviewContractUpdate);
    assert!(unreviewed.contract_update_required);
    assert!(unreviewed.candidate_rebuild_required);
    assert!(!unreviewed.automatic_rebuild_permitted);

    let reviewed_contract = contract("26.801.10001", "6001");
    let rebuild = assess_upstream_status(
        &feed("26.801.10001", "6001"),
        &reviewed_contract,
        &candidate,
    )
    .expect("reviewed rebuild status");
    assert_eq!(rebuild.action, UpstreamAction::RebuildCandidate);
    assert!(!rebuild.contract_update_required);
    assert!(rebuild.candidate_rebuild_required);
    assert!(rebuild.automatic_rebuild_permitted);
}

fn contract(version: &str, build: &str) -> RuntimeApplicationContract {
    RuntimeApplicationContract {
        version: version.to_owned(),
        build: build.to_owned(),
        app_asar_sha256: "a".repeat(64),
    }
}

fn feed(version: &str, build: &str) -> FeedInspection {
    FeedInspection {
        schema: 1,
        producer: "io.github.bearhuddleston.codex-linux-packager.rust",
        kind: "feed_inspection",
        source: FeedSource::LocalFixture {
            path: "synthetic.xml".to_owned(),
        },
        feed_sha256: "b".repeat(64),
        feed_bytes: 1024,
        channel_title: "Codex".to_owned(),
        releases: vec![ReleaseMetadata {
            title: version.to_owned(),
            version: version.to_owned(),
            build: build.to_owned(),
            published_at: "Thu, 30 Jul 2026 00:00:00 +0000".to_owned(),
            minimum_system_version: "12.0".to_owned(),
            hardware_requirements: "x86_64".to_owned(),
            architecture_source: "fixed_x86_64_feed_endpoint",
            artifact: ArtifactMetadata {
                url: format!(
                    "https://persistent.oaistatic.com/codex-app-prod/ChatGPT-darwin-x64-{version}.zip"
                ),
                length: 512_000_000,
                content_type: "application/octet-stream".to_owned(),
                ed25519_signature:
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                        .to_owned(),
            },
        }],
    }
}
