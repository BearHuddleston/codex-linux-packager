#![forbid(unsafe_code)]

const CHECKOUT_V6_SHA: &str = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803";

#[test]
fn scheduled_monitor_detects_upstream_without_handling_payloads() {
    let workflow = include_str!("../.github/workflows/upstream-monitor.yml");

    for required in [
        "schedule:",
        "workflow_dispatch:",
        CHECKOUT_V6_SHA,
        "cargo run --locked -- check-upstream",
        "TRUSTED_REBUILD_ENABLED",
        "gh workflow run rebuild-candidate.yml",
    ] {
        assert!(
            workflow.contains(required),
            "upstream monitor is missing {required:?}"
        );
    }
    for forbidden in [
        "pull_request:",
        "actions/upload-artifact",
        "acquire-artifact",
        "pack-appimage",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "upstream monitor must not contain {forbidden:?}"
        );
    }
}

#[test]
fn proprietary_rebuild_is_isolated_to_an_explicit_trusted_runner() {
    let workflow = include_str!("../.github/workflows/rebuild-candidate.yml");

    for required in [
        "workflow_dispatch:",
        CHECKOUT_V6_SHA,
        "codex-packager-trusted",
        "persist-credentials: false",
        "\"${PACKAGER_BIN}\" check-upstream",
        "acquire-artifact",
        "stage",
        "build-native",
        "assemble-runtime",
        "build-appdir",
        "PACKAGER_UPDATER",
        "--updater-sha256",
        "pack-appimage",
        "release-readiness",
        "data/engineering-candidate.json",
        "candidate_record: ${{ steps.candidate.outputs.record }}",
        "needs: rebuild",
    ] {
        assert!(
            workflow.contains(required),
            "trusted rebuild workflow is missing {required:?}"
        );
    }
    for forbidden in [
        "pull_request:",
        "push:",
        "actions/upload-artifact",
        "actions/download-artifact",
        "--allow-network",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "trusted rebuild must not contain {forbidden:?}"
        );
    }

    let record_job = workflow
        .find("\n  record:\n")
        .expect("digest-record job must be separate");
    assert!(
        !workflow[..record_job].contains("GH_TOKEN"),
        "payload-handling job must not receive a repository write token"
    );
    assert!(
        workflow[record_job..].contains("runs-on: ubuntu-24.04"),
        "digest-only pull request must run on GitHub-hosted infrastructure"
    );
}
