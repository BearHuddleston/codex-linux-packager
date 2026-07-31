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
        "AUTOMATIC_RELEASE_ENABLED",
        "gh workflow run refresh-contract.yml",
        "gh workflow run rebuild-candidate.yml",
        "release_exists",
        "missing_release",
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
        "automatic_publication_permitted",
        "gh workflow run release-draft.yml",
        "environment: automation-commit",
        "ssh-key: ${{ secrets.AUTOMATION_DEPLOY_KEY }}",
        "persist-credentials: true",
        "git push origin HEAD:",
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
        "digest-only state update must run on GitHub-hosted infrastructure"
    );
    assert!(
        workflow[record_job..].contains("contents: read")
            && !workflow[record_job..].contains("contents: write"),
        "the state writer must push only with its scoped deploy key"
    );
    assert!(
        !workflow[..record_job].contains("AUTOMATION_DEPLOY_KEY"),
        "payload-handling job must not receive the automation deploy key"
    );
    assert!(
        !workflow.contains("gh pr create"),
        "automatic candidate recording must not stop at a pull request"
    );
}

#[test]
fn automatic_public_release_separates_signing_from_repository_write_authority() {
    let workflow = include_str!("../.github/workflows/release-draft.yml");

    for required in [
        "workflow_dispatch:",
        CHECKOUT_V6_SHA,
        "codex-packager-trusted",
        "environment: release-signing",
        "UPDATE_SIGNING_SEED_BASE64: ${{ secrets.UPDATE_SIGNING_SEED_BASE64 }}",
        "sign-update",
        "prepare-release",
        "verify-release",
        "environment: release-draft",
        "needs: sign",
        "contents: write",
        "gh release create",
        "--latest",
        "codex-desktop-unofficial-x86_64.AppImage",
        "codex-linux-x86_64-update.json",
        "codex-linux-x86_64.spdx.json",
        "release-attestation.json",
        "third-party-notices.json",
        "SHA256SUMS",
        ".assessment_scope == $candidate[0].assessment_scope",
        "EXPECTED_ARTIFACT_SHA256",
        "EXPECTED_ARTIFACT_BYTES",
        "EXPECTED_APPDIR_SHA256",
        "EXPECTED_PROVENANCE_SHA256",
        "EXPECTED_CARGO_LOCK_SHA256",
        "sha256sum \"${candidate_root}/appimage/codex-desktop-unofficial-x86_64.AppImage\"",
        "stat --format=%s \"${candidate_root}/appimage/codex-desktop-unofficial-x86_64.AppImage\"",
        "--json isDraft,isPrerelease,assets",
        ".isDraft == false",
        ".isPrerelease == false",
        "map(.name) | sort",
        "find \"${download}\" -mindepth 1 -maxdepth 1",
        "mktemp --directory --tmpdir=\"${RUNNER_TEMP}\"",
    ] {
        assert!(
            workflow.contains(required),
            "protected draft-release workflow is missing {required:?}"
        );
    }
    for forbidden in [
        "pull_request:",
        "push:",
        "schedule:",
        "actions/upload-artifact",
        "actions/download-artifact",
        "--draft",
        "--prerelease",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "draft-release workflow must not contain {forbidden:?}"
        );
    }

    let draft_job = workflow
        .find("\n  draft:\n")
        .expect("draft job must be separate");
    assert!(
        workflow[..draft_job].contains("contents: read"),
        "signing job must have read-only repository permission"
    );
    assert!(
        !workflow[draft_job..].contains("UPDATE_SIGNING_SEED_BASE64"),
        "repository-write job must not receive the release-signing seed"
    );
}

#[test]
fn authenticated_contract_refresh_is_automatic_but_compatibility_bounded() {
    let workflow = include_str!("../.github/workflows/refresh-contract.yml");

    for required in [
        "workflow_dispatch:",
        CHECKOUT_V6_SHA,
        "codex-packager-trusted",
        "persist-credentials: false",
        "acquire-artifact",
        "stage",
        "inspect-contract-source",
        "refresh-runtime-contract",
        "repos/openai/codex/releases/tags/",
        "resolve_tag_revision BurntSushi/ripgrep",
        "data/runtime-contract.json",
        "environment: automation-commit",
        "ssh-key: ${{ secrets.AUTOMATION_DEPLOY_KEY }}",
        "persist-credentials: true",
        "git push origin HEAD:",
        "gh workflow run rebuild-candidate.yml",
    ] {
        assert!(
            workflow.contains(required),
            "automatic contract refresh is missing {required:?}"
        );
    }
    for forbidden in [
        "pull_request:",
        "actions/upload-artifact",
        "actions/download-artifact",
        "gh pr create",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "automatic contract refresh must not contain {forbidden:?}"
        );
    }

    let record_job = workflow
        .find("\n  record:\n")
        .expect("contract-record job must be separate");
    assert!(
        workflow[record_job..].contains("contents: read")
            && !workflow[record_job..].contains("contents: write"),
        "the contract writer must push only with its scoped deploy key"
    );
    assert!(
        !workflow[..record_job].contains("AUTOMATION_DEPLOY_KEY"),
        "authenticated payload job must not receive the automation deploy key"
    );
}
