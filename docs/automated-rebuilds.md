# Automatic releases

The repository separates public monitoring, proprietary source handling,
digest-state writes, protected signing, and GitHub release writes. A single job
never receives both the update-signing seed and repository write authority.

The automatic channel publishes only Linux x86_64 engineering releases. It
does not claim stable support or OpenAI affiliation.

## State machine

`check-upstream` compares:

- the first authoritative release in the bounded official Sparkle feed;
- the authenticated application identity in `data/runtime-contract.json`; and
- the last digest-bound result in `data/engineering-candidate.json`.

It emits:

| Action | Meaning | Automatic transition |
| --- | --- | --- |
| `current` | Feed, contract, and candidate identities agree | Do nothing when the matching public release exists; otherwise rebuild from fresh roots with reason `missing_release` |
| `review_contract_update` | Feed identity differs from the contract | Dispatch compatibility-bounded `refresh-contract.yml` |
| `rebuild_candidate` | Contract matches the feed and candidate is stale | Dispatch a fresh trusted rebuild with reason `stale_candidate` |

The monitor checks for the exact public tag
`codex-app-<version>-<build>`. A candidate record is never treated as a
substitute for a public release. Missing publication therefore triggers a
genuine rebuild rather than reusing or merely rehashing an old AppImage.

`AUTOMATIC_RELEASE_ENABLED=true` enables dispatch. The switch should remain
false while provisioning or modifying the runner, signing environment, or
workflow chain.

## Hourly public monitor

`.github/workflows/upstream-monitor.yml` runs at minute 17 each hour and on
manual dispatch. The GitHub-hosted job:

1. executes `cargo run --locked -- check-upstream`;
2. validates its schema-1 output;
3. checks whether the exact non-draft, non-prerelease public release exists;
4. maintains one `upstream-update` issue;
5. checks all three downstream workflows for active runs; and
6. dispatches exactly one required transition.

It never downloads the desktop artifact or handles payload bytes.

All contract refresh, rebuild, and release workflows use the shared
`codex-automatic-release-pipeline` concurrency group. This prevents
cooperative overlap between retained generations and digest-state commits.

## Authenticated contract refresh

`.github/workflows/refresh-contract.yml` runs first when the feed changes. Its
trusted job has read-only repository permission and a checkout with
`persist-credentials: false`.

It:

1. acquires the exact feed-selected archive with redirects disabled;
2. authenticates the complete bytes with the compiled Sparkle trust root;
3. stages only the source archive, `app.asar`, and provenance;
4. runs `inspect-contract-source`;
5. requires the authenticated ASAR to retain the reviewed Electron and native
   package contract;
6. derives one unambiguous Codex version and ripgrep
   version/revision-prefix from the authenticated Mach-O resources;
7. dereferences the exact `openai/codex` and `BurntSushi/ripgrep` GitHub tags;
8. selects exactly one official
   `codex-package-x86_64-unknown-linux-musl.tar.gz` asset;
9. verifies its API-recorded size and SHA-256 after complete download; and
10. runs `refresh-runtime-contract`, which verifies the strict six-file
    package layout, metadata, Linux x86_64 ELF identities, and source markers.

The compatible refresh may change application version/build/ASAR, Codex
version/revision/package digests, ripgrep version/revision/digest, and
authenticated source-resource digests. It may not silently change Electron,
Node ABI, native package identities, source patches, packaging tools, target
architecture, or package layout.

An Electron/native/structural change fails closed. The monitor issue remains
open for a source change and review; automation does not invent a successor
contract.

Only compact canonical runtime-contract JSON crosses the job boundary. A
GitHub-hosted job verifies that `main` still equals the trusted job's source
commit, installs only `data/runtime-contract.json`, runs focused Rust and
repository-boundary tests, commits directly to the default branch with the
scoped automation deploy key, and dispatches the rebuild. No proprietary
payload is uploaded.

## Trusted rebuild

`.github/workflows/rebuild-candidate.yml` is dispatch-only and selects:

```text
self-hosted, linux, x64, codex-packager-trusted
```

The payload job again has read-only repository permission and no persisted
credential. It permits only two guarded reasons:

- `stale_candidate` requires `check-upstream` to report
  `rebuild_candidate`; or
- `missing_release` requires it to report `current`.

Both require the feed and runtime-contract version/build to match the request.

The job then:

- resolves every cached tool/input by contract digest;
- reacquires and reauthenticates the source;
- rebuilds the locked native graph in the digest-addressed OCI image;
- performs real SQLite and PTY probes under exact Electron;
- assembles and inventories the Linux runtime;
- builds two AppDirs from separate roots;
- builds two AppImages with the second packaging operation network-isolated;
- requires byte equality;
- extracts and audits every ELF;
- performs genuine host Wayland and X11 extract-and-run launches;
- performs a non-root, network-disabled launch in the exact older-glibc
  baseline; and
- runs `release-readiness` over the exact result.

The mode-0700 retained generation remains beneath `PACKAGER_OUTPUT_ROOT`.
Payloads never use GitHub Actions artifact transfer.

After the engineering gates pass, the trusted job emits only a bounded
schema-1 candidate record. A GitHub-hosted write job checks that the default
branch is still the exact build source commit, validates the record and
repository boundary, commits only `data/engineering-candidate.json` with the
same scoped automation deploy key, and dispatches the release workflow.

Fresh records require:

```text
engineering_candidate: true
automatic_publication_permitted: true
stable_publication_permitted: false
release_status: automatic_engineering_publication_permitted_not_stable_approval
```

## Protected signing and public release

`.github/workflows/release-draft.yml` retains its historical filename but now
publishes the public automatic engineering release.

The `release-signing` job:

- runs on the trusted retained-output runner;
- has `contents: read`;
- receives `UPDATE_SIGNING_SEED_BASE64` only through the
  `release-signing` environment;
- checks the retained AppImage, AppDir manifest, provenance,
  release-readiness scope, Cargo.lock, and exact source commit against the
  committed candidate record;
- builds the exact source commit offline;
- signs the update manifest;
- creates deterministic SPDX, notices, checksums, and exact-commit
  attestation; and
- keylessly verifies the complete local set.

The `release-draft` job:

- has `contents: write` but no signing seed;
- keylessly verifies the retained handoff;
- refuses to replace an existing release tag;
- creates a public, non-prerelease release marked latest;
- redownloads exactly ten expected assets; and
- keylessly verifies every redownloaded byte and signed relationship.

Environment reviewer approvals are optional policy, not a correctness
dependency. Fully automatic operation uses environment secret scoping without
required reviewers. The signing/write authority split and all fail-closed
cryptographic and runtime checks remain mandatory.

## Required runner configuration

Use a dedicated or ephemeral runner. Never add
`codex-packager-trusted` to a general-purpose runner exposed to pull-request
workflows.

Required repository variables:

| Variable | Meaning |
| --- | --- |
| `AUTOMATIC_RELEASE_ENABLED` | Exact `true` enables the hourly dispatch chain |
| `PACKAGER_CACHE_ROOT` | Absolute private cache root |
| `PACKAGER_OUTPUT_ROOT` | Absolute private retained-output root |
| `PACKAGER_GH_SHA256` | SHA-256 of `/usr/bin/gh` used for official tag/asset resolution |
| `PACKAGER_OCI_RUNTIME_SHA256` | SHA-256 of `/usr/bin/docker` |
| `PACKAGER_SUDO_SHA256` | SHA-256 of `/usr/bin/sudo` |
| `PACKAGER_BUBBLEWRAP_SHA256` | SHA-256 of `/usr/bin/bwrap` |
| `PACKAGER_READELF_SHA256` | SHA-256 of `/usr/bin/readelf` |
| `PACKAGER_OLDER_GLIBC_IMAGE_ID` | Exact local `sha256:<64 hex>` image ID |
| `PACKAGER_CARGO_DENY` | Absolute reviewed `cargo-deny` executable |
| `PACKAGER_CARGO_DENY_SHA256` | Exact SHA-256 of that executable |

Required environment secret:

| Environment | Secret and scope |
| --- | --- |
| `automation-commit` | `AUTOMATION_DEPLOY_KEY`, one dedicated repository deploy key with write access; available only to the two GitHub-hosted digest-state jobs |
| `release-signing` | `UPDATE_SIGNING_SEED_BASE64`, exactly one base64-encoded 32-byte Ed25519 seed |

`main` is protected by a branch ruleset requiring the canonical CI and MSRV
checks for ordinary changes. The ruleset grants bypass only to repository
deploy-key pushes so the two generated-state commits do not need to weaken
human branch protection. The dedicated private key is stored only in the
`automation-commit` environment; payload-handling and release-signing jobs
never receive it.

The runner also needs stable Rust, Node.js at least 22.12.0, npm,
noninteractive access to the reviewed OCI runtime, valid Wayland/X11 sessions,
the digest-addressed native build image, older-glibc image, Electron ZIP and
headers, AppImage tools, and the native npm cache.

The cache layout is:

```text
<cache>/
├── electron-<version>/
│   ├── electron-v<version>-linux-x64.zip
│   └── node-v<version>-headers.tar.gz
├── codex-<version>/
│   └── codex-package-x86_64-unknown-linux-musl.tar.gz
├── appimage-tools-<appimagetool-release>-<runtime-release>/
│   ├── appimagetool-x86_64.AppImage
│   └── runtime-x86_64
└── npm-native/
```

Contract refresh can add a newly authenticated Codex package to its
version-addressed cache directory. Native installation and the second
deterministic packaging pass remain offline.

## Failure and retry behavior

Any failure leaves the public release unchanged. The retained private
generation is preserved for diagnosis. Digest state is written only after the
corresponding trusted job succeeds, and each GitHub-hosted writer refuses to
commit if the default branch advanced.

The hourly monitor retries once no refresh, rebuild, or release run is active.
It never promotes an old candidate merely because its version matches.

These controls address cooperative writers, ordinary failures, and the
documented permission-boundary model. They do not make owner-writable output
immutable against a hostile same-UID process, which is explicitly outside
`docs/threat-model.md`.
