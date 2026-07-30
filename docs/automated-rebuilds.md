# Automated rebuilds

The repository separates public upstream detection from proprietary artifact
handling. This keeps the hourly job safe to run on GitHub-hosted infrastructure
without pretending that a changed feed can authorize its own supply-chain
contracts.

## State machine

`check-upstream` compares three identities:

- the first authoritative release in the bounded official Sparkle feed;
- the application version/build in `data/runtime-contract.json`; and
- the last digest-bound local result in `data/engineering-candidate.json`.

It emits exactly one action:

| Action | Meaning | Permitted automation |
| --- | --- | --- |
| `current` | Feed, reviewed contract, and candidate agree | None |
| `review_contract_update` | Feed is newer than the reviewed contract | Open/update an issue; do not rebuild |
| `rebuild_candidate` | Contract matches the feed and candidate is stale | Dispatch the isolated trusted rebuild |

A feed update never changes Electron, native-package, Codex CLI, ripgrep,
patch, runtime, or packaging-tool pins by itself. Those inputs must be
authenticated or independently obtained, reconciled, and reviewed before the
contract update is merged.

## Public monitor

`.github/workflows/upstream-monitor.yml` runs at minute 17 of every hour and on
manual dispatch. It:

1. checks out the exact default-branch source;
2. runs `cargo run --locked -- check-upstream`;
3. validates the schema-1 result;
4. creates or refreshes one `upstream-update` issue when action is required;
5. closes resolved monitor issues when all three identities agree; and
6. dispatches the trusted workflow only for `rebuild_candidate`, only when the
   repository variable `TRUSTED_REBUILD_ENABLED` is exactly `true`, and only
   when no rebuild or candidate-record pull request is active.

The monitor never invokes acquisition, staging, native compilation, runtime
assembly, AppImage packaging, artifact upload, or release creation.

## Trusted runner

`.github/workflows/rebuild-candidate.yml` has only a `workflow_dispatch`
trigger and selects all four labels:

```text
self-hosted, linux, x64, codex-packager-trusted
```

Use a dedicated or ephemeral runner whose account, filesystem, displays,
container runtime, network policy, and GitHub token are treated as a release
engineering boundary. Do not add the custom label to a general-purpose public
repository runner. The workflow is intentionally not triggered by pushes or
pull requests.

The payload-handling job checks out with persisted credentials disabled and
has read-only repository permission. After validation, it passes only the
small base64-encoded candidate JSON through a job output. A separate
GitHub-hosted job validates that digest-only record, runs the repository
boundary tests, and receives the write token needed to open the pull request.
The proprietary application is never executed in a job holding repository
write authority.

The locked Cargo build produces both `codex-linux-packager` and
`codex-linux-updater`. Each deterministic AppDir consumes the same independently
hashed updater executable and generates a release-specific schema-1 config
bound to the compiled update key and manifest URL. Packaged launch tests set
`CODEX_LINUX_DISABLE_UPDATES=1`; the required network-isolated runtime checks
must not contact the release channel.

The runner must provide:

- stable Rust compatible with the repository MSRV and locked dependencies;
- host Node.js at least 22.12.0 and npm;
- exact `/usr/bin/docker`, `/usr/bin/sudo`, `/usr/bin/bwrap`, and
  `/usr/bin/readelf` executables matching repository variables;
- noninteractive sudo permission limited sufficiently to launch the reviewed
  OCI runtime;
- genuine `DISPLAY`, `WAYLAND_DISPLAY`, and `XDG_RUNTIME_DIR` sessions;
- the digest-addressed build and older-GLIBC images;
- an absolute private cache root; and
- an absolute private retained-output root.

Required repository variables:

| Variable | Meaning |
| --- | --- |
| `TRUSTED_REBUILD_ENABLED` | Exact `true` enables monitor dispatch |
| `PACKAGER_CACHE_ROOT` | Absolute preseeded cache root |
| `PACKAGER_OUTPUT_ROOT` | Absolute private retained-output root |
| `PACKAGER_OCI_RUNTIME_SHA256` | SHA-256 of `/usr/bin/docker` |
| `PACKAGER_SUDO_SHA256` | SHA-256 of `/usr/bin/sudo` |
| `PACKAGER_BUBBLEWRAP_SHA256` | SHA-256 of `/usr/bin/bwrap` |
| `PACKAGER_READELF_SHA256` | SHA-256 of `/usr/bin/readelf` |
| `PACKAGER_OLDER_GLIBC_IMAGE_ID` | Exact local `sha256:<64 hex>` image ID |

The preseeded cache layout is derived from the reviewed JSON contracts:

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

Every file digest is checked against its reviewed contract before use. Native
installation remains offline; the workflow does not pass `--allow-network`.

## Rebuild result

Each run creates a new mode-0700 generation below `PACKAGER_OUTPUT_ROOT` and
never replaces an earlier generation. It retains:

- the downloaded authenticated source;
- narrow stage, native build, runtime, and two AppDirs;
- the twice-built verified AppImage;
- the exact updater/config inventory embedded in both AppDirs;
- all schema-1 phase evidence; and
- the release-readiness assessment.

No payload-bearing file from that generation is uploaded to GitHub. After all
implemented engineering gates validate, only the digest-record JSON crosses to
the GitHub-hosted record job, which opens a pull request changing
`data/engineering-candidate.json`. That file records version/build, exact
source commit, evidence digests, artifact bytes, and the explicit
`not_release_approved_do_not_publish` disposition.

If any phase fails, the partial private generation remains on the trusted
runner for diagnosis and the candidate record is not changed. A later hourly
monitor may retry only after no run or candidate pull request remains active.

## Protected draft handoff

After a candidate-record pull request is independently reviewed and merged,
`.github/workflows/release-draft.yml` can be dispatched manually with its exact
version, build, source commit, and retained generation basename. Before
signing, it requires the retained AppImage digest/length, AppDir manifest,
AppImage provenance, Cargo.lock, and complete release-readiness assessment
scope to equal `data/engineering-candidate.json`.

The workflow uses two protected jobs:

1. `release-signing` has read-only repository permission and receives
   `UPDATE_SIGNING_SEED_BASE64`. It verifies the exact pinned `cargo-deny`
   executable, builds the selected source commit offline, signs the update
   manifest, prepares deterministic SPDX/notices/checksums/attestation, and
   keylessly verifies the local set.
2. `release-draft` has repository write permission but no signing seed. It
   keylessly verifies the retained handoff, creates only a non-public GitHub
   draft, redownloads all ten assets, and keylessly verifies them again.

No GitHub Actions artifact transfer is used. Both jobs must run on the one
dedicated retained-output runner, or on separately isolated runners with the
same private authenticated `PACKAGER_OUTPUT_ROOT`; an ordinary shared
user-writable network directory is not a stronger trust boundary. The raw seed
is decoded only inside a fresh mode-0700 `mktemp` directory as a mode-0600 file;
the file and directory are removed by the signing step's cleanup trap.

In addition to the rebuild variables, draft preparation requires:

| Setting | Meaning |
| --- | --- |
| `PACKAGER_CARGO_DENY` | Absolute path to the reviewed `cargo-deny` executable |
| `PACKAGER_CARGO_DENY_SHA256` | Exact SHA-256 of that executable |
| `UPDATE_SIGNING_SEED_BASE64` | Protected `release-signing` environment secret containing exactly one base64-encoded 32-byte seed |

The `release-signing` and `release-draft` environments must require appropriate
reviewers before the secret is imported or the workflow is dispatched. The
workflow source alone does not prove those controls exist.

## Publication boundary

The scheduled automation rebuilds engineering candidates; it does not publish
them. The separate manual workflow creates only a non-public draft.
`stable_publication_permitted` remains false while any gate in
`docs/release-gates.md` is blocking. Enabling the runner or creating a draft
does not establish independent notice/license review, protected-operation
approval, complete desktop/FUSE coverage, rollback readiness, or frozen
independent approval. It also does not evaluate or establish the publisher's
payload redistribution or trademark authority, which is outside the machine
gate catalog.
