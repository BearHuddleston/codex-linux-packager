# codex-linux-packager

<p align="center">
  <strong>Authenticated Codex Desktop builds for Linux x86_64, rebuilt and verified in public.</strong>
</p>

<p align="center">
  Clean-room Rust tooling · deterministic AppImage · native Electron ABI probes · signed automatic updates
</p>

<p align="center">
  <a href="https://github.com/BearHuddleston/codex-linux-packager/releases/latest"><img alt="Latest automatic engineering release" src="https://img.shields.io/github/v/release/BearHuddleston/codex-linux-packager?display_name=tag&label=latest%20AppImage"></a>
  <a href="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/upstream-monitor.yml"><img alt="Upstream monitor" src="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/upstream-monitor.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT tooling license" src="https://img.shields.io/badge/tooling-MIT-3fb950.svg"></a>
  <img alt="Linux x86_64 only" src="https://img.shields.io/badge/target-Linux%20x86__64-79c0ff.svg">
</p>

<p align="center">
  <a href="#download">Download</a> ·
  <a href="#what-it-does">What it does</a> ·
  <a href="#automatic-releases">Automatic releases</a> ·
  <a href="#in-app-updates">In-app updates</a> ·
  <a href="#security-model">Security</a> ·
  <a href="#build-it-yourself">Build it yourself</a>
</p>

<p align="center">
  <img
    src="docs/images/readme-terminal.svg"
    alt="codex-linux-packager help showing its seventeen acquisition, contract-refresh, packaging, signing, monitoring, and verification commands"
    width="100%"
  >
</p>

> [!IMPORTANT]
> This project is unofficial and unaffiliated with OpenAI. Releases are
> automatic engineering builds, not a claim of OpenAI support, endorsement, or
> stable Linux support. The MIT license applies to this repository's original
> tooling; payload and trademark permissions remain the publisher's
> responsibility.

## Download

Download the latest verified AppImage from
[GitHub Releases](https://github.com/BearHuddleston/codex-linux-packager/releases/latest),
or use the fixed latest-asset URL:

```text
https://github.com/BearHuddleston/codex-linux-packager/releases/latest/download/codex-desktop-unofficial-x86_64.AppImage
```

Then:

```bash
chmod +x codex-desktop-unofficial-x86_64.AppImage
./codex-desktop-unofficial-x86_64.AppImage
```

The supported target is Linux x86_64. The project does not imply support for
ARM or other architectures.

Every release also carries its signed update manifest, provenance, AppDir
manifest, Cargo lockfile, deterministic SPDX inventory, notice inventory,
sorted checksums, release-readiness report, and signed attestation. Verify the
asset set with the release's `SHA256SUMS` and evidence files when auditing a
build.

## What it does

The packager does not translate or reimplement the application. It
authenticates one official Codex Desktop source artifact, replaces
platform-specific runtime pieces with exact Linux inputs, rebuilds native
modules for the target Electron ABI, and constructs a deterministic AppImage.

| Boundary | Enforced result |
| --- | --- |
| Source | Complete Sparkle artifact authenticated with an independently pinned Ed25519 key |
| Staging | Only the authenticated archive, `app.asar`, and schema-1 provenance |
| Native ABI | Locked `better-sqlite3` and `node-pty`; real SQLite and PTY round trips under exact Electron |
| Runtime | Linux x86_64 Electron, version-matched Codex CLI and ripgrep, complete inclusion/omission manifest |
| AppImage | Two independent builds, byte equality, full extraction and ELF audit |
| Runtime tests | Genuine Wayland, X11, and network-disabled older-glibc launches |
| Release | Pinned-key update manifest, SPDX/notices/checksums, exact-commit attestation, redownload verification |
| Repository | No OpenAI application payload, executable, native module, credential, or private key in Git |

The current exact identities live in the versioned data contracts:

- [`data/runtime-contract.json`](data/runtime-contract.json)
- [`data/native-contract.json`](data/native-contract.json)
- [`data/appimage-contract.json`](data/appimage-contract.json)
- [`data/update-contract.json`](data/update-contract.json)
- [`data/engineering-candidate.json`](data/engineering-candidate.json)

Persisted machine documents begin at schema `1`, identify the producer as
`io.github.bearhuddleston.codex-linux-packager.rust`, reject unknown fields and
other schemas, and serialize deterministically.

## Automatic releases

The repository checks the fixed official Sparkle feed every hour.

```text
official feed
     │
     ▼
check-upstream
     │
     ├── source changed ──► authenticate source ──► refresh compatible contract
     │                                              │
     ├── candidate stale ───────────────────────────┤
     │                                              ▼
     └── release missing ───────────────────► fresh trusted rebuild
                                                    │
                                                    ▼
                                      ABI probes + two AppImage builds
                                                    │
                                                    ▼
                                      Wayland + X11 + old-glibc launch
                                                    │
                                                    ▼
                                      digest-only record committed to Git
                                                    │
                                                    ▼
                                      protected signing, public release,
                                      redownload, and keyless verification
```

Routine upstream changes are automatic only while the authenticated
application remains inside the reviewed compatibility boundary:

- Electron version and Linux ZIP digest must still match the native contract;
- native package names, versions, and authenticated package metadata must
  still match;
- the authenticated Codex and ripgrep source markers must each be
  unambiguous;
- exact official Linux release tags, dereferenced commits, asset sizes, and
  GitHub-provided SHA-256 digests must reconcile; and
- the Codex Linux package must retain the supported six-file layout and pass
  Linux x86_64 ELF validation.

If Electron, the native dependency graph, the package layout, or another
structural contract changes, automation fails closed and leaves an issue for a
human change. It never guesses a new ABI or lets the feed authorize its own
Linux dependencies.

The trusted payload job has read-only repository permission and no persisted
checkout credential. Only compact verified JSON crosses to a GitHub-hosted
write job. Signing, exact-tag creation, and repository-release authority are
separate jobs: the signing job receives the Ed25519 seed but cannot write the
repository, the payload-free tag job receives only the scoped deploy key, and
the publication job receives only an environment-scoped release API
credential—never the signing seed or deploy key.

Operational details and required runner variables are in
[`docs/automated-rebuilds.md`](docs/automated-rebuilds.md).

## In-app updates

The AppImage includes a small Rust updater. On normal launch it checks the
fixed `automatic` channel manifest from this repository, verifies the Ed25519
signature against the compiled public key, and accepts only a strictly newer
Linux x86_64 version/build.

For an accepted update it:

1. downloads the complete replacement with bounded headers and lengths;
2. verifies the signed byte count, full SHA-256, provenance identity, and
   Type-2 x86_64 AppImage header;
3. atomically exchanges the verified inode with the running AppImage path;
4. retains the previous file as
   `<name>.rollback-<version>-<build>`; and
5. starts the new version on the next application launch.

Run a foreground check with:

```bash
./codex-desktop-unofficial-x86_64.AppImage --codex-linux-update-now
```

Disable background checks with:

```bash
CODEX_LINUX_DISABLE_UPDATES=1 ./codex-desktop-unofficial-x86_64.AppImage
```

Updates refuse symlink launch paths and cannot replace an AppImage in a
read-only directory. No downloaded key can authorize its own rotation, and no
delta executable is trusted.

## Pipeline commands

| Command | Responsibility |
| --- | --- |
| `inspect` | Inspect the official feed or a bounded local XML fixture |
| `check-upstream` | Compare feed, runtime contract, and candidate state |
| `inspect-contract-source` | Derive Codex, ripgrep, Electron, and native identities from an authenticated stage |
| `refresh-runtime-contract` | Reconcile an authenticated stage with exact official Linux release inputs |
| `acquire-artifact` | Download and authenticate the exact feed-selected archive |
| `inspect-artifact` | Authenticate and preflight a local complete archive |
| `stage` | Publish the narrow authenticated stage without replacement |
| `extract` | Extract integrity-verified packed ASAR files |
| `build-native` | Rebuild and probe the exact native module graph |
| `assemble-runtime` | Construct and inventory the normalized Linux runtime |
| `build-appdir` | Build a deterministic AppDir with updater and launcher |
| `pack-appimage` | Build twice, extract, audit, and genuinely launch |
| `generate-update-key` | Generate a protected Ed25519 seed and emit only public identity |
| `sign-update` | Sign the exact immutable-tag AppImage update payload |
| `prepare-release` | Generate SPDX, notices, checksums, and signed attestation |
| `verify-release` | Keylessly reverify every signed release input |
| `release-readiness` | Assess exact engineering and stable-release gates |

Every build command uses typed arguments and argument arrays—never a shell
command assembled from untrusted strings. Run
`codex-linux-packager <command> --help` for its exact contract.

## Security model

The binding threat model is
[`docs/threat-model.md`](docs/threat-model.md). It covers malformed and
oversized feed/XML/archive/ASAR input, network ambiguity, signature forgery,
archive traversal and bombs, foreign binaries, cooperative destination races,
crashes before durable publication, reproducibility drift, and incomplete
manifests.

Publication guarantees the bytes produced at the durable commit boundary under
that model. It does not claim ordinary owner-writable files become permanently
immutable against a hostile process already running as the same UID. Stronger
same-UID guarantees require a separately privileged publisher or
kernel-enforced immutable storage, not another userspace rehasher.

Automatic engineering publication is distinct from stable approval.
`release-readiness` sets `automatic_publication_permitted` only after the
implemented authentication, ABI, reproducibility, ELF, Wayland, X11, and
older-glibc gates pass. It keeps `stable_publication_permitted` false until the
broader stable matrix, recovery, notices, and frozen-review gates are
independently cleared. See
[`docs/release-gates.md`](docs/release-gates.md).

Report vulnerabilities through this repository's private GitHub security
advisory flow. Never attach proprietary payloads, credentials, or private keys.

## Build it yourself

Build the locked Rust tooling:

```bash
git clone https://github.com/BearHuddleston/codex-linux-packager.git
cd codex-linux-packager
cargo build --locked
cargo run --locked -- inspect
cargo run --locked -- check-upstream
```

Acquired inputs and generated outputs must stay under ignored `work/`,
`cache/`, `build/`, `out/`, `dist/`, or Cargo `target/` directories. Ordinary
tests use only synthetic fixtures; proprietary and live-network checks are
explicitly opt in.

Canonical development gates:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```

Useful references:

| Document | Purpose |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Repository workflow and canonical commands |
| [`docs/architecture.md`](docs/architecture.md) | Data flow and trust boundaries |
| [`docs/threat-model.md`](docs/threat-model.md) | Binding security scope |
| [`docs/automated-rebuilds.md`](docs/automated-rebuilds.md) | Automatic release operating contract |
| [`docs/update-signing.md`](docs/update-signing.md) | Update key and signed release contract |
| [`docs/release-gates.md`](docs/release-gates.md) | Automatic engineering versus stable-release gates |
| [`docs/dependencies.md`](docs/dependencies.md) | Security-sensitive dependency rationale |
| [`docs/decisions/`](docs/decisions/) | Architecture decision records |

## License

The original Rust packaging and validation tooling is available under the
[MIT License](LICENSE). No OpenAI payload, trademark, branding right, support,
or endorsement is included or implied.
