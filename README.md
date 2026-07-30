# codex-linux-packager

<p align="center">
  <strong>An auditable, deterministic Linux x86_64 packaging pipeline for authenticated Codex desktop artifacts.</strong>
</p>

<p align="center">
  Clean-room Rust tooling · schema-1 provenance · exact-input contracts · no bundled application payloads
</p>

<p align="center">
  <a href="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BearHuddleston/codex-linux-packager/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-3fb950.svg"></a>
  <img alt="Target: Linux x86_64" src="https://img.shields.io/badge/target-Linux%20x86__64-79c0ff.svg">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#pipeline">Pipeline</a> ·
  <a href="#automatic-rebuilds">Automatic rebuilds</a> ·
  <a href="#security-contract">Security</a> ·
  <a href="#release-boundary">Release boundary</a> ·
  <a href="#development">Development</a>
</p>

<p align="center">
  <img
    src="docs/images/readme-terminal.svg"
    alt="codex-linux-packager command-line help showing the eleven acquisition, packaging, monitoring, and assessment commands"
    width="100%"
  >
</p>

> [!IMPORTANT]
> This project is pre-release, unofficial, and unaffiliated with OpenAI. No
> public or stable AppImage is approved. The MIT license covers this
> repository's original tooling only; it does not grant payload redistribution
> or trademark rights.

## At a glance

| Contract | Current value |
| --- | --- |
| Supported target | Linux x86_64 only |
| Toolchain | Stable Rust; MSRV 1.85.0 |
| Electron | 42.3.0 / module ABI 146 |
| Native build baseline | Debian Bookworm / GLIBC 2.36 |
| Version-matched inputs | Codex CLI 0.146.0-alpha.3.1 / ripgrep 15.2.0 |
| Persisted documents | Schema `1`, deterministic compact JSON |
| Producer | `io.github.bearhuddleston.codex-linux-packager.rust` |
| Last local candidate | Codex 26.721.81911 build 5973; [digest record](data/engineering-candidate.json) |
| Automation | Hourly public monitor; trusted rebuild disabled until its isolated runner is configured |
| Release status | Engineering candidate built; public AppImage publication blocked |

The tool authenticates one official desktop artifact, narrows it to the
permitted source set, rebuilds native dependencies for the exact Electron ABI,
assembles a Linux runtime, and verifies a deterministic AppImage. Every phase
emits evidence for the next phase to validate independently.

## Quick start

Build the CLI from the locked dependency graph:

```bash
git clone https://github.com/BearHuddleston/codex-linux-packager.git
cd codex-linux-packager
cargo build --locked
./target/debug/codex-linux-packager --help
```

Inspect the fixed official Sparkle feed:

```bash
cargo run --locked -- inspect
```

Compare the feed with the reviewed contract and last engineering candidate:

```bash
cargo run --locked -- check-upstream
```

Or exercise the same bounded parser offline with a synthetic local fixture:

```bash
cargo run --locked -- inspect --fixture /absolute/path/to/feed.xml
```

`inspect` emits the exact `signature`, `length`, `version`, and `build` required
by the artifact-acquisition and authentication commands. `acquire-artifact`
downloads only the exact official URL for that version, rejects redirects and
ambiguous HTTP responses, authenticates the complete bytes with the
independently compiled production trust root, and publishes with no
replacement.

## Pipeline

```text
hourly monitor ──► check-upstream ──► review changed contracts
                         │                    │
                         │ contract current   │ reviewed merge
                         ▼                    ▼
Sparkle feed ──► inspect ──► acquire-artifact ──► stage ──► extract
                                                        │
                                                        ▼
                                                 build-native
                                                        │
                                                        ▼
                                                assemble-runtime
                                                        │
                                                        ▼
                                                  build-appdir ×2
                                                        │
                                                        ▼
                                                 pack-appimage
                                                        │
                                                        ▼
                                               release-readiness
```

| Command | Responsibility | Result |
| --- | --- | --- |
| `inspect` | Parse the fixed feed or a bounded local fixture | Typed release metadata |
| `check-upstream` | Compare latest feed, reviewed application contract, and last candidate | `current`, `review_contract_update`, or `rebuild_candidate` |
| `acquire-artifact` | Download, authenticate, preflight, and no-replace publish the exact feed-selected ZIP | Authenticated source ZIP plus acquisition receipt |
| `inspect-artifact` | Authenticate and preflight the complete desktop ZIP | Reconciled artifact report |
| `stage` | Publish only the authenticated ZIP, `app.asar`, and provenance | Private schema-1 stage generation |
| `extract` | Expand integrity-verified packed ASAR files | New no-replace extraction generation |
| `build-native` | Rebuild the locked `better-sqlite3` and `node-pty` graph | Verified Linux x86_64 native outputs |
| `assemble-runtime` | Combine pinned Electron, Codex CLI, ripgrep, and native inputs | Normalized runtime plus complete manifest |
| `build-appdir` | Construct the deterministic filesystem and launcher | Timestamp- and mode-normalized AppDir |
| `pack-appimage` | Build twice, compare, extract, audit, and launch | Byte-reproducible AppImage plus provenance |
| `release-readiness` | Re-authenticate the full evidence chain and evaluate gates | Truthful blocking release assessment |

Run `codex-linux-packager <command> --help` for every typed argument. Build and
assessment commands require absolute paths. Acquired inputs and generated
outputs belong beneath ignored `work/`, `cache/`, `build/`, `out/`, or `dist/`
directories.

### What the completed pipeline verifies

- Ed25519 authentication covers the exact complete downloaded artifact bytes.
- ZIP and ASAR inputs are bounded and preflighted before narrow extraction.
- Native modules are rebuilt for Electron ABI 146 and must pass real SQLite
  and PTY round trips under the exact runtime.
- Runtime assembly includes only the Linux x86_64 policy set and inventories
  every inclusion and omission.
- AppImages are built from independent roots with network-isolated packaging
  and must be byte-identical.
- The final AppImage is extracted, matched to AppDir provenance, and exercised
  on host Wayland, host X11, and a controlled older-GLIBC baseline.
- Every extracted ELF requirement is recorded; `release-readiness` rejects a
  recorded GLIBC requirement above 2.36.

`build-native` is offline by default and uses the digest-addressed OCI image in
[`data/native-contract.json`](data/native-contract.json). Its explicit
`--allow-network` flag is recorded in provenance. `pack-appimage` requires two
independently constructed AppDirs, digest-matched packaging tools, both Wayland
and X11 backends, and the exact locally verified older-GLIBC image ID.

## Automatic rebuilds

The public [`upstream-monitor.yml`](.github/workflows/upstream-monitor.yml)
runs hourly and can also be dispatched manually. It reads only the official
feed and repository contracts. A new release opens or refreshes an
`upstream-update` issue.

The transition is deliberately two-step:

1. `review_contract_update` means the feed moved. Automation stops until the
   downloaded source is authenticated and every Electron, native-package,
   Codex CLI, ripgrep, patch, and tool pin is independently reconciled in a
   reviewed change.
2. `rebuild_candidate` means that reviewed contract is current while the
   candidate record is stale. If `TRUSTED_REBUILD_ENABLED=true`, the monitor
   dispatches [`rebuild-candidate.yml`](.github/workflows/rebuild-candidate.yml)
   to a dedicated `codex-packager-trusted` runner.

That trusted workflow acquires the exact source, executes every implemented
phase offline where required, builds twice, performs real Wayland/X11 and
older-GLIBC launches, retains the AppImage beneath a configured local output
root, and opens a pull request containing only the new digest record. It never
uploads the AppImage or proprietary inputs to GitHub and never creates a
release. The payload-handling job has read-only repository permission and no
persisted checkout credential; only a separate GitHub-hosted digest-record job
can write the pull request.

No matching self-hosted runner or enablement variable is installed by cloning
the repository. Configure a dedicated or ephemeral runner and its reviewed
cache before enabling dispatch; do not expose a general-purpose user
workstation to untrusted workflows. The exact operational contract is in
[`docs/automated-rebuilds.md`](docs/automated-rebuilds.md).

## Security contract

The binding scope is [`docs/threat-model.md`](docs/threat-model.md).

The implementation is designed to reject malformed, oversized, ambiguous,
truncated, unauthenticated, path-unsafe, or resource-exhausting inputs. It uses
bounded reads and subprocess output, no-follow file opens, deterministic
environments, process-group cleanup, and no-replace publication.

Publication guarantees the bytes produced at the documented durable commit
boundary. It does **not** make ordinary user-owned files permanently immutable
against a hostile process running as the same UID. Stronger same-UID guarantees
would require a separately privileged publisher or kernel-enforced immutable
storage—not another userspace verifier.

## JSON and provenance

Machine-readable documents:

- begin at schema `1`;
- require producer
  `io.github.bearhuddleston.codex-linux-packager.rust`;
- deny unknown fields, unknown or old schemas, and other producers;
- use one compact UTF-8 JSON document followed by a newline; and
- inventory paths, byte counts, modes, and SHA-256 identities.

There is no implicit compatibility with Python schema-3 staging state. Each
consumer revalidates both the identity and semantics of the evidence it reads.

## Release boundary

`release-readiness` validates the stage, native, runtime, AppDir, AppImage,
artifact, and Cargo lockfile chain. A successful invocation means only that the
assessment completed. Read `stable_publication_permitted` and
`blocking_gate_ids`; with the current cataloged gates, the expected publication
value is `false`.

Stable publication remains blocked on complete notices and SBOM, protected
signing and automation, a complete desktop and FUSE matrix, rollback/recovery
rehearsal, and frozen review of one exact commit and artifact digest set. See
[`docs/release-gates.md`](docs/release-gates.md).

The gate catalog deliberately does not decide whether a publisher has payload
redistribution or trademark authority. Those are publisher responsibilities
outside `release-readiness`; `stable_publication_permitted` is not a legal
opinion.

In particular, “automatic rebuild” does not mean “automatic public release.”
The source repository is public; the generated AppImage is not a GitHub
release.

## Repository boundary

Git must never contain OpenAI or Codex application payloads, extracted bundles,
branding assets, native modules, executables, credentials, private keys, or
build products. Tests use small synthetic fixtures; live-network and
proprietary-input tests are explicitly opt in.

[`tests/repository_boundary.rs`](tests/repository_boundary.rs) checks the
candidate Git tree for prohibited archives, binary content, symlinks, oversized
files, obvious credential paths, and private-key material. The terminal image
above is an original UTF-8 SVG containing only the CLI's public help text.

## Development

Work vertically with RED → GREEN → REFACTOR. Run the canonical gates directly
from the repository root:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```

Useful project documents:

| Document | Purpose |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Repository workflow and canonical commands |
| [`docs/architecture.md`](docs/architecture.md) | Implemented data flow and trust boundaries |
| [`docs/threat-model.md`](docs/threat-model.md) | Binding security scope |
| [`docs/release-gates.md`](docs/release-gates.md) | Engineering evidence versus publication approval |
| [`docs/automated-rebuilds.md`](docs/automated-rebuilds.md) | Scheduled detection and trusted-runner operating contract |
| [`docs/dependencies.md`](docs/dependencies.md) | Exact dependency-selection rationale |
| [`docs/decisions/`](docs/decisions/) | Accepted architecture decision records |

## License

The original packaging and validation tooling in this repository is available
under the [MIT License](LICENSE). No OpenAI application payload, trademark, or
branding right is included or implied.
