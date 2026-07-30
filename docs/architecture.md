# Architecture

The project is one binary-plus-library crate targeting Linux x86_64. The
library owns typed contracts, bounded parsing, validation, deterministic JSON,
transactions, and phase implementations. The binary owns CLI composition and
uses `anyhow` only at that boundary. `#![forbid(unsafe_code)]` remains enabled;
safe `rustix` APIs provide the required Linux filesystem/process primitives.

## Contract and document boundary

Persisted documents use schema `1`, deny unknown fields, and require producer
`io.github.bearhuddleston.codex-linux-packager.rust`. Consumers validate both
identity and semantics and require canonical compact JSON with a trailing
newline where the document is a pipeline input. Python schema 3 and other
producers are rejected without migration.

Every publication claim is
`bytes_at_durable_commit_boundary_under_documented_threat_model`. This is a
transaction boundary, not a same-UID immutability claim.

## Implemented verticals

### Feed inspection

`feed` parses a bounded, deliberately narrow Sparkle XML grammar. `download`
retrieves only the fixed exact-origin Rustls HTTPS endpoint with redirects and
content decoding disabled, bounded headers/body, and strict length handling.
Tests use local fixtures and local HTTP servers.

`upstream` compares the first authoritative feed item with the reviewed runtime
application contract and the digest-only record of the last assessed
engineering candidate. Its three-state result prevents a changed feed from
self-authorizing contract changes.

`acquire-artifact` streams one exact feed-selected ZIP into a private
mode-0600 file. It rejects redirects, wrong final URLs, encoded or transferred
responses, duplicate/conflicting headers, incorrect lengths, truncation, and
oversize before authenticating and preflighting the complete bytes. Only the
authenticated private file is committed with no replacement.

### Artifact authentication and stage

`signature` performs strict Ed25519 verification over the complete artifact
with an independently pinned key/fingerprint. `archive` performs original raw
ZIP framing/resource preflight before using the general ZIP parser. `asar`
validates canonical Pickle/JSON framing, paths, storage layout, and declared
integrity. `staging` publishes exactly the authenticated archive, `app.asar`,
and provenance through a no-replace durable transaction.

`extract` expands only integrity-verified packed ASAR files into a new
generation. Declared external files are never invented.

### Native build

`native` reconciles the authenticated application with
`data/native-contract.json`, including Electron 42.3.0, Node 24.15.0, module
ABI 146, the locked `better-sqlite3` and `node-pty` graph, and reviewed exact
source patches. Compilation runs as the invoking UID in a digest-addressed
Node 22.22.0 Debian Bookworm image with registry networking disabled unless
explicitly authorized.

Outputs must be Linux x86_64 ELF files whose GLIBC requirements do not exceed
the controlled 2.36 policy. The exact Electron runtime must complete genuine
SQLite and PTY round trips before publication.

### Runtime assembly

`runtime` consumes a freshly revalidated stage, independently pinned native
manifest, official Electron Linux x64 ZIP, and version-matched official Codex
package. It correlates the authenticated source metadata with Codex
0.146.0-alpha.3.1 and ripgrep 15.2.0, validates every executable, includes only
the Linux x86_64 policy set, and inventories every inclusion and omission.

### AppDir and AppImage

`appdir` constructs a complete deterministic tree with normalized modes and
timestamps, a generic original MIT-licensed icon, an explicit unofficial
desktop identity, and an AppRun policy for auto/Wayland/X11. AppRun disables
the unusable setuid helper while preserving Chromium's user-namespace sandbox;
it never passes `--no-sandbox`.

`appimage` requires independently built AppDirs, stable-tag digest-pinned
appimagetool and Type-2 runtime inputs, deterministic single-worker SquashFS,
and byte equality across two builds. Both builds, extraction, and host launches
use bubblewrap network/PID isolation. It then:

- extracts the final AppImage and checks every file against AppDir provenance;
- audits every included ELF with a digest-pinned `readelf`;
- performs genuine extract-and-run launches on host Wayland and X11; and
- performs a non-root X11 launch in the exact Debian Bookworm/glibc-2.36 OCI
  baseline with `--network=none`, dropped capabilities, and bounded process
  cleanup.

The baseline Dockerfile and snapshot sources are repository inputs; the exact
local image ID and package inventory digest are runtime evidence.

### Release readiness

`release` re-authenticates the stage and validates the exact native → runtime →
AppDir → AppImage provenance chain, final AppImage bytes, and Cargo lockfile.
It clears only seven engineering gates that the supplied evidence establishes.
All external legal, notices/SBOM, signing, automation, full platform-matrix,
rollback, and independent-review gates remain blocking. The command cannot
authorize publication.

### Upstream automation

The public hourly workflow executes only `check-upstream`, issue routing, and a
guarded dispatch decision. Payload handling is isolated in a dispatch-only
workflow selected by the custom `codex-packager-trusted` self-hosted-runner
label. That workflow uses reviewed cache contracts, invokes every implemented
phase, retains all payload-bearing outputs below a private local root, and
has read-only repository permission with persisted checkout credentials
disabled. It passes only the bounded digest record to a separate GitHub-hosted
write job, which validates and proposes that record to Git.

The workflow source does not establish that a runner, protected environment, or
independent reviewer exists. `TRUSTED_REBUILD_ENABLED` must remain unset or
`false` until those operational prerequisites are configured.

## Process and filesystem safety

`process` executes argument arrays with deterministic environments, bounded
stdout/stderr, deadlines, process groups, and descendant cleanup. No shell
command is constructed from untrusted strings.

Untrusted regular inputs are opened with `O_NOFOLLOW`, bounded by descriptor
metadata, read completely, and checked again for in-operation mutation.
Directory traversals are bounded and reject links and special files. Private
generations publish with no replacement and preserve an existing destination
on every precommit failure.

These mechanisms address the in-scope cooperative/error/race model. They do not
protect ordinary owner-writable outputs from arbitrary hostile writes by the
same UID after return.

## Repository and platform boundary

Acquired payloads and generated outputs remain under ignored directories. Git
contains only original Rust source, documentation, text contracts, reviewed
patches, container recipes, and synthetic tests.

Linux x86_64 is the only supported target. Other architectures require a new
contract, implementation, and test matrix.
