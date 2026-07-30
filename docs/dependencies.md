# Dependency selection

All direct release dependencies are exact-version requirements in `Cargo.toml`;
the complete transitive graph is fixed by `Cargo.lock`. `cargo deny check`
rejects unapproved licenses, registries, Git sources, wildcards, and duplicate
crate versions. `cargo audit` checks the locked graph against the RustSec
advisory database.

This document covers tooling dependencies only. It is not the complete
third-party notice or SBOM required before redistributing an AppImage containing
proprietary payloads.

## Composition and data formats

- `clap` 4.5.54: derive-based typed CLI parsing with no ad-hoc argument
  grammar. MIT/Apache-2.0.
- `serde` 1.0.228 and `serde_json` 1.0.151: typed schema-1 documents,
  deny-unknown-field decoding, and deterministic compact encoding.
  MIT/Apache-2.0.
- `thiserror` 2.0.17: structured library errors. MIT/Apache-2.0.
- `anyhow` 1.0.104: context only at the binary composition boundary.
  MIT/Apache-2.0.
- `base64` 0.22.1: canonical fixed-length Sparkle signature/key decoding, with
  default features disabled. MIT/Apache-2.0.

## Security-sensitive parsing and cryptography

- `ureq` 3.3.0: small blocking HTTPS client with only the Rustls feature. Feed
  and source-artifact redirects are disabled. The signed AppImage updater
  permits a bounded GitHub release redirect chain only when the final HTTPS
  origin is in its explicit allowlist. Content decoding is disabled and all
  response headers, lengths, and bodies remain bounded. MIT/Apache-2.0.
- `quick-xml` 0.41.0: event-driven bounded feed and XML property-list parsing.
  This release contains the fixes for RUSTSEC-2026-0194 and
  RUSTSEC-2026-0195. Dangerous or ambiguous constructs are rejected by
  application code. MIT.
- `ed25519-dalek` 3.0.0: maintained pure-Rust strict RFC 8032 verification for
  official source artifacts and pinned AppImage update manifests. The release
  commands also sign canonical update metadata and exact-set release
  attestations from an explicitly supplied protected raw seed; key generation
  uses operating-system randomness through `rustix`. Default features remain
  disabled. MIT/Apache-2.0.
- `sha2` 0.11.0: SHA-256 identities and integrity validation throughout the
  pipeline. MIT/Apache-2.0.
- `zip` 6.0.0: member decompression only after the original raw ZIP framing,
  name, mode, method, and resource preflight. Only the zlib-rs deflate feature
  is enabled. MIT.
- `flate2` 1.1.9 with `zlib-rs`: bounded gzip/deflate decoding for exact
  contract inputs without a system zlib dependency. `flate2` is
  MIT/Apache-2.0 and the selected backend is Zlib-licensed.
- `tar` 0.4.46 without default features: bounded manual iteration of exact
  Electron/Codex tar inputs; paths and types are validated by application
  policy. MIT/Apache-2.0.

## Operating-system boundary

- `rustix` 1.1.4 with `fs`, `process`, and `rand`: safe APIs for no-follow
  descriptor opens, descriptor-relative operations, `RENAME_NOREPLACE`,
  atomic `RENAME_EXCHANGE`, advisory update locking, durability, random
  private-generation names and signing seeds, process groups, and bounded
  cleanup while retaining `#![forbid(unsafe_code)]`. MIT/Apache-2.0.
- `tempfile` 3.27.0 is development-only and provides isolated synthetic test
  roots. MIT/Apache-2.0.

The OCI runtime, sudo, bubblewrap, readelf, Node/npm, Electron, appimagetool,
Type-2 runtime, and container package set are not Cargo dependencies. Commands
accept or embed their exact versions/digests and record the observed identities
in phase provenance.

## Release-evidence tools

The protected draft workflow invokes `cargo-deny list --format json --layout
crate` through an absolute path and refuses it unless its complete executable
SHA-256 matches `PACKAGER_CARGO_DENY_SHA256`. The command's documented output is
a per-crate list of license information, not a preserved SPDX license
expression. Release evidence therefore records sorted observed identifiers and
retains `NOASSERTION` for conclusions instead of inventing `AND`/`OR`
semantics. See the upstream
[`cargo-deny list` contract](https://embarkstudios.github.io/cargo-deny/cli/list.html)
and [license detection limitations](https://embarkstudios.github.io/cargo-deny/checks/licenses/index.html).

SPDX packages remain `filesAnalyzed: false`; the AppDir entries are standalone
document-described files rather than invalid package `CONTAINS` claims. This
follows the SPDX 2.3
[`FilesAnalyzed` and verification-code rules](https://spdx.github.io/spdx-spec/v2.3/package-information/)
and [`DESCRIBES` relationship semantics](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/).
