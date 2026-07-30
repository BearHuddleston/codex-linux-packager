# codex-linux-packager

`codex-linux-packager` is an auditable, unofficial Linux x86_64 packaging CLI
for authenticated Codex desktop artifacts. This repository is a clean-room Rust
restart and currently contains the Phase 0 foundation only.

The intended pipeline will inspect the official Sparkle feed, authenticate an
officially downloaded artifact, stage a narrowly selected source set, rebuild
native modules for an exact Electron ABI, assemble a version-matched runtime,
and produce deterministic AppDir and AppImage outputs with truthful provenance.
Each phase is implemented and reviewed as a separate vertical milestone.

## Status

Pre-release. Phase 0 defines the contract, threat model, repository boundary,
and verification gates. Packaging commands are not implemented yet. Linux
x86_64 is the only planned target; no other architecture is supported or
implied.

This project is unofficial and unaffiliated with OpenAI. The MIT license covers
this repository's original tooling only. It does not grant rights to redistribute
OpenAI payloads or use OpenAI trademarks or branding. No stable AppImage release
may be claimed until those questions are separately resolved.

## Repository boundary

Do not commit OpenAI or Codex application payloads, extracted bundles, branding
assets, native modules, executables, credentials, or private keys. Build and
acquisition outputs belong under ignored directories. Tests use only small,
synthetic fixtures generated locally.

The integration test in `tests/repository_boundary.rs` checks the candidate Git
tree for prohibited archive and binary formats, symlinks, oversized files, and
obvious credential paths.

## Command roadmap

The public command concepts are:

- `inspect`
- `inspect-artifact`
- `stage`
- `extract`
- `build-native`
- `assemble-runtime`
- `build-appdir`
- `pack-appimage`

Machine-readable command results use schema `1` and producer
`io.github.bearhuddleston.codex-linux-packager.rust`. Unknown schemas, older
schemas, unknown fields, and a different producer are rejected. JSON is emitted
as one compact UTF-8 document followed by a newline; typed structures and
ordered maps provide deterministic field ordering.

## Development

Rust 1.85.0 is the minimum supported version. The current stable Rust toolchain
is recommended.

Run the canonical gates from the repository root:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```

See `AGENTS.md` for the RED → GREEN → REFACTOR workflow,
`docs/threat-model.md` for the binding security scope, and
`docs/release-gates.md` for claims that tests alone cannot establish.
