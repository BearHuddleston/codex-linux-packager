# Repository instructions

This repository contains only original Rust packaging and validation code,
documentation, tests, synthetic fixtures, and compatible open-source
dependencies. Never add OpenAI or Codex application payloads, extracted bundles,
branding assets, native modules, executables, credentials, or private keys.

Read `docs/threat-model.md` before changing security-sensitive behavior. Do not
expand its scope without an explicit user decision. In particular, do not claim
that userspace re-verification makes owner-writable output immutable against a
hostile process running as the same UID.

## Development workflow

Work vertically using RED → GREEN → REFACTOR:

1. Add one behavior test.
2. Run it and retain the expected failure.
3. Implement the minimum behavior.
4. Run the focused test to green.
5. Run all canonical gates.

Run commands directly from the repository root. Do not create temporary verifier
scripts when the direct commands pass.

## Canonical gates

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```

Run `actionlint` after changing GitHub workflow files. It is a supplemental
workflow syntax/policy check, not a replacement for the canonical Rust gates.

The minimum supported Rust version is 1.85.0. Stable Rust is used otherwise.
Commit only when the user explicitly requests it.

## Repository boundaries

Keep acquired inputs and build products beneath ignored `work/`, `cache/`,
`build/`, `out/`, `dist/`, or Cargo `target/` directories. Tests must use small
synthetic data generated at runtime. Live-network and proprietary-input tests
must be separately labeled and opt in.
