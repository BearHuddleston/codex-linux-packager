# Decision 0001: Rust foundation and MSRV

- Status: accepted
- Date: 2026-07-30

## Decision

Use one binary-plus-library crate, Rust edition 2024, and minimum supported Rust
version 1.85.0. The current stable toolchain is used for canonical verification,
while CI separately checks the MSRV.

The Phase 0 dependency set is deliberately small:

- `clap` with derive support for typed CLI parsing. Version 4.6.4 declares Rust
  1.85 and establishes the project MSRV.
- `serde` and `serde_json` for typed, deterministic JSON documents.
- `thiserror` for library error types.
- `anyhow` only for binary composition and final error context.

All are dual MIT/Apache-2.0 licensed. Exact transitive versions are committed in
`Cargo.lock`; `cargo deny check` enforces approved licenses, registries, and
non-wildcard dependency declarations.

No networking, XML, signature, archive, ASAR, syscall, or subprocess crate is
selected in Phase 0. Each security-sensitive addition requires a later decision
record covering maintenance, MSRV, license, relevant features, and why its API
fits the threat model.

## Consequences

Rust 1.85 is enforced rather than merely documented. Edition 2024 is available
at that floor. Unsafe code is forbidden. The crate remains easy to audit, but
none of these choices expand the threat model or provide same-UID filesystem
immutability.
