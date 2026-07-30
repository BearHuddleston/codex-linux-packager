# Architecture

The project begins as one binary-plus-library crate. Modules are added only when
a vertical behavior reaches them; the repository does not pre-create an empty
module for every future phase.

## Layering

The library owns typed domain structures, validation, deterministic JSON
documents, and phase implementations. Library errors use `thiserror`. The binary
owns command-line composition and may use `anyhow` only at that boundary.
`#![forbid(unsafe_code)]` is enabled initially.

Machine-readable documents begin at schema `1` and carry the producer identifier
`io.github.bearhuddleston.codex-linux-packager.rust`. Deserializers deny unknown
fields and validate both values. There is no implicit compatibility with the
Python implementation's schema-3 staging state.

## Planned vertical phases

1. **Foundation:** contract, threat model, deterministic JSON primitives,
   repository-boundary enforcement, and canonical verification.
2. **Feed inspection:** bounded exact-origin HTTPS retrieval and strict Sparkle
   XML parsing into typed release metadata.
3. **Artifact authentication and staging:** exact-byte Ed25519 verification,
   structural ZIP preflight, bundle reconciliation, narrow extraction, and
   transactional generation publication.
4. **Native build:** integrity-locked dependency graph, exact Electron ABI,
   Linux x86_64 ELF validation, and real SQLite/PTTY runtime probes.
5. **Runtime assembly:** independently pinned Electron, Codex CLI, ripgrep, and
   native inputs with a complete normalized manifest.
6. **AppDir and AppImage:** deterministic filesystem metadata, sandbox-aware
   launch behavior, twice-built byte equality, final extraction and ABI audit,
   and real launch tests.
7. **Release readiness:** legal, notices, SBOM, signing, attestation, protected
   automation, platform matrix, and rollback exercises.

## Data flow

Every phase consumes immutable-by-digest inputs for the duration of that
operation, produces a typed manifest, and verifies its own output before its
documented publication boundary. A later phase independently revalidates the
digests it consumes. This is a provenance chain, not a claim that ordinary
owner-writable paths remain immutable after a command returns.

Acquired payloads and build products stay in ignored working directories. The
Git tree contains only original source, documentation, tests, small synthetic
fixtures, and compatible open-source dependency metadata.

## Platform boundary

The initial and only supported target is Linux x86_64. Foreign Mach-O, PE, and
non-x86_64 ELF files are excluded and inventoried when runtime assembly is
implemented. Other architectures require a new explicit design and test matrix.
