# Decision 0003: artifact authentication, ASAR validation, and staging

- Status: accepted
- Date: 2026-07-30

## Decision

Authenticate the exact complete artifact bytes with strict RFC 8032 Ed25519
before parsing ZIP content. The production trust root is compiled independently
from the Sparkle feed and self-declared bundle metadata:

- raw public key: `mNfr1v9t63BfgDtlw4C8lRvSY6uMggIXABDOCi3tS6k=`
- raw-key SHA-256:
  `9ffe67dd945eba7930671c7c7f4dbfc84b7ddcebe7618f82f227f1f70ef20058`

The independent bootstrap evidence, Apple code-signing chain, exact signer, and
Sparkle source semantics are recorded in `docs/sparkle-trust-bootstrap.md`.
Bundle `SUPublicEDKey` is only a consistency check and cannot rotate the trust
root.

Use:

- `ed25519-dalek` 3.0 with strict verification and no default features. It is a
  maintained pure-Rust implementation with MIT/Apache-2.0 licensing and Rust
  1.85 support.
- `zip` 6.0 with only the Rust `zlib-rs` deflate backend. A clean-room raw
  preflight validates the final EOCD, central and local records, data
  descriptors, names, modes, methods, sizes, ratios, duplicates, and exact
  record coverage before the general parser is invoked.
- Original event-driven property-list validation on `quick-xml` 0.41. Only the
  XML plist grammar and one root dictionary are accepted. Critical keys must be
  unique root string values; custom DTDs, entities, binary plists, attributes
  outside the exact root version, and ambiguous structure are rejected.
- safe `rustix` 1.1 filesystem and randomness APIs. Final symlinks and
  non-regular inputs are rejected without blocking. Private generations use
  descriptor-relative exclusive creation, explicit modes, file and directory
  fsync, and `RENAME_NOREPLACE`.

The authenticated official ZIP contains ordinary framework and package-manager
symlinks. They are accepted only as small stored relative same-root targets,
inventoried, and never extracted. Special files and any link used as
`Info.plist`, the declared executable, or `app.asar` are rejected.

Electron ASAR parsing is original Rust code. It enforces canonical Pickle
framing, bounded duplicate-free JSON, safe ASCII components, bounded depth and
entry counts, exact gap-free packed ranges, and every declared whole-file and
4 MiB block SHA-256. ASAR links are rejected. Entries declared under
`app.asar.unpacked` are inventoried but are not represented as present bytes.

Staging publishes exactly `source.zip`, `app.asar`, and `provenance.json`.
Every precommit error preserves an existing destination, and cleanup unlinks
only descriptor-relative inodes whose device/inode identities still match
objects created by the invocation. Schema 1 and the Rust producer identifier
are exact; Python schema 3 is rejected with no implicit migration.

## Publication claim

Successful publication establishes the bytes at the durable commit boundary
under `docs/threat-model.md`. It does not make ordinary owner-writable output
immutable after the command returns. Re-authentication when a later phase
consumes a stage validates that input at that later boundary; it is not claimed
as a solution to the explicitly excluded hostile same-UID model.

## Consequences

The implementation uses bounded memory proportional to the accepted source
archive plus selected ASAR. ZIP64, encrypted members, non-ASCII raw ZIP names,
unsupported compression, external ASAR files, and ASAR links are rejected or
explicitly omitted rather than guessed. A future trust-root rotation or format
expansion requires a new independently reviewed decision.

The earlier general `plist` dependency was removed after `cargo audit` reported
that its locked `time` dependency required a security fix whose patched release
raised MSRV above 1.85. Keeping the mandated MSRV while suppressing the advisory
was rejected; the narrow original parser removes the unused date/time surface.
