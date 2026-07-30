# Decision 0006: release readiness is an assessment, not an override

- Status: accepted
- Date: 2026-07-30

## Decision

Add a read-only `release-readiness` command. It re-authenticates the complete
stage with the independently pinned production key and validates canonical
native, runtime, AppDir, and AppImage manifests, the final AppImage bytes, and
the exact Cargo lockfile. Its schema-1 report binds all assessed evidence by
SHA-256.

The report clears only engineering gates that can be derived from those bytes:
authentication/provenance reconciliation, pinned inputs, reproducibility,
native ABI probes, final ELF audit, host Wayland/X11 extract-and-run, and the
controlled older-glibc launch.

Legal authority, payload notices/SBOM, signing-key protection, signed
attestation, protected automation, the complete desktop/FUSE matrix,
publication rollback/recovery, and frozen independent review remain
`not_satisfied` and blocking. The command intentionally has no
`--approve`, `--legal-ok`, or similar self-assertion flags.

## Consequences

The command exits successfully when an assessment is produced, even though
`stable_publication_permitted` is false. Automation must inspect that field and
must not equate command success with release approval.

A future mechanism for clearing external gates needs a separately designed,
protected, signed evidence workflow and explicit user authorization. It cannot
be added as an incidental boolean to this assessment.
