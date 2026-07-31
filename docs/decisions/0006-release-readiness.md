# Decision 0006: release readiness is an assessment, not an override

- Status: accepted; amended by Decisions 0008 and 0011
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

Payload notices/SBOM, signing-key protection, signed attestation, protected
automation, the complete desktop/FUSE matrix, publication rollback/recovery,
and frozen independent review remain `not_satisfied` and blocking. The command
intentionally has no generic `--approve` or similar self-assertion flag.
Decision 0008 later removed publisher legal questions from this machine gate
catalog entirely.

## Consequences

The command exits successfully when an assessment is produced, even though
`stable_publication_permitted` is false. Decision 0011 adds a separate
`automatic_publication_permitted` disposition for the seven implemented
engineering gates; command success alone remains insufficient.

A future mechanism for clearing external operational gates needs a separately
designed, protected, signed evidence workflow and explicit user authorization.
It cannot be added as an incidental boolean to this assessment.

## Amendment

[Decision 0008](0008-publisher-legal-decisions.md) removes payload
redistribution and trademark/branding authority from the machine gate catalog.
The assessment now reports only cataloged technical and operational gates and
makes no legal determination. The remaining operational evidence still cannot
be supplied through incidental boolean flags.

[Decision 0011](0011-automatic-engineering-releases.md) permits a separately
labeled automatic engineering channel after the seven implemented gates pass,
while retaining the full catalog for any stable-support claim.
