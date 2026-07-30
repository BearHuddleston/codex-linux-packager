# Decision 0008: publisher legal decisions are not machine release gates

- Status: accepted
- Date: 2026-07-30

## Decision

Remove `payload_redistribution_authority` and
`trademark_and_branding_authority` from the machine-readable release gate
catalog. The publisher, not `codex-linux-packager`, decides whether it has the
authority required for a particular distribution and presentation.

`release-readiness` continues to validate the exact artifact evidence chain and
report its cataloged technical and operational gates. Its
`stable_publication_permitted` field is not a legal opinion and must not be
presented as one.

The repository keeps its unofficial and unaffiliated notice. The MIT license
continues to cover only the repository's original tooling and does not itself
grant rights in separately acquired payloads, names, or marks.

## Consequences

No permission document, user assertion, or `--legal-ok` flag enters provenance
or changes gate status. Removing the two catalog entries neither grants nor
denies legal authority; it keeps a machine validation report from pretending
to adjudicate it.

Complete notices/SBOM, protected signing, signed attestation, protected release
automation, the desktop/FUSE matrix, rollback/recovery, and frozen independent
review remain blocking cataloged gates.
