# 0010: Signed evidence precedes a protected non-public draft

Status: accepted

## Context

A twice-built, genuinely launched AppImage is strong engineering evidence, but
it does not identify the exact release asset set, preserve dependency/license
inventory, prove which source commit/tree was selected, protect signing-key
use, or separate signing authority from GitHub release-write authority.

Uploading retained proprietary outputs through a generic workflow artifact
would create another payload copy and weaken the explicit retained-runner
boundary. Giving one job both the private release seed and repository write
permission would unnecessarily combine two authorities. Reverification cannot
solve the threat model's explicitly excluded hostile-same-UID case.

## Decision

Add deterministic schema-1 release evidence after `release-readiness` and
`sign-update`:

- SPDX 2.3 JSON inventories every AppDir file plus the complete AppImage and
  Cargo license identifiers observed by the pinned policy tool while making no
  license conclusion;
- a notice document inventories embedded notice-like files and Cargo license
  conclusions while explicitly requiring independent review;
- sorted `SHA256SUMS` covers the AppImage, manifests, lockfile, SPDX, and
  notices; and
- a pinned Ed25519 attestation binds those subjects to one immutable release
  tag, source commit, source tree, and supporting evidence digest set.

`prepare-release` performs signed construction and no-replace publication.
`verify-release` is keyless and independently reconstructs the exact subject
set from the external assets and compiled public-key pin.

Use a manual-only protected workflow. A read-only `release-signing` environment
receives the seed and writes signed evidence to the private retained-output
root. A separate `release-draft` environment receives repository write
permission but no seed, verifies the handoff, creates only a non-public draft,
redownloads every asset, and verifies it again. The selected retained generation
must match the merged engineering-candidate digest scope exactly.

Do not add a public-promotion job until every remaining release gate is cleared
for the frozen bytes.

## Consequences

- Evidence generation is deterministic and tamper-evident under the documented
  threat model.
- The GitHub write token and signing seed are not present in the same job.
- The release workflow needs one dedicated retained-output runner or an
  equivalently protected shared private root across its two jobs.
- Generated SPDX and notice inventories improve auditability but do not
  substitute for independent notice/license review.
- A successful draft exercise is evidence for later operational review; it is
  not itself stable-publication approval.
- Ordinary user-owned outputs remain mutable by the owning UID after return.
