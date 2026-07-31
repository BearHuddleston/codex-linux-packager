# 0011: Compatibility-bounded automatic engineering releases

Status: accepted

Date: 2026-07-30

## Context

The repository already authenticated source bytes, rebuilt native modules,
constructed a deterministic AppImage, exercised real runtime behavior,
prepared signed evidence, and separated signing from repository write
authority. The remaining workflow required manual contract edits,
candidate-record pull requests, environment approvals, and a non-public draft.
That did not meet the publisher's requirement to ship each compatible Codex
Desktop update automatically.

Rust and repeated userspace verification do not make owner-writable retained
outputs immutable against a hostile process running as the same UID. The
binding threat model continues to exclude that case; automation must not claim
otherwise.

## Decision

Publish a public channel named `automatic`, explicitly described as an
unofficial engineering channel rather than stable support.

Add a compatibility-bounded contract refresh:

- authenticate the complete feed-selected desktop artifact;
- require Electron and authenticated native package identities to remain
  inside the reviewed native contract;
- derive Codex and ripgrep identities from authenticated source resources;
- independently dereference exact official upstream tags;
- verify the exact official Linux package asset size and SHA-256; and
- accept only the supported six-file Linux package and Linux x86_64
  executables.

Electron, native dependency, patch, architecture, or package-layout changes
fail closed and require a source change. The feed never authorizes those
dependencies by itself.

Replace candidate pull requests and manual draft selection with guarded direct
digest-state commits and chained workflow dispatch. A missing public release
requires a fresh full rebuild even when feed, contract, and candidate
identities already agree.

Add `automatic_publication_permitted` to release-readiness and candidate
records. It is true only after the seven implemented authentication, ABI,
reproducibility, ELF, Wayland, X11, and older-glibc gates pass.
`stable_publication_permitted` remains false while the broader stable catalog
is incomplete.

Keep signing and repository-write authority in separate jobs. The read-only
signing job receives the Ed25519 seed and prepares signed evidence. The keyless
write job re-verifies the exact handoff, creates a public nonprerelease latest
release, redownloads all assets, and verifies them again. Environment reviewer
pauses are not required for the automatic channel.

Generated runtime-contract and candidate-record commits use one dedicated
write deploy key scoped to an `automation-commit` environment. The default
branch ruleset continues to require canonical checks for ordinary changes and
grants bypass only to deploy-key pushes. Trusted payload jobs and signing jobs
do not receive this key.

## Consequences

- Compatible upstream releases can flow from detection to a public AppImage
  and signed in-app update without human action.
- Structural changes stop at a visible workflow failure and monitor issue.
- Proprietary source, stages, native outputs, and retained generations remain
  off GitHub; only the final intended release set is uploaded.
- Automatic engineering publication does not imply stable support,
  independent review, OpenAI affiliation, or a machine legal determination.
- The publisher remains responsible for payload and mark permissions under
  Decision 0008.
- Ordinary same-UID mutability remains explicitly outside the threat model.
