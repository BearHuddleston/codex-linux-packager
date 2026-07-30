# Release gates

Canonical tests and a verified local AppImage are engineering evidence, not
release approval. No public binary or stable AppImage may be published until
every applicable gate is explicitly cleared for one exact source commit/tree
and artifact digest set. The publisher remains responsible for determining
whether it has permission to redistribute payloads and use relevant names or
marks; those legal decisions are deliberately outside the machine gate
catalog.

`release-readiness` produces the authoritative schema-1 assessment shape. It
re-authenticates and validates the supplied engineering evidence but does not
make legal determinations or accept self-asserted operational approvals. Its
`stable_publication_permitted` field describes only the cataloged technical
and operational gates; it is not a legal opinion. A successful assessment
command can therefore still—and currently must—report
`stable_publication_permitted: false`.

## Engineering gates implemented by the assessment

For one exact evidence set, the command can establish:

- the pinned Ed25519 trust root re-authenticates the complete staged source and
  the archive/ASAR identities reconcile through the final chain;
- native, runtime, AppDir, AppImage, and lockfile inputs are digest-bound;
- two offline, independent-root AppImage builds are byte-identical;
- real SQLite and PTY round trips passed under the exact Electron ABI;
- the extracted final AppImage matches its manifest, every ELF was audited,
  and no recorded GLIBC requirement exceeds 2.36;
- genuine host extract-and-run launches passed on both Wayland and X11; and
- a genuine non-root launch passed in the digest-pinned controlled
  Debian/glibc-2.36 baseline with networking disabled.

Changing any reviewed bytes requires a new assessment. These gates do not imply
desktop-environment coverage, signing, release operations, or a determination
of publisher rights.

## Gates presently blocking stable publication

- **Complete notices and deterministic SBOM:** the tooling dependency policy is
  documented, but complete notices and an artifact-bound SBOM for the
  proprietary payload and every redistributed component are not complete.
- **Signed checksums and protected keys:** the Rust command can now generate a
  private seed, reconcile AppImage provenance, sign a canonical full-file
  checksum manifest, and self-verify it against the compiled pin. No reviewed
  protected environment/key-custody operation is yet bound to a candidate.
- **Signed attestation:** no signed attestation binds an exact commit, tree,
  Cargo.lock, inputs, and output digest set.
- **Protected automation:** hourly monitoring and a dispatch-only trusted-runner
  workflow are implemented, but no reviewed runner registration, protected
  environment, independent reviewer, tag policy, or release automation
  evidence is bound to the candidate.
- **Complete platform matrix:** host Wayland/X11 extract-and-run and a
  controlled X11 baseline pass, but KDE and GNOME, Wayland and X11, FUSE and
  extract-and-run, and sandbox behavior are not all covered as a matrix.
- **Rollback and recovery:** runtime AppImage activation has synthetic
  atomic-exchange, rollback-retention, collision, and symlink tests. The
  intended GitHub publication system still has no reviewed rollback/recovery
  exercise.
- **Frozen independent review:** no independent approval is bound to the exact
  candidate source and artifact bytes.

The machine-readable gate identifiers and required actions are defined in
`src/release.rs`. Operational evidence needs a separately designed, protected
review/signing workflow before a future implementation may clear it; adding a
boolean CLI flag would not be adequate.

The automatic rebuild workflow is intentionally not release automation. It
builds and inventories the updater, retains the AppImage locally, and opens
only a digest-record pull request. Enabling it does not satisfy the
protected-automation gate or authorize use of the signing seed.

## Review discipline

- Freeze reviews only at completed phase boundaries.
- Bind every finding and approval to an exact commit/tree and artifact digest
  set.
- Reproduce a finding before carrying it from old bytes to a successor.
- Stop a review cycle after a decisive blocker and require an explicit decision
  before producing another candidate.
- Do not expand `docs/threat-model.md` silently.
- Do not treat green unit tests, source-tree mocks, or a local runnable AppDir
  as release approval.
