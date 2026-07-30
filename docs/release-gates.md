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

## Release evidence implemented after assessment

`prepare-release` accepts only the exact canonical AppDir manifest, AppImage
provenance, release-readiness assessment, Cargo.lock, signed update manifest,
mode-0755 Type-2 AppImage, pinned Cargo license report, source commit/tree, and
matching mode-0600 Ed25519 seed. It independently reconciles that set and
publishes, with no replacement:

- `codex-linux-x86_64.spdx.json`, a deterministic SPDX 2.3 document containing
  every AppDir file digest, the complete AppImage digest, and Cargo package
  license identifiers observed by the pinned policy tool, while retaining
  `NOASSERTION` for license conclusions; AppDir files are standalone
  document-described elements because no SPDX package-analysis/verification
  code is asserted;
- `third-party-notices.json`, a deterministic inventory of every notice-like
  file already embedded in the AppDir and every Cargo package's sorted observed
  identifier set;
- `SHA256SUMS`, covering the AppImage, provenance, update manifest, AppDir
  manifest, release-readiness report, Cargo.lock, SPDX, and notice inventory;
  and
- `release-attestation.json`, a canonical Ed25519 signature over the exact
  commit, tree, immutable release tag, every checksum subject, and supporting
  evidence digest.

`verify-release` needs no private key. It uses the independently compiled
public-key pin, rehashes every external asset, reconstructs the complete
checksum and subject sets, and rejects noncanonical, extra, missing, or
conflicting evidence.

These commands establish deterministic evidence mechanics. The generated notice
document deliberately says
`generated_inventory_requires_independent_license_review`: an inventory is not
a publisher's legal review, protected key operation, independent approval, or
publication authorization.

## Gates presently blocking stable publication

- **Complete notices and deterministic SBOM:** deterministic SPDX and notice
  inventories are implemented and locally reproducible, but their
  `NOASSERTION` file conclusions and embedded-notice inventory still require
  independent completion and review for every redistributed component.
- **Signed checksums and protected keys:** exact checksum construction,
  pinned-key signing, and keyless verification are implemented. No reviewed
  protected environment, custody/recovery procedure, or approved signing run
  is yet bound to the frozen candidate.
- **Signed attestation:** the canonical exact-commit/tree/lockfile/asset
  attestation is implemented and locally verified, but no protected signing
  run plus independent approval is bound to the frozen candidate.
- **Protected automation:** hourly monitoring, dispatch-only candidate rebuild,
  and manual draft-release workflows are implemented. No reviewed runner
  registration, protected environment/reviewer policy, pinned Cargo-license
  tool configuration, tag policy, or successful protected draft exercise is
  yet bound to the candidate.
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
`src/release.rs`. Clearing an operational gate requires evidence from the
reviewed protected workflow and an exact frozen candidate; adding a boolean CLI
flag would not be adequate.

The automatic rebuild workflow is intentionally not publication automation. It
builds and inventories the updater, retains the AppImage locally, and opens
only a digest-record pull request. The separate release workflow can create
only a non-public draft. Enabling either workflow does not satisfy the
protected-automation gate or authorize a public release.

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
