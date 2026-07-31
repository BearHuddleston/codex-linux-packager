# AppImage update signing

The Linux AppImage release key is a project trust root. It is independent of
the official Sparkle key used to authenticate downloaded Codex desktop source.
The public contract is compiled from [`data/update-contract.json`](../data/update-contract.json).

## Current public identity

Generated locally on 2026-07-30 with the repository's
`generate-update-key` command:

```text
algorithm:          Ed25519 / RFC 8032
raw public key:     PW6jUTIc/Z46q/T3D3YisXqPVVHWIdknf/GQHzJRf4E=
SHA-256 fingerprint: fd6ea6bd85ff0f85fc7f45190c505317491a59fbfd872686e2debbe41e868314
channel:            automatic
target:             linux-x86_64
```

The command obtained 32 bytes from the operating system random source, created
the seed with no replacement at mode 0600 beneath ignored `work/`, fsynced the
file and its parent, and emitted only the public identity. The raw seed is not
part of Git and must never appear in logs, command arguments, artifacts,
fixtures, or pull requests.

This record establishes the source-tree pin. The private seed is scoped to the
read-only `release-signing` job; the keyless GitHub release job cannot read it.

## Manifest contract

`sign-update` accepts:

- the exact mode-0755 AppImage;
- its canonical `pack-appimage` provenance;
- the raw mode-0600 seed;
- the exact 40-character source commit;
- an explicit UTC release timestamp; and
- a new no-replace output path.

It reconciles the AppImage SHA-256, byte count, filename, version, and build
with provenance; requires the seed's public half to match the compiled pin;
constructs the immutable tag
`codex-app-<application-version>-<application-build>`; signs the canonical
payload; verifies the result with the pinned public key; and durably publishes
the manifest.

The GitHub release must contain these exact asset names:

```text
Cargo.lock
SHA256SUMS
appdir-manifest.json
codex-desktop-unofficial-x86_64.AppImage
codex-linux-x86_64-update.json
codex-linux-x86_64.spdx.json
provenance.json
release-attestation.json
release-readiness.json
third-party-notices.json
```

The latest release alias serves only the small signed manifest. The signed
payload points at the AppImage under its immutable release tag.

## Release evidence

`prepare-release` rehashes and reconciles the exact AppImage, provenance,
signed update manifest, AppDir manifest, release-readiness report, Cargo.lock,
source commit/tree, and pinned Cargo license report. It publishes a new
four-file evidence generation containing deterministic SPDX 2.3 JSON, a
notice/license inventory, sorted checksums, and a canonical Ed25519
attestation. Both the update manifest and attestation must authenticate with
the same independently compiled release-key pin.

The signed subject set covers every asset listed above except
`release-attestation.json`, whose signature is the envelope over that subject
set. `SHA256SUMS` is itself a signed subject. `verify-release` rehashes every
external asset and validates the evidence directory without receiving a
private key.

The notice inventory is deliberately not presented as completed legal review.
It inventories embedded notice-like files and Cargo license identifiers
observed by the pinned policy tool, leaves SPDX conclusions as `NOASSERTION`,
and retains the explicit status
`generated_inventory_requires_independent_license_review`.

## Protected automatic-release workflow

`.github/workflows/release-draft.yml` retains its historical filename but is
dispatched automatically after a successful fresh candidate record. Its
signing job has read-only repository permission, receives the protected seed
through the `release-signing` environment, verifies that the retained
generation matches `engineering-candidate.json`, and stores signed evidence
under the private retained-output root.

A separate `release-draft` job keeps `GITHUB_TOKEN` read-only and receives an
environment-scoped, repository-limited release API credential but no signing
seed or deploy key. It keylessly verifies the retained handoff, creates a
public non-prerelease GitHub release marked latest, redownloads every asset,
and keylessly verifies the downloaded set.

## Operational requirements

For automatic publication:

1. import the raw seed into a protected release environment without printing
   it;
2. establish backup and recovery appropriate to the publisher;
3. keep the signing environment free of repository write authority;
4. keep the signing seed, tag deploy key, and release API credential in
   separate environments, and prevent pull-request jobs and unrelated
   proprietary application processes from receiving them;
5. bind the signing receipt, release attestation, and all release assets to one
   exact reviewed commit/tree and merged candidate digest set;
6. verify the public key and fingerprint independently after import; and
7. exercise release creation, redownload verification, publication rollback, and
   key recovery without deleting or replacing unrelated assets.

Required-reviewer pauses are intentionally absent from the automatic
engineering channel. They may be added for a separately defined stable channel
without combining signing, tag, and publication authority.

Loss of the seed stops updates for installed images carrying this pin.
Suspected disclosure requires halting publication. A replacement key cannot be
self-authorized by a downloaded manifest; rotation needs a separately reviewed
transition delivered by already trusted bytes or a manual user update.
