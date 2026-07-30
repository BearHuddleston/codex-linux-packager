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
channel:            stable
target:             linux-x86_64
```

The command obtained 32 bytes from the operating system random source, created
the seed with no replacement at mode 0600 beneath ignored `work/`, fsynced the
file and its parent, and emitted only the public identity. The raw seed is not
part of Git and must never appear in logs, command arguments, artifacts,
fixtures, or pull requests.

This record establishes the source-tree pin. It does not by itself establish
protected key custody, recovery, reviewer separation, or release approval.

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
codex-desktop-unofficial-x86_64.AppImage
provenance.json
codex-linux-x86_64-update.json
```

The latest release alias serves only the small signed manifest. The signed
payload points at the AppImage under its immutable release tag.

## Operational requirements

Before first publication:

1. import the raw seed into a protected release environment without printing
   it;
2. establish backup and recovery appropriate to the publisher;
3. require reviewer approval for that environment;
4. prevent pull-request jobs and proprietary application processes from
   receiving the seed;
5. bind the signing receipt and release assets to one exact reviewed commit;
6. verify the public key and fingerprint independently after import; and
7. exercise release rollback without deleting or replacing unrelated assets.

Loss of the seed stops updates for installed images carrying this pin.
Suspected disclosure requires halting publication. A replacement key cannot be
self-authorized by a downloaded manifest; rotation needs a separately reviewed
transition delivered by already trusted bytes or a manual user update.
