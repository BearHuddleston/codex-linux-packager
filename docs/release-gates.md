# Release gates

Canonical tests are necessary engineering evidence, not release approval. No
public binary or stable AppImage may be published until every applicable gate
below is explicitly cleared for one exact source commit and artifact digest set.

## Legal and identity

- Written authority to redistribute the relevant OpenAI payload.
- Written authority for any OpenAI trademark, name, icon, or branding use.
- Complete third-party notices and a deterministic SBOM.

The MIT tooling license does not satisfy these gates.

## Supply chain and signing

- Every release input and tool is version- and digest-pinned.
- Signed checksums are produced with protected signing keys.
- Provenance and attestation bind the exact commit, lockfile, build inputs, and
  output digests.
- Branches, tags, release environments, and automation are protected.
- The second reproducibility build runs from an independent root, with networking
  disabled, against a previously verified cache, and is byte-identical.

## Runtime and platform

- Built native modules pass real SQLite and PTY round trips under the exact
  Electron runtime.
- The final AppImage is extracted and audited, including every ELF architecture,
  ABI, interpreter, dependency, and glibc requirement.
- Genuine launch tests cover KDE and GNOME, Wayland and X11, FUSE and
  extract-and-run, and Chromium sandbox behavior.
- Compatibility is tested in a controlled older-glibc baseline container or VM,
  not only on the development host.

## Operations

- Publication rollback and recovery are exercised.
- Review is frozen to one exact commit/tree and artifact digest set.
- Findings against other bytes are reproduced before being carried forward.
- A decisive blocker ends the review cycle; another successor cycle requires an
  explicit decision.

Green unit tests, successful source builds, or a runnable local AppDir do not
implicitly clear any gate in this document.
