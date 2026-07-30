# codex-linux-packager

`codex-linux-packager` is an auditable, unofficial Linux x86_64 packaging CLI
for authenticated Codex desktop artifacts. It is a clean-room Rust
implementation and supports no other target architecture.

The implemented pipeline can:

1. inspect the fixed official x86_64 Sparkle feed;
2. authenticate a complete downloaded artifact with an independently pinned
   Ed25519 trust root;
3. preflight ZIP and ASAR structure and stage only `source.zip`, `app.asar`,
   and schema-1 provenance;
4. rebuild the exact locked native graph in a digest-addressed Debian
   Bookworm/glibc-2.36 build image for Electron 42.3.0 / module ABI 146;
5. run real SQLite and PTY probes under that Electron runtime;
6. assemble the pinned Linux x86_64 Electron, Codex CLI, and ripgrep runtime
   while omitting and inventorying foreign binaries;
7. build deterministic AppDirs and twice-built byte-identical Type-2
   AppImages with networking disabled;
8. extract and revalidate the final filesystem, audit every included ELF, and
   perform genuine Wayland, X11, and controlled older-glibc launches; and
9. emit a digest-bound release-readiness assessment that leaves every
   independent uncleared gate blocking.

## Release status

Pre-release engineering implementation. No public or stable binary is approved.

This project is unofficial and unaffiliated with OpenAI. The MIT license covers
only this repository's original tooling. It does not grant rights to
redistribute OpenAI payloads or use OpenAI trademarks or branding. The current
release-readiness report is deliberately non-approving because those legal
questions, complete payload notices/SBOM, signing, protected automation, the
full desktop/FUSE matrix, rollback, and frozen independent review have not been
cleared.

Generated outputs prove the bytes produced at their documented commit boundary
under [`docs/threat-model.md`](docs/threat-model.md). They do not become
immutable against a hostile process running as the same owning UID after a
command returns.

## Commands

The public command surface is:

- `inspect`
- `inspect-artifact`
- `stage`
- `extract`
- `build-native`
- `assemble-runtime`
- `build-appdir`
- `pack-appimage`
- `release-readiness`

Run `codex-linux-packager <command> --help` for the exact typed inputs. Paths
used by build and assessment commands are absolute. Acquired inputs and outputs
belong only beneath ignored `work/`, `cache/`, `build/`, `out/`, or `dist/`
directories.

Inspect the fixed live feed:

```bash
cargo run -- inspect
```

Inspect a bounded synthetic local fixture without network access:

```bash
cargo run -- inspect --fixture /absolute/path/to/feed.xml
```

Artifact commands require the exact `signature`, `length`, `version`, and
`build` returned by `inspect`. The production trust root is compiled
independently and is not caller-selectable.

`build-native` defaults to offline npm operation and uses the exact OCI image
in `data/native-contract.json`; network access requires the explicit
`--allow-network` flag and is recorded truthfully. `pack-appimage` requires two
independently constructed AppDirs, exact tool digests, both Wayland and X11
backends, and the exact locally verified older-glibc image ID.

`release-readiness` re-authenticates the complete stage and validates the
manifest chain, AppImage bytes, and Cargo lockfile. A successful command means
the assessment ran successfully; consult `stable_publication_permitted` and
`blocking_gate_ids`. With the presently external gates, the expected value is
`false`.

## JSON and provenance

Machine-readable documents begin at schema `1` and use producer
`io.github.bearhuddleston.codex-linux-packager.rust`. Unknown schemas, older
schemas, unknown fields, and other producers are rejected. There is no implicit
compatibility with Python schema-3 staging state.

JSON is emitted as one compact UTF-8 document followed by a newline. Manifests
inventory exact paths, byte counts, modes, and SHA-256 identities. A later phase
independently validates the evidence it consumes.

## Repository boundary

Never commit OpenAI or Codex application payloads, extracted bundles, branding
assets, native modules, executables, credentials, private keys, or build
outputs. Tests generate only small synthetic fixtures. Live-network and
proprietary-input tests are separately labeled and opt in.

`tests/repository_boundary.rs` checks the candidate Git tree for prohibited
archives, binaries, symlinks, oversized files, obvious credential paths, and
private-key material.

## Development

Rust 1.85.0 is the minimum supported version. Stable Rust is used otherwise.
Run the canonical gates from the repository root:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo audit
cargo deny check
```

See [`AGENTS.md`](AGENTS.md) for RED → GREEN → REFACTOR,
[`docs/architecture.md`](docs/architecture.md) for the implemented data flow,
and [`docs/release-gates.md`](docs/release-gates.md) for the release boundary.
