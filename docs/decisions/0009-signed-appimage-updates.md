# 0009: Signed full-file AppImage updates

Status: accepted; channel name amended by Decision 0011

## Context

The authenticated Codex desktop application enables its vendor updater only on
macOS and Windows. Linux users need an update path owned by this packaging
project. AppImage update metadata and transport alone do not establish the
project-specific release identity required by the threat model, and replacing
a running Electron process in place would make failure behavior difficult to
audit.

The update mechanism cannot solve the explicitly out-of-scope ability of the
owning UID to alter ordinary files after return.

## Decision

Ship a second original Rust binary, `codex-linux-updater`, in each AppDir.
`AppRun` starts it in the background for Type-2 AppImage launches and exposes a
foreground `--codex-linux-update-now` path. The running application is never
restarted or hot-swapped; successfully installed bytes are used on the next
launch.

Use a project-owned Ed25519 release key independently pinned in
`data/update-contract.json`. A canonical schema-1 payload binds the automatic
channel, Linux x86_64 target, immutable GitHub release tag and URL,
version/build, source commit, release timestamp, complete AppImage length and
SHA-256, and matching provenance SHA-256. Downloaded metadata cannot supply or
rotate the verifying key.

Download the complete AppImage rather than executing a delta. Require bounded
headers, a singular strict `Content-Length`, identity encoding, an allowed
GitHub final HTTPS origin, the signed full-file digest, and a Linux x86_64
Type-2 marker. Serialize cooperative updates with an adjacent advisory lock.

Create the private replacement in the current AppImage directory. Commit with
`renameat2(RENAME_EXCHANGE)`, then publish the old inode without replacement as
`<name>.rollback-<old-version>-<old-build>` and fsync the directory. Roll back
ordinary post-exchange errors with another atomic exchange.

`generate-update-key` writes a no-replace raw seed at mode 0600 and emits only
its public identity. `sign-update` reconciles the complete AppImage with
canonical packaging provenance, requires the seed to match the compiled pin,
signs the canonical payload, self-verifies, and publishes without replacement.
Protected custody and release-environment evidence remain separate release
gates.

## Consequences

- A writable, directly launched AppImage can update quietly while Codex is in
  use and takes effect on the next launch.
- A symlink launch path or read-only installation fails closed and requires a
  manual replacement.
- Each successful update retains a versioned full rollback image and therefore
  consumes additional disk space.
- Full downloads use more bandwidth than deltas but keep the authentication and
  recovery boundary small and explicit.
- Losing the private release seed prevents new manifests for the existing pin;
  key rotation requires a separately reviewed transition delivered by an
  already trusted release or a manual update.
- Atomic exchange keeps the launch path complete across crashes, but it does
  not make user-owned output immutable against the same UID.

Decision 0011 renamed the published update channel from `stable` to
`automatic` so update metadata cannot be confused with a stable-support claim.
