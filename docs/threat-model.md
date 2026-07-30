# Threat model

This document is the binding security scope for `codex-linux-packager`. Changes
to this scope require an explicit user decision. Rust improves memory and type
safety; it does not make mutable, user-owned filesystem paths immutable.

## Security objective

Within the in-scope boundaries below, the tool rejects unauthenticated,
ambiguous, unsafe, or resource-exhausting inputs; avoids publishing partial
results; and records enough deterministic provenance to identify every accepted
input and produced output.

Publication guarantees the bytes produced at the commit boundary under this
documented model. It does not promise that the owning UID cannot modify them
afterward.

## In scope

- Malicious, malformed, oversized, ambiguous, or truncated feed, XML, archive,
  or ASAR input.
- Network errors, redirects, duplicate or conflicting headers, incorrect
  lengths, and wrong final URLs.
- Signature forgery, wrong signing keys, self-authenticating key rotation, and
  mismatched bundle metadata.
- ZIP traversal, unsafe raw names, duplicate critical members, symlinks, special
  files, decompression bombs, unsupported formats, and foreign binaries.
- Accidental or concurrent cooperative writers and racing destination names.
- Crashes and ordinary errors before durable publication.
- Symlink and pathname substitution where the operating system's normal
  permission boundaries provide meaningful separation.
- Output/input aliasing and cleanup that might delete caller-owned files.
- Reproducibility drift, hidden network access, unpinned tools, and incomplete
  manifests.

## Explicitly out of scope

- A malicious process already running as the invoking user and able to use
  `ptrace`, `/proc/<pid>/fd`, code injection, writable aliases, or arbitrary
  writes to user-owned outputs.
- Permanent immutability of ordinary files after the public command has
  returned.
- Protection after the user's account, signing environment, or build runner is
  compromised.

Rehashing repeatedly only moves the last-verifier window. Changing modes does
not revoke the file owner's authority, and a retained directory descriptor does
not freeze descendant inodes. Implementations and reviews must not claim these
techniques close the out-of-scope same-UID problem.

If stronger same-UID guarantees are requested, implementation must stop. The
next design should instead propose a separately privileged publisher service or
kernel-enforced immutable storage with its own threat model and operational
review.

## Trust anchors and boundaries

- Feed transport identity and artifact-signing identity are distinct checks.
- The artifact signing key and fingerprint must be independently pinned; an
  artifact cannot authorize its own key rotation.
- Authentication applies to the exact complete artifact bytes. Extraction does
  not broaden what is trusted or permitted to be staged.
- External runtimes, CLIs, native packages, ripgrep, and packaging tools are
  independent inputs and require exact version and digest contracts.
- The official Sparkle artifact key and this project's AppImage release key are
  independent trust roots. The former authenticates source input; the latter
  authenticates a final Linux release. Downloaded metadata cannot authorize a
  replacement release key.
- Runtime updates accept only canonical schema-1 manifests, immutable-tag asset
  URLs in the reviewed GitHub repository, a strictly newer version/build, and a
  complete AppImage matching the signed length and SHA-256.
- Git, the build host, the signing environment, and release automation are
  operational trust boundaries, not consequences of passing unit tests.

## Availability and resource policy

All untrusted reads, parses, traversals, decompression operations, network
responses, and subprocess output must have explicit bounds. Subprocesses need
timeouts and group cleanup. Ordinary tests use synthetic local inputs and do not
depend on a live OpenAI service.

## Publication semantics

A phase may prepare output in a private generation and publish it through a
documented commit boundary. Precommit failures preserve the previously committed
output. Cleanup is limited to objects the current invocation created and proved
it still owns under the in-scope model; it must not remove caller-owned or
substituted paths.

The runtime updater prepares a private replacement in the current AppImage's
directory and commits with Linux `RENAME_EXCHANGE`, so the launch path always
names either the complete old image or the complete verified new image. It then
publishes the prior inode under a versioned no-replace rollback name and fsyncs
the directory. An ordinary error after exchange is rolled back with another
atomic exchange. A crash between exchange and rollback-name publication can
leave the prior bytes at the updater's private name, but cannot leave the
current launch path absent or partially written.

After a public command returns, ordinary user-owned output remains mutable by
that user. Provenance describes what the tool committed, not an eternal
property of the path. Rechecking, atomic exchange, a retained backup, and a
signed manifest do not change that limitation.
