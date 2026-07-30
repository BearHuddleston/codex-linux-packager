# Decision 0004: controlled native build and Linux runtime

- Status: accepted
- Date: 2026-07-30

## Decision

Rebuild only `better-sqlite3` 12.9.0 and `node-pty` 1.1.0 from an
integrity-locked npm graph for Electron 42.3.0, embedded Node 24.15.0, and
module ABI 146. Exact reviewed upstream patches are permitted only when their
package version, upstream commit, patch digest, and every before/after file
digest match `data/native-contract.json`.

Compilation runs in:

`docker.io/library/node@sha256:20a424ecd1d2064a44e12fe287bf3dae443aab31dc5e0c0cb6c74bef9c78911c`

This is Node 22.22.0 on Debian Bookworm with npm 10.9.4, glibc 2.36, and GCC
12.2.0. The image is read-only, capabilities are dropped, build/output/cache
mounts are explicit, the process uses the invoking UID, and network access is
disabled unless the caller explicitly selects and records otherwise.

The older Debian Bullseye baseline was tested and rejected: GCC 10 lacks the
C++20 `<source_location>` support required by the Electron 42 V8 headers. The
Bookworm toolchain builds the exact graph while still enforcing a substantially
older glibc boundary than the development host.

Native outputs must be Linux x86_64 ELF, match exact paths and digests, require
no GLIBC symbol newer than 2.36, and complete real SQLite and PTY round trips
when loaded by the exact target Electron runtime. A synthetic ELF cannot clear
these probes.

Runtime assembly independently validates the stage and native manifest, then
combines the exact official Electron Linux x64 ZIP with the exact official
Codex 0.146.0-alpha.3.1 Linux x86_64-musl package. Authenticated source markers
must reconcile the Codex and ripgrep identities. Every considered file is
included or omitted with an explicit disposition; Mach-O, PE, and
foreign-architecture ELF content is not silently copied.

## Consequences

Build-host Node must be at least 22.12.0, but host Node does not compile the
accepted native outputs. OCI runtime and optional sudo bytes are independently
digest-bound. The runtime manifest carries a complete normalized inventory and
the exact native-manifest digest.

This controls build and ABI evidence; it does not grant redistribution rights
or make outputs immutable against the owning UID after publication.
