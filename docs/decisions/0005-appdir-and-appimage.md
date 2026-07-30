# Decision 0005: deterministic AppDir, AppImage, and runtime tests

- Status: accepted
- Date: 2026-07-30

## Decision

Construct AppDirs from one independently pinned runtime manifest with complete
file inventory, normalized modes, and a caller-supplied `SOURCE_DATE_EPOCH`.
The desktop entry and icon are original, generic, MIT-licensed tooling assets
and make the unofficial/unaffiliated status explicit.

Electron is renamed `codex-desktop` so it enters packaged mode. AppRun supports
auto, Wayland, and X11. The bundled setuid helper cannot retain its privileged
ownership/mode inside an ordinary AppImage, so AppRun passes
`--disable-setuid-sandbox` and exercises Chromium's user-namespace sandbox. It
never passes `--no-sandbox`.

Use the exact stable-tag contracts in `data/appimage-contract.json`:

- appimagetool 1.9.1 at revision
  `8c8c91f762b412a19f4e8d2c4b35afb98f2d7c81`;
- Type-2 runtime release 20251108 at revision
  `dd6cebedcbddde9c82f89b011e8e1d40b6e43868`; and
- deterministic zstd SquashFS with 131072-byte blocks, one processor, and no
  xattrs.

Build from two independently constructed AppDir roots. Both appimagetool
invocations, final extraction, and host launches run with bubblewrap network
and PID namespaces, deterministic environments, bounded output, and
process-group cleanup. The AppImages must be byte-identical.

Extract the final filesystem and revalidate all regular-file bytes and modes
against AppDir provenance. Directory timestamps are not compared after
unsquashfs because extraction recreates directories; every source AppDir
timestamp remains strict. Audit every extracted ELF with digest-pinned
`readelf` and record its complete requirements in AppImage provenance. The
separate `release-readiness` assessment rejects any recorded GLIBC requirement
above 2.36.

Require genuine extract-and-run launches on both host Wayland and X11. Each
must reach packaged-mode, exact app-server handshake, and ready-to-show markers
and remain healthy until its bounded observation deadline.

Additionally build the baseline in `containers/appimage-baseline.Dockerfile`
from exact Debian snapshot repositories. The pack command accepts only an exact
local image ID and verifies its labels, architecture, OS, non-root user, glibc,
Dockerfile/source digests, and sorted package inventory. Launch the final
AppImage under Xvfb with OCI networking disabled, capabilities dropped,
no-new-privileges, and the same runtime markers.

## Consequences

The AppImage provenance truthfully records both isolation mechanisms, the
twice-built digest, complete ELF audit, host launch evidence, controlled
older-glibc launch evidence, and process containment.

Host Wayland/X11 and one controlled X11 baseline do not clear the full
KDE/GNOME, FUSE/extract-and-run, sandbox, or older-distribution release matrix.
Those remain Phase 6 blockers.
