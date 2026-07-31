# Security policy

`codex-linux-packager` publishes an unofficial automatic engineering channel.
No release line is currently claimed as stable or supported for production
use.

Please report suspected vulnerabilities privately through GitHub's security
advisory mechanism for this repository. Include the affected commit, exact
command, synthetic reproducer where possible, observed result, expected result,
and relevant artifact digests. Do not attach proprietary Codex payloads,
credentials, or private keys.

Security findings are evaluated against `docs/threat-model.md`. Findings that
propose expanding that scope are valuable, but require an explicit scope
decision before they become release blockers. A review applies only to the exact
source tree and artifact digest set it examined.

Do not label an AppImage stable or supported based only on green unit tests.
Automatic publication additionally requires the exact source authentication,
native ABI probes, twice-built equality, final ELF audit, Wayland/X11 launches,
older-glibc launch, protected signing, and redownload verification defined by
the workflows. Broader stable gates remain in `docs/release-gates.md`.

Packaged AppImages contain a background HTTPS updater. Reports involving its
schema-1 manifest parser, pinned release key, GitHub redirect allowlist,
full-file verification, adjacent lock, atomic exchange, or rollback-name
publication are security-sensitive. The AppImage update key is deliberately
independent from the official Sparkle source-artifact key; neither downloaded
metadata nor a source artifact may rotate it.

The hourly public monitor handles feed and release metadata only. Payload
acquisition and builds belong exclusively on a dedicated or ephemeral runner
carrying the `codex-packager-trusted` label; never attach that label to a runner
exposed to untrusted push or pull-request workflows. Proprietary intermediate
outputs remain local. Only the final public release asset and its evidence are
uploaded by the keyless repository-write job.

The automatic release workflow separates the protected signing seed from
repository write authority. Its signing job must remain read-only and its
repository-write job must remain keyless. Both jobs reverify the exact signed
asset set, but that userspace verification does not make retained owner-writable
files immutable against a hostile process running as the same UID.
