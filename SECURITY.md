# Security policy

`codex-linux-packager` is pre-release software. No release line is currently
supported for production use, and no public binary is approved.

Please report suspected vulnerabilities privately through GitHub's security
advisory mechanism for this repository. Include the affected commit, exact
command, synthetic reproducer where possible, observed result, expected result,
and relevant artifact digests. Do not attach proprietary Codex payloads,
credentials, or private keys.

Security findings are evaluated against `docs/threat-model.md`. Findings that
propose expanding that scope are valuable, but require an explicit scope
decision before they become release blockers. A review applies only to the exact
source tree and artifact digest set it examined.

Do not publish a stable AppImage or imply release readiness based only on green
unit tests. The independent legal, supply-chain, platform, runtime, signing, and
recovery gates in `docs/release-gates.md` remain mandatory.
