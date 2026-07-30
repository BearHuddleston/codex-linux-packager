# Decision 0002: feed transport and XML parsing

- Status: accepted
- Date: 2026-07-30

## Decision

The Linux x86_64 pipeline inspects the fixed official x86_64 Sparkle endpoint:

`https://persistent.oaistatic.com/codex-app-prod/appcast-x64.xml`

The endpoint was independently confirmed from the same OpenAI-controlled
distribution origin used by the published Codex CLI installer source. It is not
caller-configurable in live mode. A bounded local fixture is the only offline
alternative.

Use:

- `ureq` 3.3 with Rustls and WebPKI roots for blocking HTTPS. Automatic
  decompression and redirects are disabled. Response headers and bodies have
  explicit bounds.
- `quick-xml` 0.41.0 in event mode. This patched release addresses the
  duplicate-attribute and namespace-allocation advisories published in June
  2026. The parser rejects DTDs, entity declarations,
  processing instructions, CDATA, excessive nesting, duplicate critical
  fields, and non-UTF-8 input before constructing typed metadata.
- `base64` 0.22 without optional features for canonical signature decoding.
- `sha2` 0.11 for complete-input SHA-256 provenance.

All selected versions support Rust 1.85 and use licenses admitted by
`deny.toml`. Feed XML is never authenticated by transport metadata alone; the
artifact signature is verified over the complete downloaded archive in Phase 2.

Artifact URLs use a deliberately smaller grammar than a general URL parser:
the exact ASCII HTTPS prefix above followed by one flat ASCII archive filename.
This rejects user information, ports, alternate hosts, escaping, queries,
fragments, traversal, and nested paths while avoiding an unrelated IDNA/ICU
dependency graph.

The current x86_64 feed may omit `sparkle:hardwareRequirements`. In that case,
the result records `fixed_x86_64_feed_endpoint` as the architecture source.
Any present architecture declaration must be exactly `x86_64`; a conflict is
rejected.
