# Decision 0007: separate public detection from trusted rebuilds

- Status: accepted
- Date: 2026-07-30

## Decision

Add a typed `check-upstream` state machine and an hourly public monitor. Compare
the authenticated feed identity with the independently reviewed runtime
contract and last digest-bound engineering candidate. Emit `current`,
`review_contract_update`, or `rebuild_candidate`.

A feed change is not permission to update its own Electron, native, Codex CLI,
ripgrep, patch, or packaging-tool contracts. The public monitor opens an issue
and stops at `review_contract_update`. Only after a reviewed contract change
may it emit `rebuild_candidate`.

Add a separate dispatch-only workflow for a dedicated
`codex-packager-trusted` Linux x86_64 runner. It performs exact artifact
acquisition, the complete packaging pipeline, real launch checks, and
release-readiness. It retains payload-bearing outputs locally and opens a pull
request containing only the new schema-1 digest record. It uploads no
proprietary artifact and creates no release. The payload-handling job has no
persisted checkout credential and only read permission; a separate
GitHub-hosted job receives the bounded digest record and write authority.

## Consequences

An upstream release is detected automatically, while changes to independent
trust contracts remain reviewable. Once the runner, reviewed cache, variables,
and enablement switch exist, a current contract with a stale candidate is
rebuilt automatically.

Cloning the repository does not install or enable a self-hosted runner. Until a
dedicated or ephemeral runner is configured, monitoring remains active but
rebuild dispatch remains disabled. This is an explicit operational
prerequisite, not a hidden claim of completed protected automation.

The candidate record is monitoring state and evidence routing. It cannot clear
legal, branding, signing, platform-matrix, recovery, or independent-review
gates, and it never changes the `not_release_approved_do_not_publish`
disposition.
