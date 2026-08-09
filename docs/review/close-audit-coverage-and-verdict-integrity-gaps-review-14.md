# Review — close-audit-coverage-and-verdict-integrity-gaps (round 14)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. The live cold-corpus capacity attempt proved that the
four-shard production design cannot reliably finish inside the existing CI
budget. Preserve that blocker evidence and revise the production workflows to
fourteen deterministic shards. This round is one atomic capacity-remediation
slice; do not repeat the full local corpus scan and do not change download,
archive, or job timeout limits.

## Gate status

- Reviewed commit: `570a89c9e775fe31cf2330e7f9a789191cc2ec76`.
- The round-complete marker is valid and the feature worktree is clean.
- `docs/agent_conversations/2026-08-08_audit-live-corpus-capacity-blocker.json`
  durably records the stopped cold run: 579 eligible releases, 161 completed
  in 2,412.76 seconds, and a 144.6-minute projected unsharded duration.
- The blocker evidence also records that all observed release ZIP sizes remain
  below the existing 64 MiB limit and that the isolation/integrity checks stayed
  clean. This is a throughput-design failure, not a reason to raise safety
  limits.
- The last full local gate was green: actionlint/Ruff/format plus `616 passed,
  61 subtests passed`.

## Required changes

1. Change the full-corpus matrices in both the pull-request and scheduled audit
   workflows from four shards to fourteen deterministic shards: indices
   `0..13`, `--shard-count 14`, and consistent `/14` job names, summaries,
   caches, and artifact names. Preserve the changed-release path's existing
   behavior.
2. Make both aggregation paths require exactly fourteen exit-status, report,
   and verdict-delta artifacts. Preserve existing fail-closed handling for
   missing, duplicate/conflicting, and intentionally empty shard outputs.
3. Update executable workflow, aggregation, and sharding tests to exercise all
   fourteen shards, including deterministic assignment, pairwise disjointness,
   complete union coverage, and the expected node/artifact names.
4. Update the README, audit-gating overview, plan acceptance text, and their
   documentation assertions from four to fourteen production shards. Revise
   the capacity contract so production success is measured against the maximum
   fourteen-shard wall-time estimate; preserve semantic equality between
   unsharded and sharded results through deterministic tests and the existing
   mutation evidence. Do not describe the failed sequential cold run as a
   required production success condition.
5. Add a durable follow-up JSON evidence record under
   `docs/agent_conversations/` that references the blocker artifact and records
   the actual fourteen-shard release-count balance, observed mean and p95
   per-release timings, projected maximum-shard runtime/headroom, and the 1,162
   repeated baseline enumeration requests. Explicitly record hosted-runner
   concurrency/API behavior as deferred validation because pushing or starting
   Actions is outside this implementation boundary.
6. Do not rerun the full corpus locally and do not raise any timeout or content
   limit. Run the focused workflow/sharding/documentation tests, actionlint, and
   the complete local quality gate; commit the atomic slice and write a new
   round-complete marker.

STATUS: CHANGES_REQUESTED
