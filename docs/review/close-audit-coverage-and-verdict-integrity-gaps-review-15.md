# Review — close-audit-coverage-and-verdict-integrity-gaps (round 15)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. The fourteen-shard production change is correct, but its
documentation currently overstates the capacity evidence. Correct only the
verification record; do not change workflows, production code, limits, or run
the live corpus.

## Gate status

- Reviewed commit: `e3b39311d636f1a230189a356c45f8cb4c38d9f7`.
- The round-complete marker is valid.
- Both workflows correctly use deterministic fourteen-shard full-corpus
  matrices and exact-fourteen aggregation guards; changed-mode selection is
  unchanged.
- Focused review tests passed (`119 passed`), actionlint passed both workflows,
  and the complete quality gate passed with `623 passed, 61 subtests passed`.
- The projection arithmetic and preserved hashes reproduce, and no timeout or
  content limit changed.

## Required changes

1. Correct the plan statement that says cold and warm corpus budgets were
   verified locally. The preserved blocker evidence records that the warm run
   and warm zero-work assertions were not executed after the cold budget
   failure; describe them as deferred/unverified, not complete.
2. Explicitly add the unexecuted warm run/zero-work assertions and the
   incomplete source-archive size inventory to
   `docs/agent_conversations/2026-08-08_audit-fourteen-shard-capacity-projection.json`
   as open/deferred uncertainties, with a reference to the blocker artifact.
3. Keep the source-archive inventory acceptance requirement visibly open; do
   not silently mark it complete or remove it in this slice.
4. Add documentation assertions that prevent the plan and projection evidence
   from describing either the warm verification or complete source-archive
   inventory as verified.
5. Run the focused documentation/evidence tests and the complete local quality
   gate, commit this docs-only/test-only correction, and write a new
   round-complete marker. Do not rerun the live corpus.

STATUS: CHANGES_REQUESTED
