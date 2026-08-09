# Review — close-audit-coverage-and-verdict-integrity-gaps (round 19)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. Round 18 improved aggregate validation, but the integrity
check is global rather than shard-paired and still has three bypasses. Correct
only these aggregate-integrity defects in this round.

## Gate status

- Reviewed commit: `4c587f41643f8cc241f286e2848dbc3b508b2d6d`.
- The round-complete marker is valid and the feature worktree is clean.
- The complete local quality gate is green with `639 passed, 61 subtests
  passed`; focused review tests passed (`138 passed`).
- Reproductions at the reviewed marker show that aggregation accepts: a true
  two-way swap of otherwise-valid alpha/beta shard deltas; a completed UNKNOWN
  PASS report with its matching delta; a completed PASS report with all delta
  arguments omitted; and a supplied delta with an unexpected field that is
  normalized away for comparison but retained in published output.

## Required changes

1. Pair each shard report with its corresponding shard verdict-delta artifact.
   Require equal artifact counts and compare the exact report-derived delta for
   each shard against that shard's supplied delta before performing the global
   merge. A two-way swap must fail even when the global union is unchanged.
2. Require `identity_status == "CURRENT"` for every completed aggregate report.
   Reject completed STALE_HASH and UNKNOWN records before they can create a
   durable PASS/WARN/BLOCK verdict.
3. Require a verdict-delta argument for every supplied shard report, including
   intentionally empty `{}` delta files. Omitting the entire delta list or any
   individual shard delta must fail closed; valid empty shards must continue to
   pass.
4. Make delta equality exact. Reject unexpected fields rather than dropping
   them during comparison and then publishing the unnormalized input.
5. Replace the ineffective duplicate-alpha splice test with a genuine two-way
   alpha/beta delta swap. Add completed STALE_HASH/UNKNOWN negatives, no-delta
   and count-mismatch negatives, an unexpected-field negative, plus clean
   multi-shard and empty-shard controls.
6. Keep this correction scoped to aggregate integrity. Do not perform source
   inventory work or unrelated refactoring.
7. Run focused aggregation/schema/workflow tests and the complete local quality
   gate, commit the correction, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
