# Review — close-audit-coverage-and-verdict-integrity-gaps (round 16)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. A repository pagination/enumeration failure on a nonzero
production shard can currently be discarded, allowing that shard to emit an
empty complete report and exit zero. Fix only this sharded enumeration
fail-closed gap in this round.

## Gate status

- Reviewed commit: `b14294ce6a240a7f8c033a7a60cf22128f64d9b6`.
- The round-complete marker is valid and the feature worktree is clean.
- The complete local quality gate is green: actionlint/Ruff/format plus `624
  passed, 61 subtests passed`.
- Final-review reproduction: shard 7 received a repository later-page
  enumeration error, emitted an empty report described as complete, and exited
  zero. Aggregation has no shared worklist fingerprint that could detect the
  missing releases after that local error is discarded.

## Required changes

1. In sharded audit mode, treat every repository enumeration/pagination error
   observed by the local shard runner as run-global failure, regardless of
   shard index. Do not permit a nonzero shard with such an error to emit a
   successful/complete report or publishable verdict delta.
2. Preserve the existing unsharded and successful-shard behavior, output
   isolation, deterministic assignment, and exit-precedence contract.
3. Add a regression that injects a later-page repository enumeration failure
   into a nonzero shard and proves the shard fails closed and the workflow
   aggregation/publication path cannot accept the run as complete.
4. Keep this round scoped to enumeration failure handling and its tests. Do not
   implement shared-manifest fingerprinting, update-policy parity, aggregate
   schema/cross-artifact validation, or source-inventory verification here.
5. Run the focused audit/workflow tests and the complete local quality gate,
   commit the atomic fix, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
