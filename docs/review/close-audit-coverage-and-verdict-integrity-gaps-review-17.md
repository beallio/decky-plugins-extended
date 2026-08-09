# Review — close-audit-coverage-and-verdict-integrity-gaps (round 17)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. Update detection currently ignores the configured
enforcement mode, so report-only policy can suppress the rebuild needed to ship
a release whose current verdict is BLOCK. Fix only this mode-parity gap in this
round.

## Gate status

- Reviewed commit: `bd0e5aee4b772d32400a1a10b2ad401d9b1b609e`.
- The round-complete marker is valid and the feature worktree is clean.
- Round 16's nonzero-shard enumeration fix reviewed CLEAN with `195` focused
  tests passing.
- Final-review reproduction: with report-only policy, an empty live catalog,
  and a CURRENT BLOCK verdict, `check_upstream()` returned no missing update.
  The update checker unconditionally removes blocked versions instead of
  applying that exclusion only under enforce mode.

## Required changes

1. Load the configured enforcement mode through the existing centralized
   policy path and pass it explicitly into both upstream-release and
   configured-release update detection.
2. Exclude a CURRENT BLOCK release from update/rebuild candidates only when
   enforcement mode is `enforce`. Under `report-only`, retain the release as an
   eligible missing/update candidate so the catalog can be rebuilt and publish
   the report-only result.
3. Preserve existing behavior for historical/non-current verdicts, WARN/PASS,
   stale/unknown findings, and enforce mode.
4. Add focused regressions for both upstream and configured releases under
   report-only mode, corresponding enforce-mode fences, and a `main()`-level
   parity test proving the loaded mode reaches both paths.
5. Keep this round scoped to update-policy parity and its tests. Do not change
   aggregate schema/cross-artifact validation or source-inventory verification.
6. Run focused update-policy tests and the complete local quality gate, commit
   the atomic fix, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
