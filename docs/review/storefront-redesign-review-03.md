# Review — storefront-redesign (round 03)

Branch: `feat/storefront-redesign`
Reviewed against: `docs/plans/2026-08-31_storefront-redesign.md`

## Verdict

The requested five-column version table is present and excludes Audit, but its
Source state can mislabel Extended versions and remain stale after metadata
loads. Correct these two observable states before integration.

## Gate status

The completed round reported actionlint and all mutations passing, Ruff clean,
Node 14/14, Playwright 7/7, and pytest 1,104 tests plus 66 subtests. Read-only
review found the two source-state gaps below; the existing fixtures do not cover
either optional-metadata transition.

## Required changes

1. **Never label a known Extended artifact as official when metadata is absent.**
   The catalog already distinguishes custom versions with `version.artifact`.
   Keep the exact metadata source link when it resolves. If it does not resolve,
   use `Official catalog` only for an artifactless version; a version with an
   artifact must use a truthful unavailable-source label. Cover both states when
   `/storefront.json` rejects or has not completed.

2. **Refresh an open version table when optional metadata arrives.**
   A detail dialog opened after the catalog but before `/storefront.json`
   completes currently keeps its initial fallback rows after `loadOptionalData`
   rerenders the cards. Rebuild the active detail content when optional metadata
   settles without reopening the dialog, resetting focus, or corrupting body
   overflow restoration. Add a delayed-metadata Playwright regression that opens
   details first and then proves the exact per-version source link appears.

Re-run the Node and Playwright suites and the complete
`scripts/orchestration/run-quality-gates` hook. Record the final actionlint,
Ruff, Node, Playwright, and pytest tallies.

STATUS: CHANGES_REQUESTED
