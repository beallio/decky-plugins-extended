# Review — quota-safe-security-audit (round 16)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4A remains functionally clean, but the corrected final-promotion race test has one narrow
regression-fence gap. Add the missing `os.rename` sentinel; do not change implementation behavior
and do not begin Task 4B in this round.

## Gate status

- Commit reviewed: `f00b42f8df0cd759920cd9324eddb012cf393a37`; tree clean, marker valid,
  implementer session absent, and the change is test-only.
- The corrected test now creates the empty destination inside the promotion wrapper after initial
  validation, delegates to the real `_rename_without_replace`, proves the helper was reached, and
  preserves the destination inode and emptiness while cleaning staging.
- Independent Terra verification reports the focused source-snapshot suite green at `62 passed`.
- The test sentinels `os.replace` and `shutil.move`, but not `os.rename`; a future fallback to that
  legacy primitive could therefore escape the intended no-fallback regression fence.
- No distinct round-15 focused or full-gate logs were preserved yet.

## Required changes

1. In the corrected empty-destination final-promotion race test, monkeypatch `audit_source_snapshot.os.rename`
   to raise if called, alongside the existing `os.replace` and `shutil.move` sentinels. Keep all
   current helper-reached, inode, emptiness, exception, and cleanup assertions. Do not alter
   production code.
2. Run and preserve a distinct round-16 focused source-snapshot log and full quality-gate log,
   record their exact tallies, confirm `security-verdicts.json` is unchanged, commit only this test
   correction and review response, leave the tree clean, recreate the completion marker, and stop
   for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
