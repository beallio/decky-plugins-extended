# Review — quota-safe-security-audit (round 15)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4A is functionally clean. One test-only correction is required before closing the slice: the
test named as the real empty-destination final race currently exits at the early `lstat()` guard and
never calls the no-clobber primitive. Do not change implementation behavior and do not begin Task 4B.

## Gate status

- Commit reviewed: `009182539beea171d71fe9e6c1f021a555f525fc`; tree clean, marker valid,
  implementer session absent, and `security-verdicts.json` unchanged.
- Root and both Terra reviews found the Task-4A implementation functionally clean. Focused runs
  report `62 passed`; root complete gate reports `836 passed, 61 subtests passed` with actionlint
  mutation controls and Ruff clean.
- Independent real-race reproductions create an empty destination immediately before native
  `renameat2(RENAME_NOREPLACE)`: the call fails closed and preserves the destination inode.
- Lazy parsing stops at the over-limit header, the plan stays bounded, explicit empty directories
  materialize safely, and every earlier transport/path/hash/metadata/cleanup contract remains green.
- Round-14 red/green logs were not preserved. This is a process-evidence gap, not a current functional
  failure; do not fabricate or relabel historical output.

## Required changes

1. Keep the current pre-existing-destination test as the early zero-transport guard. Replace or split
   the misleading `...real_renameat2_with_empty_destination` test so a wrapper around
   `_rename_without_replace` creates an empty destination only after initial validation and
   extraction, records its inode, then delegates to the original native helper. Assert the helper is
   reached, materialization raises `SourceSnapshotError: destination already exists`, the exact inode
   and emptiness survive, staging is cleaned, and no fallback rename/move occurs. Retain the separate
   nonempty-sentinel race and unsupported-platform tests.
2. Because the implementation already has the correct behavior and the corrected test should pass
   immediately, do not invent a red phase. Preserve a distinct round-15 focused green log and full
   quality-gate log, record exact tallies, keep `security-verdicts.json` unchanged, commit only this
   test correction, leave the tree clean, recreate the completion marker, and stop for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
