# Review — close-audit-coverage-and-verdict-integrity-gaps (round 24)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. Round 23 materially strengthened the proof regression, but
four assertions remain structural rather than independently derived. Correct
only those assertions in the same test; the proof and inventory are already
valid and must not be rerun or changed.

## Gate status

- Reviewed commit: `678cd83443e748a0001f9882eae4920a82fbb865`.
- The round-complete marker is valid and the feature worktree is clean.
- The complete local gate passed with `646 passed, 61 subtests passed`; the
  focused nodes passed (`3 passed`) and the documentation module passed (`6
  passed`).
- Round 23 is correctly test-only and meaningfully validates the tracked policy
  checksum/values, request/helper/error counters, zero violations, proof result,
  projection linkage, and deferred warm/hosted boundaries.

## Required changes

1. Reconstruct the exact canonical corpus rows and inventory payload from the
   proof detail records, serialize them with the production evidence's canonical
   JSON rules, compute SHA-256, and compare the results with the recorded corpus
   and inventory digests. Do not merely validate hexadecimal shape.
2. Join every release mapping to its exact unique source-inventory record and
   assert the mapped byte count, archive hash/content identity, error state, and
   bounded-download result agree. Set equality without record-by-record field
   validation is insufficient.
3. Assert the tag parsed from each release identity exactly equals the joined
   tag-to-commit record's `tag_name`, and assert the source archive URL is the
   exact canonical commit-addressed GitHub tarball URL rather than merely
   nonempty.
4. Reconcile the independently derived mapped-release byte sum with
   `request_metrics.cumulative.mapped_release_bytes` in addition to the proof
   summary.
5. Keep this round limited to the existing documentation test and review note.
   Do not alter evidence, plan, projection, production code, policy, workflows,
   or limits, and do not rerun the inventory/full audit.
6. Run the focused nodes, full documentation module, and complete local quality
   gate; commit the atomic test correction and write a new round-complete
   marker.

STATUS: CHANGES_REQUESTED
