# Review — quota-safe-security-audit (round 09)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on two remaining strict-schema aliases in Task 3A. All other review-08 functional
contracts pass. Do not begin Task 4 in this correction.

## Gate status

- Focused `tests/test_audit_worker_snapshot.py tests/test_audit_worklist.py`: `144 passed`.
- Root reproduced a v2 progress entry with an arbitrary `unexpected` key loading successfully.
  Terra also confirmed non-string `audit_context_hash` values are accepted.
- Root reproduced `audit_worklist._normalise_worklist_identity()` accepting integer release/asset
  IDs and rewriting them to strings, despite the canonical manifest identity being string-only.
- The Task-3A red log currently contains a green `144 passed` result, so it is not genuine red
  evidence. The tree is clean and the marker is valid at
  `db4cccdd05eafcb690d84753bd513208d441fe6e`.

## Required changes

1. Define and require the exact v2 progress entry key set, including `report`; reject missing and
   unexpected keys in both the writer and loader. Require `audit_context_hash` to be a nonempty
   string and keep the existing strict types/shapes for fingerprint, repository/IDs, artifact hash,
   resolved commit, completion status, and report object. Add writer/loader negatives for extra
   fields and non-string/empty context, including when the valid root fingerprint belongs to another
   snapshot (the document must be validated before returning no resume).
2. Make `_normalise_worklist_identity()` accept only canonical string IDs matching
   `[1-9][0-9]*`; do not stringify integers or other aliases there. Keep `worklist_identity()` as
   the explicit adapter that converts the already validated integer item fields to canonical
   strings before calling the strict seam. Add integer/bool/float/Unicode/zero/leading-zero tests.
3. Capture the new tests' failing output without overwriting it at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task3a-red.log`; write green output to a
   distinct Task-3A green log. Run focused tests and the complete quality gate, keep
   `security-verdicts.json` unchanged, commit only this correction, leave the tree clean, recreate
   the marker, and stop after Task 3A.

STATUS: CHANGES_REQUESTED
