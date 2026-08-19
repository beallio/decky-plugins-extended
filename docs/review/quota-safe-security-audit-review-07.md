# Review — quota-safe-security-audit (round 07)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 2 is clean-reviewed with no remaining functional finding. The full plan is not complete, so
changes are requested for the next atomic slice: Task 3A's immutable worker data, progress, and
shard-manifest primitives only. Do not expose or execute `--worklist` yet: the current uncached
`audit_release()` path still uses legacy REST source/ref/tree/raw-file calls, and claiming an API-free
worker before Task 4 would be false.

## Gate status

- Terra's final Task 2 review found no functional issue; its focused result was
  `309 passed, 36 subtests passed`, with Ruff clean.
- Root reran the complete gate at `659c774a8eb0d33f9832f58c1b4f8ee999a1143d`:
  actionlint plus all mutation controls, Ruff check/format, and
  `724 passed, 61 subtests passed in 17.59s`.
- The worktree is clean, the round marker is valid, and `security-verdicts.json` retains checksum
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Round-06's implementer green log contains the full Pytest transcript but omits actionlint/Ruff;
  root's complete transcript is preserved at
  `/tmp/decky-plugins-extended/root-review-gate-round06.log`.

## Required changes

For this round only, implement the following Task 3A primitives and stop. Defer the worker CLI,
`audit_release()` routing, prepared source commit/error dispatch, real API-isolation sentinels,
source acquisition, aggregation, workflows, and scanners to later slices.

1. Add a read-only expected-worklist loader that performs the complete Task 2 validation and
   requires an exact lowercase expected fingerprint match. Add deterministic shard selection that
   derives `shard_count` from the validated payload, validates the index, applies the unchanged
   `sha256(canonical_owner_repo + "\0" + release_id) % shard_count` formula, and preserves payload
   order. Define one canonical manifest identity object with exactly `repository`, decimal-string
   `github_release_id`, and decimal-string `asset_id`.
2. Add a worklist-bound progress schema without weakening legacy local-mode progress. Use schema v2
   with exact root fields `schema_version`, `worklist_fingerprint`, and `entries`; bind the same
   fingerprint into every entry alongside the existing resume identity/report fields. A different
   snapshot fingerprint and a legacy v1 document must yield no resumable work for a v2 caller;
   malformed v2 is run-global invalid input. Keep v1 behavior available only to unchanged legacy
   callers.
3. Add strict atomic shard-manifest write/load/validation primitives with exact schema:
   `schema_version`, `worklist_fingerprint`, `source_revision`, `shard_count`, `shard_index`,
   `assigned_identities`, `attempted_identities`, and `report_identities`. Lists use canonical
   identity objects and deterministic worklist/report order. Require unique assigned identities,
   unique attempted/report identities, attempted/report as subsets of the assigned shard, and exact
   attempted/report equality for a completed manifest. Accept an entirely empty assigned shard.
4. Add genuine-red focused tests before implementation for: expected fingerprint match/mismatch and
   tampering without output creation; exact per-index assignment, order, and disjoint-union coverage;
   same/different snapshot resume behavior; v1/v2 separation and malformed v2; manifest round-trip
   and empty shard; wrong fingerprint/source/count/index/wrong-shard identity; duplicates and
   out-of-assignment attempts/reports; and atomic-write failure leaving no partial manifest/progress.
   Keep these in a compact new `tests/test_audit_worker_snapshot.py` if that avoids further enlarging
   the existing giant worklist test module.
5. Capture red and green evidence under `/tmp/decky-plugins-extended/`, run the complete quality gate,
   keep `security-verdicts.json` unchanged, commit only these primitives/tests, leave the tree clean,
   recreate the marker, and stop after Task 3A.

STATUS: CHANGES_REQUESTED
