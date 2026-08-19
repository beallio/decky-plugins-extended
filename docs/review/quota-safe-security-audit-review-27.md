# Review — quota-safe-security-audit (round 27)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B2 is accepted. The immutable source snapshot is now acquired exactly once after a real cache
miss, shared by metadata/Trivy/diff, fails with correct required/optional/structural semantics, and
has adversarial cache, identity, bounds, and secret-redaction coverage. Proceed only with Task 4B3:
remove the legacy source acquisition/comparison implementation and transitional Trivy input so the
later worker API cannot accidentally reach either source data plane. Do not begin Task 3B or Tasks
5-9 in this round.

## Gate status

- Accepted through `5577ed3dee069e815cc7aefc76c99fd188e7caec`; tree clean, marker valid,
  implementer session absent, `git diff --check` clean, and `security-verdicts.json` unchanged at
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Root focused Task-4B2 suite: `305 passed, 45 subtests passed`; log:
  `/tmp/decky-plugins-extended/root-review-task4b2-round26-focused.log`.
- Root complete gate: actionlint mutation controls passed, Ruff check/format clean, and `878 passed,
  63 subtests passed`; log:
  `/tmp/decky-plugins-extended/root-review-gate-task4b2-round26.log`.
- The boundary fixture now places `ghp_` at index 248 and its full token through index 287. Root
  confirmed the old ordering emits a 257-character `ghp_aaaa...` fragment while current production
  emits 256 bounded characters without a token prefix or payload. Terra independently accepted the
  corrected fence.
- Requested implementer round-26 logs were absent; root's independent focused/full logs and direct
  before/after reproduction are the acceptance evidence. Record the process gap and do not
  fabricate artifacts.
- Repo-wide callsite inspection shows the remaining legacy production chain is self-contained:
  `run_trivy(source_repo=...)` calls `_fetch_source_tree()`, which calls
  `_download_source_archive()`; legacy `compare_source_and_artifact()` calls
  `_resolve_ref_to_tree_sha()` and `get_repo_file_raw()`. No non-legacy production consumer of
  `get_repo_file_raw()` remains. `_resolve_ref_to_commit_and_tree_sha()` is still the current audit
  entry resolver and must remain until Task 3B injects the prepared worklist commit/error.

## Required changes

1. Delete the transitional `source_repo` parameter, mutual-exclusion branch, and hidden source-fetch
   fallback from `run_trivy()`. Its only source input must be an already prepared `source_root` (or
   `None` for artifact-only behavior). Update callers/tests without changing Trivy's finding/status
   shape or required/optional semantics.
2. Delete the dead legacy source data plane from `audit_plugins.py`:
   `_download_source_archive()`, `_fetch_source_tree()`, `_resolve_ref_to_tree_sha()`, and the legacy
   `compare_source_and_artifact()` implementation. Delete `get_repo_file_raw()` as well because the
   repo-wide production callsite check found no consumer outside that legacy comparison. Remove
   imports/constants used only by these paths, but retain `_resolve_ref_to_commit_and_tree_sha()`
   and the current `audit_release()` call until Task 3B.
3. Migrate legacy behavioral tests to the snapshot adapters where they express unique normalized-
   version, build-stamp, symlink, metadata, matching, or finding-shape contracts. Remove only tests
   made strictly redundant by existing snapshot-equivalence cases; do not reduce behavioral
   coverage merely to delete old names. Replace cache/success sentinel patches for deleted helpers
   with explicit absence assertions plus raising sentinels on the remaining applicable source/API
   seams. Remove transitional `source_repo` tests and retain prepared-root Trivy cases.
4. Add a repository-level regression proving the deleted helper names and `source_repo` parameter
   are absent, the real fresh audit still performs exactly one immutable codeload materialization,
   and metadata/Trivy/diff still receive the same prepared snapshot/root. Patch remaining REST
   source seams (`_gh_get` after the allowed current resolver and raw/API download interfaces) to
   raise where applicable; cache-hit and source-failure contracts must remain green.
5. Write the removal-contract tests first and preserve genuine failing output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b3-round27-red.log`, focused green at
   `...-round27-green.log`, and the complete gate at `...-round27-quality.log`, recording exact
   tallies. Keep scope to `audit_plugins.py`, directly affected audit/cache/bounded-download tests,
   and the review response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate
   the completion marker, and stop for review.

STATUS: CHANGES_REQUESTED
