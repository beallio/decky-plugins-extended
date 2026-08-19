# Review — quota-safe-security-audit (round 25)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B2's two-component detail budgeting is sound, and the missing cache/scanner-call fences are
now present. One P1 security-reporting defect remains: source exception details are still truncated
before redaction, so a credential crossing the truncation boundary becomes an unmatchable partial
token and is emitted in public finding evidence. Correct this narrow boundary flaw; do not begin
Task 4B3.

## Gate status

- Commit reviewed: `aec04d1f380d8d68d4f30bd88decc0d2bbece5d0`; tree clean, marker
  valid, implementer session absent, `git diff --check` clean, and `security-verdicts.json`
  unchanged at `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Implementer preserved genuine round-24 red, focused-green, and complete-quality logs. Its full
  gate reports `878 passed, 63 subtests passed`; Ruff and actionlint controls are clean.
- Root focused audit/cache/verdict/download suite: `305 passed, 45 subtests passed`; log:
  `/tmp/decky-plugins-extended/root-review-task4b2-round24-focused.log`.
- `_combine_scanner_detail()` now budgets and redacts complete artifact/source components so both
  labels survive within its final 256-character value. The missing `_resolve_ref_to_tree_sha`
  cache-hit sentinels and ClamAV/Semgrep call counters are present.
- Both root and Terra independently reproduced the blocker at `_redacted_exception_detail()`:
  `_truncate()` runs before `redact_secrets()` and returns `max_len + 1` characters. A GitHub token
  beginning near character 256 is cut into a partial non-matching token; the public
  `SOURCE_ARTIFACT_PREPARATION_FAILED` finding evidence is 257 characters and retains `ghp_` plus
  token payload. `Finding.__post_init__` cannot recover because it receives only the fragment.
- The new round-24 test makes the artifact detail oversized, but the secret-bearing source exception
  itself is not oversized and does not cross the boundary, so it is a false-green for this defect.
  The complete gate was not rerun independently after the focused review found the P1 blocker.

## Required changes

1. In `_redacted_exception_detail()`, redact the complete exception string before applying an exact,
   ellipsis-inclusive `EVIDENCE_MAX_LEN` bound. Reuse the safe component helper or an equivalent;
   do not use the legacy truncate-before-redact ordering. Preserve existing behavior outside the
   safe ordering/bound correction.
2. Replace or extend the source-failure regression with a genuinely oversized exception whose full
   GitHub token begins before and ends after the old truncation boundary, with additional suffix
   content keeping the input oversized after redaction. Drive it through the real audit source-
   preparation failure path. Assert the preparation warning evidence and every related scanner
   detail/incomplete finding field are `<= EVIDENCE_MAX_LEN`, contain neither the complete secret
   nor `ghp_`/payload fragments, and still retain their source/artifact context labels.
3. Preserve a genuine failing focused run at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b2-round25-red.log`, then focused green
   at `...-round25-green.log` and the complete quality gate at `...-round25-quality.log`, recording
   exact tallies. Keep scope to `audit_plugins.py`, the source-failure test, and the review response;
   keep `security-verdicts.json` unchanged, leave the tree clean, recreate the completion marker,
   and stop for review.

STATUS: CHANGES_REQUESTED
