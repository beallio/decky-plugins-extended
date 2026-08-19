# Review — quota-safe-security-audit (round 26)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

The round-25 production correction is safe and root's direct boundary reproduction is clean, but
the committed regression does not exercise the partial-token leak it claims to fence. Its token
starts wholly after the old truncation boundary, so a length-corrected but still truncate-before-
redact implementation would pass. Make the test exercise the actual boundary; no production change
or Task 4B3 work is authorized in this round.

## Gate status

- Commit reviewed: `6383d946aef954941b0a5dca3563c383b0353d43`; tree clean, marker
  valid, implementer session absent, `git diff --check` clean, and `security-verdicts.json`
  unchanged at `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Implementer round-25 red/green/quality logs are genuine; full gate: `878 passed, 63 subtests
  passed`, with Ruff and actionlint controls clean. Root focused suite: `305 passed, 45 subtests
  passed`; log: `/tmp/decky-plugins-extended/root-review-task4b2-round25-focused.log`.
- `_redacted_exception_detail()` now redacts the full exception before exact-length truncation.
  Root's direct old-case reproduction returns 256 characters with no complete secret, `ghp_`
  prefix, or payload fragment.
- The new regression's literal prefix is 65 characters and its filler is 250 characters, placing
  `ghp_` at zero-based index 315. The old 256-character truncation never reaches the token. The red
  log therefore proves only the prior 257-character length error, not the partial-secret leak.

## Required changes

1. Change the test fixture so the complete recognized token begins before and ends after the old
   character-256 boundary (for example, begin `ghp_` at index 248), while suffix content keeps the
   input oversized after full-string redaction. Assert the fixture's token start/end positions in
   the test so future wording edits cannot silently move it away from the boundary.
2. Retain the existing real audit-path assertions: warning evidence and related statuses/findings
   stay `<= EVIDENCE_MAX_LEN`, preserve their context labels, and contain neither the full token nor
   `ghp_`/payload fragments. Demonstrate that the corrected test fails against the pre-round-25
   truncate-before-redact implementation specifically because a partial token leaks, then passes
   against current production.
3. Preserve the genuine targeted failing output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b2-round26-red.log`, focused green at
   `...-round26-green.log`, and complete gate at `...-round26-quality.log`. Change only the focused
   test and review response unless a directly exposed test issue requires otherwise; keep
   `security-verdicts.json` unchanged, leave the tree clean, recreate the completion marker, and
   stop for review.

STATUS: CHANGES_REQUESTED
