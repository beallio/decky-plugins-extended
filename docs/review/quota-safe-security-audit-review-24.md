# Review — quota-safe-security-audit (round 24)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B2 now has the correct unconditional cache-miss snapshot placement and preserves the
established metadata/scanner semantics, but one production diagnostic-composition bug and two
acceptance-test gaps remain. A long artifact-Trivy detail can erase the source-preparation reason
entirely, so the report says only that Trivy failed without preserving why its source consumer
failed. Keep this slice in Task 4B2; do not begin Task 4B3.

## Gate status

- Commit reviewed: `1178bdb870f2f8358f497a08cf4f10f7340f82a5`; tree clean, marker
  valid, implementer session absent, `git diff --check` clean, and `security-verdicts.json`
  unchanged at `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Root focused audit/cache/verdict/download suite: `304 passed, 45 subtests passed`; log:
  `/tmp/decky-plugins-extended/root-review-task4b2-round23-focused.log`.
- Snapshot preparation is now attempted exactly once after both cache-miss boundaries and before
  ZIP inspection, regardless of scanner enablement or archive safety. The exact prepared object/root
  reaches diff/Trivy, tagged metadata paths remain `@<tag>`, attribution is neutral, disabled and
  required scanner semantics are preserved, and structural `BLOCK` retains precedence.
- Root reproduced the remaining production defect directly: combining a 400-byte artifact detail
  with a source failure returns 257 characters for the 256-character limit and contains no
  `source snapshot preparation failed` context. `_combine_scanner_detail()` appends the source
  component after the artifact component and truncates the aggregate, so the first component can
  crowd the required second component out completely.
- Both digest-backed and digestless cache-hit fences still omit a raising sentinel for
  `_resolve_ref_to_tree_sha`. The source-failure test checks a short secret but neither exact bounds
  nor survival of a non-secret artifact-Trivy detail, and it does not count ClamAV/Semgrep calls.
- Required round-23 red/green/quality logs were not preserved. This review records that process gap;
  do not fabricate those artifacts. The complete gate was not rerun after the focused review found
  a production defect.

## Required changes

1. Replace `_combine_scanner_detail()`'s append-then-truncate behavior with deterministic bounded
   composition that preserves both labeled contexts when both exist: a bounded/redacted artifact
   scanner detail and a bounded/redacted source-snapshot preparation detail. The final public value
   must be at most `EVIDENCE_MAX_LEN` characters, including any ellipsis/separator, and the source
   failure label/reason must not disappear merely because the artifact detail is long. Preserve the
   artifact detail as fully as the fixed two-component budget permits. Apply the same exact bound to
   the one-component diff/source detail.
2. Add a regression with an oversized non-secret artifact-Trivy marker plus an oversized
   secret-bearing source exception. Assert the composed Trivy detail retains both context labels and
   the non-secret artifact marker, contains no secret, and is `<= EVIDENCE_MAX_LEN`. Walk every
   source-failure `ScannerStatus.detail` and relevant warning/incomplete `Finding.evidence`/`message`
   to assert redaction and the fixed bound. Do not rely on the current short-secret assertion.
3. Extend the source-failure helper with ClamAV and Semgrep call counters and assert Trivy, ClamAV,
   and Semgrep each execute exactly once for a safe artifact while their artifact findings survive.
   Assert the original non-secret artifact-Trivy detail survives composition; injected return values
   alone are not proof that the scanner paths ran.
4. Add `_resolve_ref_to_tree_sha` raising sentinels to both the digest-backed and digestless
   cache-hit fences, after the one allowed prepared commit-resolution step. Strengthen the fresh
   miss/`skip_cache=True` control so it proves source materialization/consumer seams are actually
   reached outside a cache hit, while a hit still reaches none of the forbidden seams.
5. Add the new regressions first and preserve their genuine failing output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b2-round24-red.log`. Preserve focused
   green at `...-round24-green.log` and the complete quality gate at `...-round24-quality.log`, with
   exact tallies. Keep scope to `audit_plugins.py`, the focused audit/cache tests, and the review
   response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate the completion
   marker, and stop for review.

STATUS: CHANGES_REQUESTED
