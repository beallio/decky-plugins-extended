# Review — quota-safe-security-audit (round 23)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B2 has the correct cache boundary and shared-snapshot direction, but two contract regressions
and several false-green acceptance tests remain. Make snapshot preparation unconditional after a
successful cache miss, restore report compatibility, preserve artifact Trivy diagnostics, and
complete the requested failure/cache fences. Do not begin Task 4B3.

## Gate status

- Commit reviewed: `af8a71dc970bc7bc6ec8b2540fba478319a44e1a`; tree clean, marker
  valid, implementer session absent, and `security-verdicts.json` unchanged.
- Root focused audit/cache/verdict/download suite: `299 passed, 45 subtests passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `872 passed, 63 subtests passed`.
- Cache lookup ordering is correct, digestless hits stream the artifact once, the active success
  path materializes/extracts once at the exact immutable codeload URL, and the prepared root/object
  reaches Trivy/diff without raw/tree/API-tarball consumers.
- Both Terra reviews found that materialization is conditional on enabled scanners and a safe
  extracted artifact, even though tagged source metadata is itself an unconditional consumer on
  every successful cache miss. They also found changed metadata paths, lost artifact-Trivy detail,
  and missing adversarial assertions.
- Required round-22 implementer red/green/quality logs were not preserved; root independent green
  logs exist. Record the process gap and do not fabricate it.

## Required changes

1. After artifact download/digest validation and the SHA-keyed cache-miss decision—but before ZIP
   inspection—attempt exactly one snapshot materialization for every fresh audit. Do not gate it on
   Trivy/diff enablement, ZIP safety, or extraction success; tagged source metadata is always a
   consumer. Cache hits still perform zero source work. Later scanner code must use the prepared
   snapshot only when that scanner is enabled, and disabled scanners must remain skipped.
2. When snapshot root metadata exists, retain `plugin.json@<tag>` and `package.json@<tag>` exactly;
   change only the byte source, not the established finding/report paths. On preparation failure,
   keep the explicit low warning but attribute it to a neutral source-snapshot/metadata source, not
   falsely to source-artifact-diff when that scanner is disabled.
3. Continue artifact-only Trivy when source preparation fails, then mark the enabled Trivy consumer
   failed without discarding its artifact status detail or findings. Compose a bounded detail that
   includes the original artifact status/detail plus the redacted source-preparation failure. Do
   the same bounded/redacted source detail for diff and the source-snapshot warning. Do not expose
   secrets or grow any public detail without a fixed bound.
4. Strengthen both digest-backed and digestless cache-hit tests with raising sentinels on raw
   metadata, `_gh_get`, tree/ref helpers after prepared resolution, legacy source fetch/archive,
   legacy comparison, materialization/extraction, and prepared consumers. Total counters alone are
   not enough. Add a miss/bypass control proving these sentinels are reached only when appropriate.
5. Wrap the real materializer in the uncached-success test, capture its returned
   `SourceSnapshot`, and assert the diff receives that exact object with `is`, while Trivy receives
   its exact root. Assert tagged metadata finding paths remain tag-qualified. Retain one codeload
   request/extraction and lightweight/annotated commit cases.
6. Expand source-preparation-failure tests to prove: both consumers disabled still materializes once,
   uses ZIP metadata fallback, records the source warning, and leaves Trivy/diff skipped; Trivy-only
   required and diff-only required each yield `AUDIT_ERROR`; optional enabled consumers yield
   `PASS_WITH_WARNINGS`; artifact Trivy, ClamAV, and Semgrep findings/call counts survive; the
   original artifact Trivy detail survives; a long secret-bearing exception is redacted and every
   public detail/evidence stays bounded; and source failure plus a structural archive `BLOCK`
   remains `BLOCK` while still recording the preparation failure. Assert identity/completion fields
   for required and optional outcomes.
7. Write the new metadata-only/cache-sentinel/failure tests first and preserve their genuine failing
   output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b2-round23-red.log`. Preserve focused
   green at `...-round23-green.log` and the complete gate at `...-round23-quality.log`, recording
   exact tallies. Keep scope to `audit_plugins.py`, focused audit/cache/verdict/download tests, and
   the review response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate the
   completion marker, and stop for review.

Deferred to Task 4B3: legacy helper removal. Deferred to Task 3B: prepared worklist commit/error
injection and the public worker API-isolation test. Aggregation, workflows, scanner bootstrap, and
documentation remain deferred.

STATUS: CHANGES_REQUESTED
