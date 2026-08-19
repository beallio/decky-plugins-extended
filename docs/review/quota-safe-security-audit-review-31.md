# Review — quota-safe-security-audit (round 31)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

The major Task 3B corrections are accepted: option presence is fail-closed,
prepared source errors bypass scanner/source/artifact work, the real worker
test crosses one codeload download and extraction boundary, and the required
safe-sibling/resume/sharding cases are now substantive. Two narrow safety
contracts remain before Task 3B can be accepted: prepared-error redaction and
identity fallback need explicit tests, and checkpoint promotion must not expose
a mixed output generation when replacement fails after staging succeeds.

Stay on **Task 3B only**. Do not begin Task 5 or edit workflows.

## Gate status

- Reviewed HEAD: `b95512e878ae3e9f5641d43171e82ad38c4a7987`.
- Worktree was clean; the round marker was valid for that HEAD; no implementer
  session remained active.
- Implementer complete gate passed: actionlint `1.7.12` and all three mutation
  controls, Ruff check/format, and `882 passed, 63 subtests passed` in
  `/tmp/decky-plugins-extended/quota-safe-security-audit-round30-quality-gates.log`.
- Terra focused reviews passed `401 passed, 45 subtests passed`, `372 passed,
  38 subtests passed`, and `183 passed`; focused Ruff was clean.
- The round-30 red log genuinely records five pre-fix failures; focused green
  reports `146 passed`.
- `/tmp/decky-plugins-extended/quota-safe-security-audit-round30-plan-focused-green.log`
  is not valid evidence because it names nonexistent
  `tests/test_scanner_bootstrap.py`; do not cite it as green.
- `security-verdicts.json` checksum remained
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

## Required changes

1. Prove prepared-error redaction as well as truncation.
   - `test_prepared_source_error_is_bounded_before_worker_checkpointing` uses
     only repeated `x` bytes, so it cannot fail if secret redaction disappears.
     Put a recognized token-shaped secret across the truncation boundary and
     assert the complete and partial/raw secret are absent, `[REDACTED]` is
     present, and the final detail remains within the exact bound. Preserve
     redaction-before-truncation ordering.
   - Add missing and malformed asset-digest variants at this internal boundary
     and assert `artifact_sha256 == ""` and `identity_status == "UNKNOWN"`.
     Keep the valid-digest `CURRENT` assertion. Immutable worklist validation
     may normalize/reject malformed external values; the direct unit boundary
     should still prove truthful report fallback.

2. Make staged checkpoint promotion exception-safe across every visible
   target, not only manifest creation.
   - `checkpoint_outputs()` stages and validates all files, then promotes
     progress, report JSON/Markdown, delta, and manifest with sequential
     `os.replace()` calls. If a later target creation/replacement fails, earlier
     targets are already the new generation while later targets and the
     manifest can remain the old generation. Custom progress/delta paths can
     also reside on another filesystem and make this failure realistic.
   - Publish through one atomic generation/commit-pointer boundary, or prepare
     recoverable per-target backups and roll back every already-promoted target
     on any promotion failure. Whichever design is used, consumers must see
     either the entire prior publishable generation or the entire new one after
     the function returns; they must never accept a mixed generation. Preserve
     arbitrary supported progress/delta paths, atomic individual files, and
     cleanup of staging/backup material.
   - Add a two-release regression that lets checkpoint one publish, lets
     checkpoint two stage and validate fully, then injects an `os.replace`
     failure in the middle of promotion. Assert run-global exit `1` and prove
     the report, Markdown, progress, delta, and shard manifest all exactly
     match checkpoint one's prior generation. Retain the existing
     manifest-staging-failure case.

3. Record genuine focused red/green evidence for both corrections, replace the
   invalid plan-focused transcript with a valid command if that suite is still
   claimed, and rerun the complete quality gate. Preserve actionlint mutation
   controls, Ruff check/format, all Pytest tests/subtests, a clean worktree, and
   the unchanged verdict checksum.

STATUS: CHANGES_REQUESTED
