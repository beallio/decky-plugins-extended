# Review — close-audit-coverage-and-verdict-integrity-gaps (round 05)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 3 is accepted. The whole plan still requires changes. This round owns only embedded
checkpoint-report identity validation during resume.

## Gate status

- Reviewed commit: `38f5804c82c226ea2f58a67cf99fea095e1688e6`
- Round marker: valid and stamped with the reviewed commit
- Focused allowlist tests: `116 passed, 32 subtests passed`
- Full quality gate: `542 passed, 54 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 4 — validate the embedded report before resume

Resume currently validates top-level progress-entry identity fields, then deserializes and trusts
the embedded `report` without proving that report belongs to the same work item. A corrupted or
spliced manifest can therefore present a valid wrapper, skip the current audit, and publish another
release's report/verdict.

Required implementation:

1. Before treating a progress entry as completed, deserialize its embedded report and require exact
   agreement with both the progress key and expected current work item for canonical repository,
   tag/release key, numeric release ID, asset ID/URL, current artifact SHA-256, resolved source
   commit, and audit-context hash.
2. Validate classification/completion state consistently with resume policy: only an exact,
   completed, publishable report may be reused. A release-local `AUDIT_ERROR` checkpoint may remain
   reportable but must not become a durable completed verdict.
3. On any wrapper/report mismatch, malformed embedded report, missing identity field, or unexpected
   completion state, treat the entry as a cache miss and rerun that release. Do not publish or
   delete unrelated prior verdicts from the rejected entry.
4. Add parameterized regressions that mutate each embedded identity field while leaving the wrapper
   valid. Assert the release reruns, the replacement report matches the current identity, and the
   spliced report is never emitted. Include an exact-match resume negative control proving no audit
   call occurs.
5. Run focused worklist/checkpoint tests and the full orchestration quality gate. Record exact
   totals, commit only this slice, leave the tree clean, and mark the round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
