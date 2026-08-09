# Review — close-audit-coverage-and-verdict-integrity-gaps (round 03)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 2 needs one correction before it is accepted. Sibling continuation and exit 4 are
implemented, but the worklist boundary catches generic exceptions too broadly and can publish a
run-global failure as release-local state.

## Gate status

- Reviewed commit: `552626d75006363598eb1c4a650478624e7419c0`
- Round marker: valid and stamped with the reviewed commit
- Focused worklist/verdict tests: `55 passed`
- Full quality gate: `537 passed, 35 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Correct atomic slice 2 — narrow the release-local exception boundary

The worklist loop currently catches `OSError`, `EOFError`, `BadZipFile`, and `LargeZipFile` around
the entire `audit_release()` call. A generic `OSError` from progress/cache/context/output plumbing
can therefore be converted into publishable exit 4 even though it is run-global. The synthesized
fallback report also omits `resolved_tag_commit_sha` and `audit_context_hash`, so it is not the
identity-complete release-local result required by review note 02.

Required correction:

1. Remove the broad worklist-level conversion of generic `OSError`/archive exceptions. Catch
   expected download/archive-open/read/inspection failures only at the operations that establish
   they are release-local, or use a dedicated typed release-local exception raised exclusively by
   those operations.
2. Keep an unexpected generic `OSError` escaping `audit_release()` as run-global exit 1 with no
   publishable delta/checkpoint mutation.
3. Ensure every scoped release-local failure report contains all identity known at the failure
   point, including `resolved_tag_commit_sha` and `audit_context_hash`, in addition to repository,
   tag, release/asset identity, URL, and current hash.
4. Replace the test that monkeypatches all of `audit_release()` to raise generic `OSError` with a
   failure injected through the real scoped archive inspection/read path. Assert the later sibling
   still completes, the prior verdict is unchanged, and the aggregate result is exit 4.
5. Add the inverse regression: a generic `OSError` outside the scoped archive path remains
   run-global, returns exit 1, and publishes no safe outputs.
6. Run the focused tests and the full orchestration gate, commit only this correction, leave the
   tree clean, and mark the round finished.

Do not begin another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
