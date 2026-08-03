# Review — audit-verdicts (round 01)

Branch: `feat/audit-verdicts`
Reviewed against: `docs/plans/2026-08-03_audit-verdicts.md`
Reviewed commit: `0a9d780`

## Verdict

Good round. The API is the right shape, every verification step in the plan has a matching test
in the same order, and the fail-open semantics are correct where it counts.

Verified on the branch:

- **`VerdictResult` carries all three fields** (`audit_plugins.py:206-209`):
  `effective_classification`, `audit_classification`, `blocking_rule_ids`. A bare string could
  not have satisfied `catalog-gate`'s logging requirement.
- **First-seen failure is not laundered into `PASS`.** `classification_for`
  (`audit_plugins.py:2679-2716`) returns `AUDIT_ERROR` for both fields when nothing is known.
  Mutation-verified: changing that return to `VerdictResult("PASS", "AUDIT_ERROR", [])` turns
  `test_first_seen_audit_error_is_not_laundered_into_pass` red.
- **Unknown releases default to `AUDIT_ERROR`, not `PASS`** on the dict-lookup path (2710-2716).
  That is the honest default and still fails open at the gate, since `catalog-gate` only
  excludes on `BLOCK`.
- **Atomic writes are real.** `_write_verdicts_atomic` uses `mkstemp` + `fsync` + `os.replace`
  (2619-2634). Mutation-verified: replacing it with truncate-then-move turns
  `test_atomic_write_failure_preserves_prior_verdict_file` red.

## Gate status

`scripts/orchestration/run-quality-gates` -> pass: ruff clean, 197 passed / 17 subtests. Run by
me on `0a9d780`.

## Required changes

### 1. The never-overwrite-with-AUDIT_ERROR invariant is pinned by nothing

This is the invariant the whole fail-open design rests on, and the plan called it out
explicitly: *"Never overwrite an existing entry with `AUDIT_ERROR`; that is what makes
fail-open-with-last-verdict work."*

It is enforced twice — at the call site (`audit_plugins.py:3441`,
`if report.final_classification != "AUDIT_ERROR":`) and again inside `_record_verdict` (2653).
I removed **both** guards and the entire verdict suite stayed green: 7 passed.

The reason is that every `AUDIT_ERROR` the tests produce comes from `download_zip` raising,
which returns early at 3175 and never reaches the record block at 3440 at all. So the test that
looks like it covers this — `test_audit_error_preserves_good_verdict_and_reports_both_states` —
passes because of an unrelated early return, not because the guard works.

The uncovered path is the one that matters: an audit that *completes* but sets `has_error` from
a failed required scanner, so `classify_findings` returns `AUDIT_ERROR` and execution reaches
3441 with a prior `PASS` already on disk. Add a test that drives that path — seed a `PASS`
verdict, force a required scanner to report `failed`, run `audit_release` to completion, and
assert the stored verdict is still `PASS`. It must go red when either guard is removed.

### 2. Collapse the redundant guard

Given 3441 already guards the call, the check inside `_record_verdict` (2653) is unreachable via
the only production caller. Keep exactly one enforcement point. If `_record_verdict` is meant to
be the safe entry point callers cannot misuse, make it the sole guard and drop the condition at
3441; if the call site is the gate, drop the inner one. As it stands the inner check reads as
protection while being dead code, which is how the next person talks themselves out of testing
it.

### 3. Session log missing

`docs/agent_conversations/` has entries for `release-utils`, `audit-port` and `audit-scanners`,
but nothing for this sub-plan. Record the observed output for verification steps 1-8, including
the mutation results for the test added under finding 1.

STATUS: CHANGES_REQUESTED
