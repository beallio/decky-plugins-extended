# Review — close-audit-coverage-and-verdict-integrity-gaps (round 06)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 4 needs one exactness correction. All embedded report identity and completion checks
except repository representation are accepted.

## Gate status

- Reviewed commit: `f2b62c713b854b9482615315fedb5a6c14607faf`
- Round marker: valid and stamped with the reviewed commit
- Focused checkpoint/worklist tests: `36 passed`
- Full quality gate: `557 passed, 54 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Correct atomic slice 4 — require exact canonical repository representation

The resume validator canonicalizes the embedded and expected repository values before comparison.
That accepts an embedded noncanonical value such as `https://github.com/OWNER/REPO/` for expected
`https://github.com/owner/repo` and then emits the embedded spelling unchanged. A resumable report
must already contain the exact canonical repository identity recorded by the current work item.

Required correction:

1. Require `report.repository` to equal the expected canonical repository string exactly. Do not
   normalize an embedded mismatch into acceptance.
2. Add case-only and trailing-slash embedded-report mismatch regressions. Assert both entries are
   rejected, the release reruns, and the replacement report uses the expected canonical value.
3. Preserve the exact-match resume negative control.
4. Run focused worklist tests and the full orchestration gate, commit only this correction, leave
   the tree clean, and mark the round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
