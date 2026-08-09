# Review — close-audit-coverage-and-verdict-integrity-gaps (round 10)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 7 is accepted. The whole plan still requires changes. This round owns only the manual
workflow-dispatch base-ref contract for changed mode.

## Gate status

- Reviewed commit: `0302327cc6e3f0251df618031413aba19a4ba2e9`
- Round marker: valid and stamped with the reviewed commit
- Focused Trivy freshness tests: `13 passed, 7 subtests passed`
- Full quality gate: `572 passed, 61 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 8 — give manual changed-mode dispatch a real base ref

The PR audit workflow selects `changed` for a manual `workflow_dispatch`, then constructs
`--base-ref origin/${{ github.base_ref }}`. `github.base_ref` is empty for dispatch events, so the
command receives `origin/`, diff resolution fails, and current fallback audits all repositories
while the summary still claims changed configured repositories.

Required implementation:

1. Compute one explicit base-ref output in the workflow selection step: use the fetched
   `origin/<pull-request-base>` for pull requests and `HEAD~1` for manual dispatch in changed mode.
   Full-corpus mode must not depend on a base ref.
2. Ensure checkout history contains the dispatch base commit; do not rely on a shallow checkout
   where `HEAD~1` is absent.
3. Pass the computed output to every changed-mode shard command and use the actual selected mode
   and base ref in summaries. Never construct `origin/`.
4. Add executable workflow-step tests for pull-request changed mode, dispatch changed mode,
   dispatch all mode, and an unavailable dispatch base. The unavailable-base case must fail
   explicitly rather than silently widening to all repositories.
5. Preserve the current deliberate full-corpus behavior for security-pipeline diffs.
6. Run focused workflow-selection/enforcement tests, pinned `actionlint`, and the full orchestration
   quality gate. Record exact totals, commit only this slice, leave the tree clean, and mark the
   round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
