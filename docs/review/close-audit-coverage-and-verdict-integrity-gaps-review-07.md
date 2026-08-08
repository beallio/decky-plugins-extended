# Review — close-audit-coverage-and-verdict-integrity-gaps (round 07)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 4 is accepted after its repository-exactness correction. The whole plan still
requires changes. This round owns only unresolved upstream release identity in update detection.

## Gate status

- Reviewed commit: `5f79f29aa62a3fb1b00762294e5cfdb75cdce7fe`
- Round marker: valid and stamped with the reviewed commit
- Focused checkpoint/worklist tests: `38 passed`
- Full quality gate: `559 passed, 54 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 5 — fail closed when upstream current identity cannot be resolved

`check_for_updates.py` can fail to match an upstream catalog version to exactly one current GitHub
release/asset, then fall back to the upstream catalog version and its already-published hash. That
hash is not proof of current bytes and can make a changed asset appear unchanged.

Required implementation:

1. Remove the fallback that treats the existing upstream catalog hash as current artifact
   identity when GitHub release/asset resolution returns no unique match.
2. When a current upstream artifact cannot be resolved uniquely, return/raise an explicit
   current-artifact identity failure. The update-check command must exit nonzero with repository,
   normalized version, and ambiguity/missing-match reason; it must never report "no update" or
   silently request no deployment from unproven identity.
3. Preserve the successful path: a uniquely resolved current asset uses a valid GitHub digest or
   bounded streamed SHA-256 and compares normalized version plus current hash.
4. Add regressions for zero matches, multiple matches, same normalized version with changed current
   asset identity, and stale upstream URL/hash. Assert every unresolved case fails explicitly and
   never calls the catalog-hash fallback; add a unique-match negative control.
5. Keep generator/catalog behavior outside this slice unchanged unless a shared typed identity
   error is required; do not broaden the round.
6. Run focused update-detection/catalog-identity tests and the full orchestration quality gate.
   Record exact totals, commit only this slice, leave the tree clean, and mark the round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
