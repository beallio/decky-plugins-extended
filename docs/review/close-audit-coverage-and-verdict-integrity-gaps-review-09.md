# Review — close-audit-coverage-and-verdict-integrity-gaps (round 09)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 6 is accepted. The whole plan still requires changes. This round owns only malformed
Trivy version/database JSON handling in cache freshness identity.

## Gate status

- Reviewed commit: `d946ebcb09d865af1e1bb6c6a830fa6c5ed54283`
- Round marker: valid and stamped with the reviewed commit
- Focused empty-worklist/aggregation tests: `86 passed`
- Full quality gate: `570 passed, 54 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 7 — fail safe on malformed Trivy identity JSON

The Trivy identity probe assumes any valid JSON result is an object and calls `.get()` directly.
Valid non-object JSON such as `[]` raises `AttributeError`, aborting a scheduled shard instead of
marking database freshness unavailable and bypassing unsafe cache reuse.

Required implementation:

1. Validate the parsed Trivy version/database payload is a mapping before reading fields.
2. For non-object, missing, malformed, or type-invalid identity fields, return an unavailable
   database/freshness identity without crashing. Preserve any independently valid executable
   version identity.
3. Ensure scheduled cache policy treats unavailable database freshness as non-reusable/bypass,
   while an exact valid identity still permits a cache hit.
4. Add focused tests for `[]`, a scalar, an object with wrong field types, malformed JSON, and a
   valid object negative control. Assert invalid forms do not raise and cannot authorize a cache
   hit.
5. Run focused cache-invalidation tests and the full orchestration quality gate. Record exact
   totals, commit only this slice, leave the tree clean, and mark the round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
