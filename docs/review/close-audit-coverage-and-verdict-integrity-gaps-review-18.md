# Review — close-audit-coverage-and-verdict-integrity-gaps (round 18)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. Aggregation currently validates shard report and verdict
delta files too shallowly and merges them independently, so incomplete records
or a report/delta splice can be accepted. Fix only aggregate schema and
cross-artifact integrity in this round.

## Gate status

- Reviewed commit: `891702d62bf8e98b2e5d68602343eb5d31da4e50`.
- The round-complete marker is valid and the feature worktree is clean.
- Round 17 reviewed CLEAN: focused update-policy tests passed (`91 passed`) and
  the complete local quality gate passed with `630 passed, 61 subtests passed`.
- Final-review reproductions accepted a canonical repository report missing its
  completed release identity/hash and an incomplete BLOCK verdict delta.
  Reports and deltas are currently aggregated independently, so their
  relationship is not proven.

## Required changes

1. Validate every shard report record and verdict-delta record against the
   existing durable schema/central validators before aggregation. Do not let
   dataclass defaults turn missing required completed-report identities into
   apparently valid records.
2. Require every completed report record to contain the full canonical release
   identity and authoritative content/hash fields required by the durable
   contract. Reject malformed or incomplete BLOCK/WARN/PASS verdict records
   fail closed.
3. Derive the expected merged verdict delta from the validated aggregated
   completed reports through the central verdict construction logic, and
   require exact canonical equality with the separately supplied/merged shard
   deltas. Reject missing, extra, mismatched, or cross-shard-spliced verdict
   entries before publication.
4. Preserve valid intentionally empty shard deltas (`{}`), deterministic merge
   order, duplicate/conflict rejection, and existing exit precedence.
5. Add focused regressions for a completed report missing release
   identity/hash, an incomplete BLOCK delta, missing/extra/mismatched delta
   entries, and a report/delta splice across otherwise valid shard artifacts;
   include clean multi-shard and empty-shard controls.
6. Keep this round scoped to aggregate schema and cross-artifact validation.
   Do not perform source-inventory verification or unrelated refactoring.
7. Run focused aggregation/schema/workflow tests and the complete local quality
   gate, commit the atomic fix, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
