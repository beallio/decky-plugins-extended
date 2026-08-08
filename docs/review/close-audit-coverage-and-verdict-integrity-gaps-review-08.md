# Review — close-audit-coverage-and-verdict-integrity-gaps (round 08)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 5 is accepted. The whole plan still requires changes. This round owns only the
empty-worklist shard output/aggregation contract.

## Gate status

- Reviewed commit: `8ecd228d5295f5dae71e9dfa0a878e7819ba59c5`
- Round marker: valid and stamped with the reviewed commit
- Focused upstream/update identity tests: `27 passed`
- Full quality gate: `565 passed, 54 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 6 — emit safe empty verdict deltas for zero-work shards

When repository selection is empty, the audit CLI returns after writing JSON/Markdown reports but
before resolving/writing the configured verdict-delta path. Four-shard workflow aggregation expects
one delta from every safe shard, so a legitimate changed-mode selection with zero repositories can
fail aggregation despite exit 0.

Required implementation:

1. Resolve the report, progress, and verdict-delta output paths before the empty-worklist return.
2. For a safe empty worklist, atomically write deterministic empty report outputs and a `{}` verdict
   delta at the configured path, then return exit 0. Do not mutate the tracked verdict store.
3. Preserve fail-closed behavior: a run-global validation/output error must not create an apparently
   safe delta.
4. Add an executable CLI regression proving an empty selection creates JSON/Markdown plus an exact
   `{}` delta. Add a four-shard workflow/aggregator regression where every shard is empty and the
   aggregate succeeds with deterministic empty outputs and no tracked-store change.
5. Include a mixed control where some shards are empty and one has a valid delta; aggregation must
   merge the valid record exactly once without treating empty shards as missing.
6. Run focused worklist/aggregation/workflow tests and the full orchestration quality gate. Record
   exact totals, commit only this slice, leave the tree clean, and mark the round finished.

Do not address another review-inventory item in this round.

STATUS: CHANGES_REQUESTED
