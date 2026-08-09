# Review — close-audit-coverage-and-verdict-integrity-gaps (round 11)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 8 is accepted. The behavior review inventory is resolved, but the plan's verification
contract is incomplete. This round owns only the all-caller bounded-download boundary matrix.

## Gate status

- Reviewed commit: `19683299175a239f0a5f7150e89456fa4b09129e`
- Round marker: valid and stamped with the reviewed commit
- Focused workflow tests: `69 passed`
- Full quality gate: `576 passed, 61 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic verification slice 1 — exercise every bounded-download caller at its limits

Existing tests prove the shared bounded helper and some caller delegation, but they do not execute
the complete `limit - 1`, exact `limit`, and `limit + 1` contract through every required production
caller: release auditing, source archive materialization, generator hashing, upstream
reconciliation, and update detection.

Required verification:

1. Add a hermetic parameterized matrix that executes each of the five real caller paths with a
   small non-default effective policy limit. Do not replace/mock the bounded helper itself; fake
   only the HTTP/session response and unrelated downstream work.
2. For every caller, prove `limit - 1` and exact `limit` succeed and yield the expected SHA/content,
   while `limit + 1` fails with the caller-appropriate release-local or run-global outcome.
3. Cover oversized `Content-Length`, absent length, understated length followed by streamed
   overflow, malformed/negative length, and a chunk that crosses the limit.
4. Assert failures remove partial files, skip extraction/scanners, write no cache entry, preserve
   prior durable verdicts, and never produce a safe generator/update result. Exact-limit controls
   must remain green.
5. Prove release ZIP paths use the 64 MiB policy field and source archives use the 256 MiB field by
   overriding both with distinct small values. No caller may fall back to built-in defaults.
6. Record the exact pytest node IDs and pass/subtest totals in a durable verification artifact under
   `docs/agent_conversations/`, referencing the reviewed commit and commands. This artifact records
   evidence only; do not include secrets, tokens, raw plugin contents, or generated reports.
7. Run the focused matrix and the full orchestration quality gate. Commit only this verification
   slice and evidence, leave the tree clean, and mark the round finished.

Do not begin mutation or live-capacity verification in this round.

STATUS: CHANGES_REQUESTED
