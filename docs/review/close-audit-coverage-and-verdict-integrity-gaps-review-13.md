# Review — close-audit-coverage-and-verdict-integrity-gaps (round 13)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Production-mutation verification is accepted. This is the final planned verification slice before
the whole-plan review. It owns only isolated live-corpus capacity and compatibility evidence.

## Gate status

- Reviewed commit: `513a1f5ad1636d5428c3c727fcc6796cd0988182`
- Round marker: valid and stamped with the reviewed commit
- Production mutations: all 11 failed for intended assertions; `11` clean controls passed
- Full quality gate: `616 passed, 61 subtests passed`; actionlint/Ruff/format green
- Feature and mutation worktrees: clean before this orchestrator-authored review note

## Required changes

### Atomic verification slice 3 — record live cold/warm corpus capacity

Run the plan's complete configured-corpus capacity gate without mutating tracked verdicts, caches,
catalogs, or reports in the feature worktree.

Required verification:

1. Use a temporary worktree/staging root under `/tmp` at the reviewed commit. Redirect report,
   progress, cache, verdict, shard, aggregation, and scanner state there. Snapshot the feature
   worktree and tracked `security-verdicts.json` checksum before and after; they must remain clean
   and identical.
2. Instrument and record repository count, eligible-release count, pagination pages, wall-clock
   time, authenticated GitHub API requests, release/source bytes and download counts, scanner
   subprocess counts, report count, verdict count, and four-shard balance.
3. Run the full corpus cold and unsharded, then run the same corpus through four deterministic
   shards and aggregate it. Prove the aggregated report/verdict identities equal the unsharded
   result with no duplicates or omissions.
4. Run the four shards warm from the verified cache. Cold completion must be under 40 minutes; warm
   completion under 10 minutes; each run must consume fewer than 4,000 authenticated GitHub API
   requests. Unchanged digest-backed releases make zero artifact downloads. Digestless releases may
   perform one bounded validation stream; unchanged releases perform zero source downloads,
   extractions, or scanner subprocesses after identity validation.
5. Inventory every eligible release ZIP and source archive. Assert release ZIPs fit 67,108,864
   bytes and source archives fit 268,435,456 bytes. If a legitimate current item or runtime/API
   budget fails, do not raise limits or weaken the gate: record the exact blocker and stop the round
   without claiming success.
6. Commit one durable, redacted JSON evidence artifact under `docs/agent_conversations/` with the
   reviewed commit, commands, environment/tool versions, all metrics/budgets, unsharded-vs-sharded
   equality result, exact output/checksum paths, and deferred hosted-runner variance. Do not include
   credentials, raw plugin/source contents, caches, reports, or signed download URLs.
7. Run the full orchestration quality gate after evidence is recorded. Commit only the durable
   evidence and any narrowly necessary instrumentation tests/tooling, leave the feature tree clean,
   and mark the round finished.

Do not change production policy limits, scanner classifications, workflow timeouts, or audit
behavior in this round.

STATUS: CHANGES_REQUESTED
