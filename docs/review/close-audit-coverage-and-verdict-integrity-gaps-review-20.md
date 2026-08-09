# Review — close-audit-coverage-and-verdict-integrity-gaps (round 20)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. The only remaining finalization gate is the complete
source-archive size inventory. Run a bounded inventory-only probe and close the
gate only if every freshly enumerated eligible release is covered without an
error or limit violation.

## Gate status

- Reviewed commit: `0d1819f71c3236ebaaa3b64b633b7ca3f3961ac5`.
- The round-complete marker is valid and the feature worktree is clean.
- All remaining code review findings are closed. Round 19 reviewed CLEAN with
  `175` focused tests; the complete local gate passed with `645 passed, 61
  subtests passed`.
- The plan still requires every eligible source archive to fit within the
  existing 256 MiB source-download limit before finalization. The projection
  and blocker evidence correctly mark that inventory as unverified.

## Required changes

1. In an isolated `/tmp` workspace at the reviewed marker, freshly enumerate
   the eligible release corpus through the production enumeration/eligibility
   helpers. Resolve every release tag to its exact source commit and retain a
   deterministic release-to-repository/commit mapping.
2. Deduplicate identical repository/commit pairs for downloading while proving
   that every enumerated eligible release maps to one successfully inventoried
   source archive.
3. Stream each unique commit tarball through the existing
   `bounded_stream_download(kind="source", policy=load_policy())`. Do not use
   metadata-only size guesses. Delete each archive immediately after measuring
   it; do not extract it or invoke scanners, cache generation, verdict
   generation, catalog generation, or report generation. Do not raise any
   timeout or content-size limit.
4. Make the probe checkpoint/resume safely in `/tmp` so an interruption does
   not discard completed measurements. Keep any probe helper transient and
   outside the committed production tree unless a minimal reusable test helper
   is genuinely required.
5. Commit a redacted durable JSON evidence record under
   `docs/agent_conversations/` containing: reviewed commit and policy checksum;
   corpus and inventory hashes; eligible-release and unique-commit counts;
   per-identity measured byte counts or a content-addressed equivalent audit
   trail; total and maximum bytes with its identity; API/download request and
   error counts; limit violations; start/end/elapsed time; and before/after
   feature-worktree plus tracked-verdict checksums. Do not record credentials or
   signed/temporary URLs.
6. If and only if every eligible release is covered with zero errors and zero
   over-limit archives, update the plan, fourteen-shard projection evidence,
   and documentation assertions from source-inventory open/unverified to
   verified, referencing the new evidence. Warm and hosted-runner validation
   must remain explicitly deferred. If any item fails, preserve fail-closed
   blocker evidence and leave the acceptance gate open; do not change limits.
7. Run focused evidence/documentation tests and the complete local quality
   gate, commit the atomic evidence/contract update, and write a new
   round-complete marker. Do not rerun the full audit corpus.

STATUS: CHANGES_REQUESTED
