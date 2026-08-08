# Review — close-audit-coverage-and-verdict-integrity-gaps (round 12)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Bounded-download verification slice 1 is accepted. The plan's mutation and live-capacity evidence
remain outstanding. This round owns only production-mutation verification.

## Gate status

- Reviewed commit: `d17b6856c7e3c17e595fcd8c65b9fa3d8f230215`
- Round marker: valid and stamped with the reviewed commit
- Bounded caller matrix: `40 passed`; evidence node IDs match collection
- Full quality gate: `616 passed, 61 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic verification slice 2 — prove each production branch with mutation

Use an isolated temporary worktree under `/tmp`; do not mutate the feature branch in place. Starting
from the reviewed commit, break and restore these production behaviors one at a time:

1. restore newest-release-only selection;
2. remove draft filtering from shared eligibility;
3. force two shards to overlap;
4. loosen embedded resume identity validation;
5. suppress successful sibling publication after a release-local error;
6. restore URL-only catalog hash reuse when no digest exists;
7. remove the current-hash verdict comparison;
8. move scanner-error precedence ahead of structural `BLOCK`;
9. restore implicit legacy verdict fallback;
10. bypass streamed byte-limit enforcement; and
11. remove the workflow full-audit selection branch.

Required evidence:

1. For each mutation, apply a minimal production-only diff, run the exact focused pytest node IDs
   that should detect it, and require nonzero pytest status plus the expected assertion/failure
   text. A syntax error, import error, missing command, or unrelated failure does not count.
2. Restore the reviewed production file after every mutation and prove its checksum matches the
   baseline before applying the next mutation. Finish by proving the entire temporary worktree is
   clean.
3. If a mutation does not make the intended regression fail, strengthen the focused test on the
   feature branch, then rerun the clean control and mutation. Do not weaken production behavior or
   expected values to manufacture failure.
4. Commit a durable JSON evidence artifact under `docs/agent_conversations/` containing reviewed
   commit, temporary-worktree path pattern, per-mutation production file/function, diff checksum,
   exact node IDs, exit status, expected failure excerpt, restoration checksum, and final clean
   status. Exclude credentials, raw plugin contents, caches, and generated audit reports.
5. Run all named regression nodes clean after mutation evidence, then run the full orchestration
   quality gate. Record exact totals, commit only any necessary test strengthening plus the evidence
   artifact, leave the feature tree clean, and mark the round finished.

Do not run the live cold/warm corpus capacity verification in this round.

STATUS: CHANGES_REQUESTED
