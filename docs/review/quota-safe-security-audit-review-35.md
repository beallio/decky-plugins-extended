# Review — quota-safe-security-audit (round 35)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

The stop boundary recorded in round 34 is lifted.  The user has authorized the
remaining plan scope, and this note directs the implementer to drive Tasks 6
through 9 to completion.

Task 5 (`Prove aggregate coverage against the worklist`) was implemented
directly in the orchestrator's own session, not by the implementer, at:

- `dad839f` — `feat(audit): prove aggregate coverage against the prepared worklist`
- `d3b0473` — `test(audit): cover identity-incomplete reports and the real aggregate CLI`

Because the orchestrator authored that code, it has **not** received an
independent review.  Re-verifying it is the first required item below; do not
treat it as accepted work.  Everything before it — Tasks 1 through 4 — remains
accepted as recorded in rounds 1 through 34.

## Gate status

Measured at `d3b0473` before this note was written:

- `scripts/orchestration/run-quality-gates` passed: actionlint verified, all
  three actionlint mutation negative controls rejected as expected
  (invalid YAML, invalid expression, invalid job dependency), Ruff check clean,
  Ruff format clean across 116 files, and Pytest reporting
  `953 passed, 63 subtests passed`.
- `scripts/orchestration/check-review-notes-not-deleted` reported no deleted
  review notes.
- `git diff --check` passed and the worktree was clean.
- `security-verdicts.json` retained SHA-256
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`,
  unchanged from `git merge-base dev HEAD`.
- Task 5 red phase is preserved at
  `/tmp/decky-plugins-extended/quota-safe-security-audit-task5-red.log`
  (16 failing aggregation-coverage tests against the unimplemented CLI, 55
  pre-existing tests still passing); the green rerun is
  `/tmp/decky-plugins-extended/quota-safe-security-audit-task5-green.log`.
- A Task 5 mutation that bypassed `_validate_expected_shard_manifest()` was
  detected by the fingerprint and source-revision tests, saved to
  `/tmp/decky-plugins-extended/quota-safe-security-audit-task5-mutation.patch`,
  reversed with `git apply -R`, and left `git diff --exit-code` clean.

These gates cover the tree as it stands; they are not a substitute for the
independent Task 5 review requested below.

## Required changes

### 1. Independently verify Task 5 before building on it

Review `dad839f` and `d3b0473` against Task 5 of the plan as if another author
wrote them, because another author did.  Confirm at minimum that:

- `validate_aggregate_worklist_coverage()` runs before any aggregate report,
  verdict delta, or verdict-store write, so a coverage failure publishes
  nothing;
- unique shard indices, expected shard count, one common fingerprint and source
  revision, and exact per-index assignments recomputed from the worklist are all
  enforced;
- correspondence holds in every direction, including the byte binding of each
  supplied report and delta to its manifest's `artifacts` entry;
- the union of identity-complete report identities — release-local incomplete
  reports included — must equal the worklist identity set exactly;
- a valid empty worklist still requires fourteen empty, fingerprint-matching
  manifest/report/delta triples;
- deterministic aggregate ordering, classification precedence, PR enforcement
  after safe publication, and scheduled atomic verdict publication are
  unchanged.

Report any defect you find as an implementation change in this round rather
than deferring it.  If you conclude the work is correct, say so explicitly with
your evidence; do not stay silent.

### 2. Implement Tasks 6 through 9 in plan order

Work the remaining scope exactly as the plan specifies:

- **Task 6** — a shared monotonic API budget governing every producer REST
  request, pagination step, retry, and rate-limit wait in `audit_plugins.py` and
  `plugin_release_utils.py`.  Today the only rate-limit touchpoint sleeps to
  `X-RateLimit-Reset` with no deadline awareness; the eight-minute internal
  budget inside a ten-minute job must clip connect/read attempts and
  retry/backoff sleeps, and must raise a clear bounded run-global error when a
  required wait does not fit.
- **Task 7** — wire one `prepare-audit-worklist` producer into both workflows in
  lockstep, converting workers to `--worklist` and aggregation to exact-coverage
  mode, and update the `scripts/orchestration-hooks/quality-gates` actionlint
  mutation anchor without weakening the negative control.
- **Task 8** — add executable `scripts/install-security-scanners` and
  `tests/test_scanner_bootstrap.py`; neither exists yet.
- **Task 9** — update `README.md` and `docs/audit-gating-overview.md` without
  rewriting the historical capacity JSON.

### 3. Close the Task 5 / Task 7 coupling

Task 5 deliberately made `--expected-worklist` and `--aggregate-shard-manifests`
a required-together *optional* group so the not-yet-rewired workflows kept
working between the two tasks.  That leaves exact-coverage enforcement opt-in at
the CLI today.

Task 7 must close it: aggregation in both workflows must always pass the
prepared worklist and all fourteen shard manifests, and the workflow contract
tests must fail if either argument is dropped from either workflow.  A rewired
workflow that still aggregates without proving coverage does not satisfy the
plan.

### 4. Follow the plan's Verification section for the full scope

Record a real red phase for each task's new behavior before implementing it,
including the new `tests/test_scanner_bootstrap.py` module.  Run every failure
control the Verification section lists, then the valid controls, then the
mutation test, then the complete repository gate.  Report actual exit statuses
and test/subtest tallies; a missing fixture or command is a failure, not an
implicit pass.

The Deferred verification items stay deferred.  Do not claim local tests prove
hosted GitHub quota or package-mirror availability.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note.  Do not
modify `security-verdicts.json`.  Do not start hosted workflows.

STATUS: CHANGES_REQUESTED
