# Plan: Allocate Scanner Bootstrap Budget Across Phases (scanner-budget-allocation)

## Context

The scanner bootstrap gives up with two thirds of its budget unspent. Each
phase is capped by a small fixed timeout while the 600-second bootstrap budget
that already bounds the whole step sits mostly unused, so a slow package mirror
fails the step early instead of consuming time that was already allocated.

Run `32275727649` (`workflow_dispatch` on `main` at `4b18a95`, 2026-08-19) failed
ten of fourteen shards. Every one failed the same way: `install base packages`
hit its 90-second budget on both attempts and the step exited 124 at roughly 190
seconds, leaving about 400 seconds of the bootstrap budget unused.

Measured first-attempt durations for `install base packages` in that run:

```text
shard 11   34s   ok
shard  4   74s   ok
shards 0,1,2,3,5,6,7,8,9,10,12,13   >90s (censored at the phase budget)
```

The same phase on the same runner image ten hours earlier, in run
`32222340066`: 17s, 48s, 10s, 47s. The work did not change between the two runs;
the mirrors got slower. A fixed per-phase budget tuned to a fast sample is
fragile against that variance, and 90 seconds sits inside the real distribution
rather than above it.

The retry machinery added by `scanner-bootstrap-retry-safety` is working and
must not be disturbed. Three shards in the same run recovered exactly as
designed:

```text
shard 0  install base packages 95s/124 -> retry 83s/0 -> success
shard 1  install base packages 95s/124 -> retry 47s/0 -> success
shard 4  install Trivy         95s/124 -> retry 52s/0 -> success
```

Every dpkg-lock wait reported `status=0`, and no retry ever contended with a
held lock, so process-group reaping and the lock guard are both behaving.

Aggregation again failed closed correctly on an incomplete set: it downloaded
the worklist and the surviving shard artifacts, refused to aggregate, and
skipped verdict merge, snapshot, publish, and enforcement. The verdict store is
untouched. Aggregation has still never published on fourteen triples.

This plan changes how the existing 600-second budget is distributed, and reduces
the amount of mirror work the bootstrap does. It does not raise the budget, and
it does not raise the calling workflow's unchanged twelve-minute step cap.
External package availability still cannot be guaranteed; the goal is to stop
failing while budget remains, not to promise success.

Expected implementation scope is `scripts/install-security-scanners`,
`tests/test_scanner_bootstrap.py`, and current documentation. Changing the
workflows, the twelve-minute step cap, the 600-second bootstrap budget, the
worklist producer, the shard data plane, aggregation, or `security-verdicts.json`
is outside this plan.

**Slug used throughout this plan:** `scanner-budget-allocation`

---

## Orchestration Contract

**Slug:** `scanner-budget-allocation`

**Plan file:**

```text
docs/plans/2026-08-19_scanner-budget-allocation.md
```

**Implementation branch:**

```text
feat/scanner-budget-allocation
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-budget-allocation_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-budget-allocation_finalized
```

**Review notes:**

```text
docs/review/scanner-budget-allocation-review-*.md
```

Each review note ends with exactly one status trailer:

```text
STATUS: CHANGES_REQUESTED
```

or:

```text
STATUS: APPROVED
```

---

## Required Agent Protocol

1. Use the **implementer** skill.
2. Work from the repository root.
3. Branch from `dev`.
4. Commit this plan as the first commit on the implementation branch.
5. Follow TDD where behavior changes are testable.
6. Run quality gates before marking any round complete.
7. Do not write your own review.
8. Do not create files under `docs/review/`.
9. Do not delete files under `docs/review/`.
10. Review notes are durable audit records and must be committed.
11. Resolving a review note means:
    - implement the requested changes;
    - run quality gates;
    - commit the code/docs changes;
    - commit the review note itself if it is not already committed;
    - recreate the round-complete marker.
12. After finalization, stop polling and exit cleanly.

---

## Scope discipline

- Implement only the units the plan lists. Do not modify files outside the plan's scope.
- Do not change runtime behavior beyond what the plan specifies. A `refactor` or
  `cleanup` commit must preserve observable behavior.
- Never edit a test's expected value to make a behavior change pass. If a test
  legitimately must change, that change must be required by the plan or a review
  note, and you must record the rationale in the session log.
- If you spot an unrelated improvement, do not make it here — note it in the
  session log for a separate plan.

---

## Setup

Start from `dev`:

```bash
git checkout dev
git pull --ff-only origin dev
git checkout -b feat/scanner-budget-allocation
```

Commit this plan first:

```bash
git add docs/plans/2026-08-19_scanner-budget-allocation.md
git commit -m "docs(plan): add scanner-budget-allocation implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add failing contracts before changing allocation

- Add a test proving a network phase may exceed its nominal budget when the
  bootstrap budget still has room: with a large remaining budget, a phase whose
  work takes longer than today's fixed timeout must succeed rather than time
  out.
- Add a test proving the reserve is honored: a phase must not consume budget
  that later mandatory phases need. Drive the bootstrap so an early phase runs
  long, and require the later phases to still receive their minimum budgets.
- Add a test proving budget exhaustion is distinguishable from a phase timeout.
  A phase that cannot start because the remaining budget is below its minimum
  must fail closed with a diagnostic naming budget exhaustion, not a bare `124`
  that reads as a mirror stall.
- Add a test proving the reserve table is internally consistent: the sum of the
  declared minimum budgets and fixed overheads for a full cold path must not
  exceed `BOOTSTRAP_TIMEOUT_SECONDS`.
- Add tests for the Task 3 work reduction: already-present packages are not
  reinstalled, and the post-repository-configuration index refresh fetches only
  the Trivy source list.

Record node IDs and failing assertions before implementing, and confirm the
failures are the missing behavior rather than fixture errors.

### Task 2 — Allocate each phase from the remaining bootstrap budget

Replace the fixed per-phase cap with an allocation that draws on what is
actually left.

- Give each phase a declared minimum budget and a declared reserve: the time
  that must remain after it for every phase that still has to run. A phase's
  timeout becomes the remaining bootstrap budget minus its reserve and minus the
  existing teardown margin, clamped to at least its minimum and at most a stated
  maximum.
- Derive each phase's reserve from the declared minimums of the phases after it
  rather than hand-maintaining a second set of magic numbers. A test must fail
  if the derived reserves and the bootstrap budget become inconsistent.
- The APT phases are the ones that need headroom. Their maximum must be large
  enough to absorb the observed slow tail — the 95-second censored observations
  in run `32275727649` are a lower bound on what a slow mirror needs, not an
  estimate of it — while still leaving every later phase its minimum.
- Retries continue to draw from the same budget. A retry that cannot receive at
  least its phase minimum must not be attempted; report budget exhaustion and
  fail closed rather than starting an attempt that is certain to be cut short.
- Preserve everything the previous plan established: `NETWORK_ATTEMPTS`,
  retry only for idempotent APT and key-fetch work, dpkg-lock waiting with its
  fail-closed `fuser` check, process-group reaping on timeout with the
  proportional supervisor margin, named UTC phase logging, and fail-closed exit
  on an exhausted phase.
- Keep `BOOTSTRAP_TIMEOUT_SECONDS` at 600 and keep the workflow step cap at
  twelve minutes. This task redistributes budget; it does not add any.

### Task 3 — Reduce the mirror work the bootstrap performs

Less exposure to a slow mirror is worth more than a longer wait for it.

- Install only the base packages that are actually missing. Query the local
  package state first and skip the install entirely when nothing is needed. The
  runner image already carries most of these; `clamav` is normally the only
  addition. Skipping must be observable as its own named phase outcome so the
  log still shows what was decided.
- Scope the index refresh that follows Trivy repository configuration to the
  Trivy source list alone, rather than refreshing every configured source a
  second time. Use APT's own directory options to restrict it, and keep the
  resulting index usable for the subsequent `install Trivy`.
- Do not weaken any correctness property to save time: the Trivy signing-key
  fingerprint verification, the exact Semgrep `1.132.0` check, the ClamAV
  database check with its `fuser`-backed lock guard, and every fail-closed exit
  stay exactly as they are.
- If a reduction cannot be made safely, leave it out and say so in the commit
  message rather than implementing a partial version.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` where they describe the
scanner bootstrap's bounded phases and budget, so the description matches
budget-derived phase allocation and the reduced mirror work.

State plainly that this redistributes a fixed budget and reduces exposure, and
that a sufficiently slow or unavailable mirror still fails the shard closed and
blocks publication. Do not claim the bootstrap is now reliable.

Do not rewrite historical capacity evidence or prior review notes.

---

## Quality Gates

Run before marking any round complete:

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git status --short
```

The round is not complete unless:

1. all requested implementation work is done;
2. all relevant tests pass;
3. build/typecheck gates pass;
4. review notes have not been deleted;
5. the working tree is clean;
6. all code/docs changes are committed.

---

## Verification

Every check must report its real exit status and tallies. A missing fixture or
command is a failure, not an implicit pass.

### 1. Record the red phase

After adding the Task 1 tests and before changing allocation:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_scanner_bootstrap.py \
  2>&1 | tee /tmp/decky-plugins-extended/scanner-budget-allocation-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

Record the specific expected failures. The long-phase case must fail because the
phase was cut short at its fixed budget, not because of a fixture error.

### 2. Prove the allocation arithmetic directly

`bash -n scripts/install-security-scanners` must pass.

Then demonstrate the allocator over a table of remaining-budget values, showing
for each phase the timeout it would receive, and record the output under
`/tmp/decky-plugins-extended/scanner-budget-allocation-table.log`. The table must
show that with a full budget an APT phase receives materially more than today's
90 seconds, that every later phase still receives at least its minimum, and that
the totals never exceed `BOOTSTRAP_TIMEOUT_SECONDS`.

### 3. Exercise the failure controls, then the valid controls

Prove each fails closed with its specific named-phase diagnostic:

- a phase that exceeds even its budget-derived maximum still reports `124` and
  names the phase;
- a phase that cannot start because the remaining budget is below its minimum
  fails with a budget-exhaustion diagnostic distinct from `124`;
- an early phase that runs long does not starve a later mandatory phase below
  its minimum;
- the dpkg-lock guard, missing-`fuser` fail-closed path, orphan reaping,
  wrong Semgrep version, absent ClamAV database, and no-retry-for-non-idempotent
  phases all still behave exactly as they do today.

Then the valid controls: the full happy path succeeds; a phase that times out
once and succeeds on retry still completes the bootstrap; a run where all base
packages are already installed skips the install and records that decision; and
the Trivy index refresh fetches only the Trivy source list.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that
reintroduces a fixed per-phase cap in place of the budget-derived allocation,
and require the long-phase test to fail because of it. Save the diff to
`/tmp/decky-plugins-extended/scanner-budget-allocation-mutation.patch`, reverse
it with `git apply -R`, rerun to exit 0, and verify `git diff --exit-code`. Do
not restore with a destructive checkout or reset.

### 5. Run the complete repository gate

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git diff --check
base_commit=$(git merge-base dev HEAD)
git diff --exit-code "$base_commit..HEAD" -- security-verdicts.json
worktree_status=$(git status --porcelain)
if [[ -n "$worktree_status" ]]; then
  printf '%s\n' "$worktree_status" >&2
  exit 1
fi
```

Require Ruff check, Ruff format, all pytest tests and subtests, verified
actionlint, and all actionlint negative controls to pass. Record actual
test/subtest tallies. Confirm the worktree is clean and `security-verdicts.json`
has not changed.

Do not invoke real APT, ClamAV refresh, Trivy installation, or Semgrep
installation locally. The fake-tool harness is the only permitted local
execution of the installer.

### Deferred verification

Local tests can prove allocation arithmetic, reserve behavior, and the reduced
command set. They cannot prove mirror throughput. Defer until the user
authorizes a run on the default branch:

1. a full-corpus run in which all fourteen shards complete scanner setup inside
   the unchanged twelve-minute cap;
2. at least one observed phase that runs longer than the old 90-second cap and
   still succeeds, visible by name and duration in the job log;
3. aggregation publishing on fourteen triples — this has never happened. Run
   `32222340066` reached aggregation with thirteen and run `32275727649` with
   four, and both correctly refused. The verdict merge, snapshot, and publish
   path remains unexercised on real evidence.

Mirror behavior varies by hours: the same phase measured 10–48 seconds in run
`32222340066` and exceeded 90 seconds on twelve of fourteen shards in run
`32275727649`. A single green run is therefore not proof that the budget is
sufficient, and should not be reported as such.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-budget-allocation
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-budget-allocation_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-budget-allocation`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-budget-allocation-review-*.md
```

When a review note exists or a new review note appears:

1. Read the full review note.
2. If the note ends with:

   ```text
   STATUS: CHANGES_REQUESTED
   ```

   then resume work.

3. Clear the round-complete marker:

   ```bash
   scripts/orchestration/clear-finished scanner-budget-allocation
   ```

4. Address every requested change.
5. Run quality gates:

   ```bash
   scripts/orchestration/run-quality-gates
   scripts/orchestration/check-review-notes-not-deleted
   ```

6. Commit code/docs fixes.
7. Commit the review-note file itself if it is not already committed:

   ```bash
   git add docs/review/scanner-budget-allocation-review-*.md
   git commit -m "docs(review): record scanner-budget-allocation review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-budget-allocation
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-budget-allocation` after the next review note is created.

---

## Approval Handling

If the latest review note ends with:

```text
STATUS: APPROVED
```

then:

1. Confirm every previous review item has been addressed.
2. Confirm all review notes are committed:

   ```bash
   scripts/orchestration/check-review-notes-committed scanner-budget-allocation
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-budget-allocation
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-budget-allocation_finalized
   ```

6. Stop polling and exit cleanly.

---

## Review Rules

Do not write your own review.

Do not create files under:

```text
docs/review/
```

Do not delete files under:

```text
docs/review/
```

Only the orchestrator writes review notes. Your job is to read them, resolve them, commit them as audit records, and continue the loop.

---

## Finalization Rules

Only finalize after a review note with:

```text
STATUS: APPROVED
```

Finalization is performed with:

```bash
scripts/orchestration/finalize scanner-budget-allocation
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-budget-allocation_finished
/tmp/decky-plugins-extended/scanner-budget-allocation_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
