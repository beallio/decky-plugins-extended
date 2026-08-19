# Plan: Make Scanner Bootstrap Retries Survive Phase Timeouts (scanner-bootstrap-retry-safety)

## Context

The scanner bootstrap's bounded retry cannot succeed after a phase timeout. It
kills the wrapper but not the `apt-get` underneath it, so the retry runs
straight into a dpkg lock still held by the orphan from the previous attempt.

Run `32222340066` (`workflow_dispatch` on `main` at `bd5c611`, 2026-08-19) is the
first run in which the fourteen-shard data plane completed end to end. The
producer finished in 54 seconds, thirteen shards succeeded in 8.9–20.1 minutes
with no rate-limit waits, and aggregation correctly refused to publish on
thirteen artifacts. Shard 13 failed in `Install required security scanners`:

```text
06:12:16  phase=install base packages start=2026-08-19T06:12:16Z
06:13:16  phase=install base packages status=124 failed
06:13:16  phase=install base packages retry=1/2 backoff=4s
06:13:20  phase=install base packages start=2026-08-19T06:13:20Z
06:13:22  E: Could not get lock /var/lib/dpkg/lock-frontend.
          It is held by process 2708 (apt-get)
06:13:22  phase=install base packages end=... status=100
```

`phase_run()` invokes `timeout --foreground "$timeout_seconds" "$@"`, and the
APT phases pass a `bash -o pipefail -c '...'` wrapper that runs `sudo -n
apt-get` inside it. GNU `timeout`'s own documentation states that with
`--foreground`, "children of COMMAND will not be timed out". The flag suppresses
the process group that `timeout` would otherwise create and signal, so on
timeout only the wrapper dies and `apt-get` keeps running and keeps the lock.

Confirmed directly, with a payload that spawns a grandchild outliving the
timeout:

```text
timeout --foreground 2 ./payload  -> grandchild SURVIVED
timeout 2 ./payload               -> grandchild reaped
```

`RETRY_BACKOFF_SECONDS=4` then guarantees the retry lands while the orphan still
holds the lock. Every phase that reaches its timeout therefore burns its whole
retry budget on an attempt that cannot succeed, and the shard fails. The
60-second `BASE_APT_TIMEOUT_SECONDS` is what exposed it — installing `clamav`
and its dependencies fits on most runners and did not fit on this one — but
raising the budget alone would leave a retry path that is still structurally
incapable of recovering.

`tests/test_scanner_bootstrap.py` cannot see any of this. Its harness replaces
`timeout` with a fake that `exec`s its argument or exits with a canned status,
so no test ever exercises real signal delivery, real process groups, or a
second attempt contending with residue from the first.

The surrounding fail-closed behavior is correct and must not be weakened. A
shard that cannot install its scanners must not publish evidence, aggregation
must keep refusing to publish on fewer than fourteen triples, and the verdict
store must stay untouched. This plan does not make a failed shard tolerable; it
makes the retry that was supposed to absorb a transient stall actually able to.

Expected implementation scope is `scripts/install-security-scanners`,
`tests/test_scanner_bootstrap.py`, and current documentation. Changing the
workflows' job topology, the unchanged twelve-minute scanner step cap, the
worklist producer, the shard data plane, aggregation, or `security-verdicts.json`
is outside this plan. Retrying a failed shard at the workflow level is a
separate concern and explicitly out of scope.

**Slug used throughout this plan:** `scanner-bootstrap-retry-safety`

---

## Orchestration Contract

**Slug:** `scanner-bootstrap-retry-safety`

**Plan file:**

```text
docs/plans/2026-08-18_scanner-bootstrap-retry-safety.md
```

**Implementation branch:**

```text
feat/scanner-bootstrap-retry-safety
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finalized
```

**Review notes:**

```text
docs/review/scanner-bootstrap-retry-safety-review-*.md
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
git checkout -b feat/scanner-bootstrap-retry-safety
```

Commit this plan first:

```bash
git add docs/plans/2026-08-18_scanner-bootstrap-retry-safety.md
git commit -m "docs(plan): add scanner-bootstrap-retry-safety implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add failing contracts before changing the script

The existing harness fakes `timeout`, so it can prove nothing about signal
delivery. Add tests that use the real `timeout` binary and real processes.

- Add a case that runs one phase whose payload spawns a grandchild through an
  intermediate wrapper, lets the phase exceed its timeout, and asserts that the
  grandchild is no longer alive shortly afterwards. Record the grandchild PID
  from inside the payload and poll `kill -0` with a bounded wait rather than a
  fixed sleep. This must fail against the current script.
- Add a case proving a retry after a timeout can succeed: a phase whose first
  attempt hangs past its timeout and whose second attempt exits 0 must make the
  phase succeed overall, with the script continuing to the next phase.
- Add a case proving an APT phase does not retry into a held dpkg lock: simulate
  the lock being held when the retry begins and require the script to wait for
  it, within a bounded window, rather than failing immediately with the
  `Could not get lock` status.
- Keep the existing fake-tool cases for the phases that do not need real signal
  behavior. Do not delete or weaken them.

Run the focused tests and record their node IDs and failing assertions before
implementing. Failures must be the missing behavior, not fixture errors.

### Task 2 — Reap the whole process group on phase timeout

Make a phase timeout terminate everything the phase started.

- Change `phase_run()` so a timed-out phase kills the payload's entire process
  group rather than only its direct child. Dropping `--foreground` is the
  documented mechanism and is expected to be sufficient; the script does not
  need TTY signal forwarding because every phase is non-interactive. If evidence
  shows a case it does not cover, use an explicit process-group kill instead and
  record why in the commit message.
- Escalate: send the terminating signal, allow a short bounded grace period, and
  then force-kill anything still alive in the group. Keep the exit status
  reported for a timeout as `124` so the existing named-phase diagnostics and
  the `test_scanner_bootstrap_timeout_fails_named_phase` contract still hold.
- Preserve every existing property of `phase_run()`: the UTC start/end/duration
  logging, the phase name in both the stdout record and the stderr failure line,
  the distinction between `require_phase`, `retry_phase`, and
  `require_retry_phase`, and fail-closed exit on a phase that exhausts its
  attempts.

### Task 3 — Make APT retries lock-aware and re-budget the phases

- Before an APT phase attempt, wait for the dpkg frontend lock to be free,
  bounded by an explicit timeout and logged as its own named phase so a stall is
  attributable in the job log. Exceeding that wait is a fail-closed error naming
  the lock, not a silent continue.
- Raise `RETRY_BACKOFF_SECONDS` for the APT phases so a retry does not begin
  while the previous attempt's teardown is still settling. A per-phase or
  category-specific backoff is acceptable; a single global constant that is too
  short for APT is not.
- Raise `BASE_APT_TIMEOUT_SECONDS` and `TRIVY_APT_TIMEOUT_SECONDS` so a normal
  cold install is not marginal. Shard 13 exceeded 60 seconds on an otherwise
  healthy runner while thirteen others fit, which means the budget is at the
  edge of the real distribution rather than above it.
- Recompute the documented worst-case total at the top of the script, including
  the new lock waits, backoffs, and grace periods. The recomputed worst case
  must be at most 600 seconds, leaving at least two minutes under the calling
  workflow's unchanged twelve-minute step cap. Update that comment to match the
  new constants exactly; a stale figure is a defect.
- Do not add attempts to phases that are not safe to repeat. Retry must remain
  limited to idempotent APT and key-fetch work, exactly as it is today.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` where they describe the
scanner bootstrap's bounded, retried phases, so the description matches the new
timeout, teardown, lock-wait, and budget behavior.

State plainly that external package-mirror availability is still not guaranteed
and that a shard which cannot install its scanners still fails closed and blocks
publication. Do not overstate the change: it makes a transient stall recoverable,
it does not make scanner setup reliable.

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

After adding the Task 1 tests and before changing the script:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_scanner_bootstrap.py \
  2>&1 | tee /tmp/decky-plugins-extended/scanner-bootstrap-retry-safety-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

Record the specific expected failures. The orphan-reaping case must fail because
the grandchild survives, not because of a fixture error.

### 2. Reproduce the production failure mechanism directly

Independently of pytest, confirm the mechanism and the fix with the real binary:

```bash
bash -n scripts/install-security-scanners
```

Then run a standalone probe that starts a payload spawning a grandchild which
outlives the timeout, once through the pre-fix invocation and once through the
post-fix invocation, and record for each whether the grandchild was reaped. The
expected result is that the pre-fix form leaves it alive and the post-fix form
does not. Save the probe and its output under
`/tmp/decky-plugins-extended/scanner-bootstrap-orphan-probe.log`.

### 3. Exercise the failure controls, then the valid controls

Prove each fails closed with its specific named-phase diagnostic:

- a phase that exceeds its timeout still reports status `124` and names the
  phase on stderr;
- an APT phase whose dpkg lock is never released fails within its bounded wait,
  naming the lock, rather than hanging or continuing silently;
- a key-download failure, a wrong Semgrep version, and an absent ClamAV database
  all still fail closed exactly as they do today;
- a non-idempotent phase is still not retried.

Then the valid controls: the full happy path succeeds; a phase whose first
attempt times out and whose second attempt succeeds makes the script continue;
and the recomputed worst-case total in the script's header comment is arithmetic
that matches the constants below it and is at most 600 seconds.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that
reintroduces the defect — restore `--foreground` to the timeout invocation — and
require the orphan-reaping test to fail because of it. Save the diff to
`/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety-mutation.patch`,
reverse it with `git apply -R`, rerun to exit 0, and verify
`git diff --exit-code`. Do not restore with a destructive checkout or reset.

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
installation locally. The fake-tool harness and the standalone signal probe are
the only permitted local executions; the probe must not install anything.

### Deferred verification

Local tests can prove signal delivery, teardown, and budget arithmetic. They
cannot prove hosted package-mirror behavior. Defer until the user authorizes a
run on the default branch:

1. a full-corpus run in which all fourteen shards complete scanner setup inside
   the unchanged twelve-minute cap;
2. at least one observed phase retry that recovers rather than failing, with the
   named phase and its timing visible in the job log;
3. aggregation publishing on fourteen triples, which has not yet happened — run
   `32222340066` reached aggregation with thirteen and correctly refused.

External package availability can never be guaranteed. The contract is that a
stall is bounded, named, retried once where safe, and fail-closed otherwise.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-bootstrap-retry-safety
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-bootstrap-retry-safety`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-bootstrap-retry-safety-review-*.md
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
   scripts/orchestration/clear-finished scanner-bootstrap-retry-safety
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
   git add docs/review/scanner-bootstrap-retry-safety-review-*.md
   git commit -m "docs(review): record scanner-bootstrap-retry-safety review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-bootstrap-retry-safety
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-bootstrap-retry-safety` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed scanner-bootstrap-retry-safety
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-bootstrap-retry-safety
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finalized
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
scripts/orchestration/finalize scanner-bootstrap-retry-safety
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finished
/tmp/decky-plugins-extended/scanner-bootstrap-retry-safety_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
