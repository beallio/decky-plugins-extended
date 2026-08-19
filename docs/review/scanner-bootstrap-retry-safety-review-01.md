# Review — scanner-bootstrap-retry-safety (round 1)

Branch: `feat/scanner-bootstrap-retry-safety`
Reviewed against: `docs/plans/2026-08-18_scanner-bootstrap-retry-safety.md`
Reviewed commits: `3dbfae7`, `96ce692`, `0c1d0c7`, `aa06b57`

## Verdict

The central defect is fixed and proven fixed.  I reproduced the orphan-reaping
behavior independently of the delivered tests and confirmed the payload is now
killed with its process group.  The global 600-second runtime budget is a better
answer than the static arithmetic the plan asked for, because it is enforced
rather than asserted.

Two defects remain.  Both are cases where a protection this plan added can
silently become a no-op, which is the same failure shape as the bug being
fixed: machinery that looks present in the log but cannot do its job.

## Gate status

`scripts/orchestration/run-quality-gates` passed at `aa06b57`: actionlint
verified with all three mutation negative controls rejected, Ruff check and
format clean, Pytest `995 passed, 63 subtests passed`.  Review notes not
deleted, `git diff --check` clean, worktree clean, `security-verdicts.json`
unchanged from `git merge-base dev HEAD`.

Verification evidence is genuine and independently reproduced:

- The red log records
  `test_scanner_bootstrap_reaps_timeout_grandchildren_with_real_timeout` and
  `test_scanner_bootstrap_waits_for_dpkg_lock_before_apt_retry` failing before
  implementation.
- The saved probe records `pre-fix: SURVIVED` / `post-fix: REAPED`.
- The mutation patch restores `timeout --foreground` and the orphan test fails,
  confirming the guard is load-bearing.
- I re-ran the escalation independently with the shipped constants
  (`grace=5s`, `kill-after=6s`) and observed the payload reaped.

## Required changes

### 1. The dpkg-lock wait fails open when `fuser` is unavailable

`wait_for_dpkg_frontend_lock()` polls with:

```bash
while sudo -n fuser "$lock_path" >/dev/null 2>&1; do
  sleep "$poll_seconds"
done
```

If `fuser` is not installed, the command fails, the loop condition is false on
the first evaluation, and the phase reports success having checked nothing.
Verified directly: with a command that does not exist, the loop exits in 0
seconds.

This matters more than it looks.  `fuser` ships in `psmisc`, and the first
caller of this guard is `install base packages` — the phase that runs *before*
the bootstrap has installed anything.  On any runner image lacking `psmisc` the
entire Task 3 protection is vacuous, and the log still prints a
`wait for dpkg frontend lock` phase that appears to have passed.

Every test in `tests/test_scanner_bootstrap.py` stubs `fuser`, so none of them
can observe this.

Require the lock check to establish that it can actually check: verify the tool
is available and fail closed with a named diagnostic if it is not, or use a
detection method that does not depend on an optional package.  Add a test that
runs the bootstrap with no `fuser` on `PATH` and asserts the run does not
silently proceed as though the lock were free.

### 2. Orphan reaping depends on a one-second escalation margin

`timeout` is invoked without `--foreground`, so it signals its own process
group — but the supervisor runs `set -m` and backgrounds the payload, which puts
the payload in a *different* process group.  Confirmed:

```text
wrapper pid=2239756 wrapper pgid=2239756
payload pid=2239757 payload pgid=2239757
```

So `timeout`'s group signal never reaches the payload.  The only thing that
kills it is the supervisor's own `TERM` trap.  If `timeout --kill-after` kills
the supervisor before that trap finishes, the payload's separate process group
is orphaned — exactly the bug this plan exists to fix.

The trap needs `PHASE_TIMEOUT_KILL_GRACE_SECONDS` (5) plus overhead;
`--kill-after` is `KILL_GRACE + SUPERVISOR_GRACE` (6).  The entire safety margin
is the one-second supervisor grace.  I confirmed the failure mode is real by
running the identical supervisor with the grace raised above the kill-after:

```text
grace=5s killafter=6s -> payload reaped
grace=8s killafter=6s -> payload SURVIVED
```

Make the relationship structural rather than a coincidence of two constants.
Either give the supervisor a margin proportional to its grace rather than a flat
extra second, or have it issue `KILL` and exit without waiting out the full
grace when the payload is already gone.  Then add a test that fails if the
margin is removed — the current
`test_scanner_bootstrap_enforces_documented_total_budget` asserts the presence
of implementation strings but never asserts that escalation completes inside
`--kill-after`.

### 3. Reduce the budget test's dependence on implementation strings

`test_scanner_bootstrap_enforces_documented_total_budget` asserts on literal
source fragments including `'timeout --kill-after="$((timeout_teardown_seconds))s"'`,
`"set -m"`, and an exact arithmetic expression.  Keeping the
`"timeout --foreground" not in source` assertion is right — that one guards a
specific known regression.  The rest will break on any harmless refactor while
proving nothing about behavior.

Replace the structural assertions with behavioral ones wherever the harness can
execute the script, and keep only the constants and the `--foreground` guard as
source-level checks.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note.  Do not
modify `security-verdicts.json`.  Do not start hosted workflows.  Deferred
verification stands: aggregation has still never published on fourteen triples,
so the verdict merge and publish path remains unexercised on real evidence.

STATUS: CHANGES_REQUESTED
