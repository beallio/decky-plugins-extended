# Review — quota-safe-security-audit (round 36)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`
Reviewed commits: `fa8db3a`, `1da7ffa`, `849e299`, `bb006b2`

## Verdict

Tasks 6 through 9 are structurally complete and the design is right.  The
producer/worker/aggregator topology, the credential boundary, the bounded API
budget, the shared scanner bootstrap, and the documentation all match the plan.

Three defects block acceptance.  One of them fails every CI run on the first
scanner-install step, and the test that should have caught it is constructed so
that it cannot.  The other two are unplanned resilience regressions in code
paths the plan did not authorize changing.

## Gate status

`scripts/orchestration/run-quality-gates` passed at `bb006b2`: actionlint
verified with all three mutation negative controls rejected as expected —
including the updated `needs: [prepare-audit-worklist, scheduled-audit]` anchor,
which still fails actionlint when mutated to a missing job — Ruff check and
format clean, and Pytest reporting `971 passed, 63 subtests passed` (up from
953).  `check-review-notes-not-deleted` reported none deleted, `git diff --check`
passed, the worktree is clean, and `security-verdicts.json` is unchanged from
`git merge-base dev HEAD` at SHA-256
`d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

Green gates are not evidence here.  Defect 1 below is invisible to the suite by
construction, and defects 2 and 3 have no covering test at all.

## Required changes

### 1. The ClamAV database check can never pass in CI (blocking)

`scripts/install-security-scanners` ends with:

```bash
require_phase "verify ClamAV database" "$VERIFY_TIMEOUT_SECONDS" ls "$CLAMAV_DB_GLOB"
```

`CLAMAV_DB_GLOB` defaults to `/var/lib/clamav/*.c?d`.  Because it is quoted and
`phase_run` execs `timeout --foreground <n> "$@"` with no shell, `ls` receives
the literal pattern as one argument.  `ls` does not expand globs.  Verified
directly against a directory containing real `main.cvd` and `daily.cld` files:

```text
timeout --foreground 5 ls "<dir>/*.c?d"        -> exit 2, "cannot access"
bash -c 'ls $1' -- "<dir>/*.c?d"               -> exit 0
bash -c 'compgen -G "$1" >/dev/null' -- "<dir>/*.c?d" -> exit 0
```

The final phase therefore fails, `require_phase` exits non-zero, and the
`Install required security scanners` step fails in all three places it is used —
both audit workers and the PR smoke job — on every run.  The predecessor inline
body used an unquoted `ls /var/lib/clamav/*.c?d`, so the shell expanded it; the
extraction to a script silently changed that behavior.

`tests/test_scanner_bootstrap.py` cannot see this.  `_fake_environment()` sets
`CLAMAV_DB_GLOB` to a concrete file path (`tmp_path/clamav/main.cvd`) rather
than a pattern, and stubs `ls` with a script that ignores its arguments and
succeeds unless `FAKE_CLAMAV_DB_MISSING` is set.  Both substitutions are needed
for the test to pass; either one alone would have exposed the defect.

Fix the expansion — a shell-evaluated `compgen -G` phase is the clearest form —
and fix the fixture so it exercises a real glob pattern against a directory of
real files, with a real `ls`/`compgen`, so the present-database and
missing-database cases both mean what they claim.

### 2. Disabling urllib3 retries regressed the worker data plane

`_make_github_session()` changed from
`Retry(total=MAX_RETRIES, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504], respect_retry_after_header=True)`
to `Retry(total=0, connect=0, read=0, redirect=0, status=0, respect_retry_after_header=False)`.

Routing producer retry policy through `ApiRequestBudget` is correct, but
`_gh_session` is not producer-only.  It is also the transport for
`download_zip()` (`audit_plugins.py:4143`) and
`audit_source_snapshot.materialize_source_snapshot()` (`audit_plugins.py:5013`),
both on the worker path, and
`plugin_release_utils.bounded_stream_download()` issues a single
`session.get(...)` with no retry loop of its own.  Workers therefore lost every
transient-failure retry for artifact and codeload downloads: one 502 from
`objects.githubusercontent.com` or `codeload.github.com` now fails the release
outright where three backed-off attempts previously succeeded.

The non-producer `_gh_get()` path regressed too.  Its `except
requests.RequestException` clause wraps only `_gh_session.get(...)`; the
subsequent `resp.raise_for_status()` sits in a separate `try/finally`, so a
5xx now propagates on the first response instead of being retried.  That path
still serves the PR smoke audit and every local `--all`/`--repository` run.

The plan scopes Task 6 to *producer* REST, and Scope discipline forbids changing
runtime behavior beyond what the plan specifies.  Restore equivalent
transient-failure resilience for the non-producer and download paths — either by
keeping the transport-level `Retry` for sessions used outside the producer
budget, or by giving those callers their own bounded retry — and add a test that
fails if a transient 5xx stops being retried on the worker download path.

### 3. `git ls-remote` is not clipped to the producer budget

`prepare_audit_worklist()` calls
`tag_resolver(owner, repo, api_deadline_seconds)` once per repository, and
`resolve_repository_tags_via_ls_remote()` passes that value straight through as
the per-subprocess `timeout`.  Each repository may therefore consume the full
480 seconds independently: `additional_plugins.txt` currently holds 41
repositories, so the worst case is 41 × 480s ≈ 328 minutes against a job whose
timeout is 10 minutes.

Task 6 exists so the producer fails with a clear bounded error rather than being
killed by the surrounding Actions deadline.  Git transport is not REST, but it
is producer work inside the same job, and leaving it unclipped defeats the
task's stated purpose.  Clip each `ls-remote` timeout to the budget's remaining
monotonic seconds and raise the same bounded run-global error when no budget
remains, with a test that proves a late repository cannot exceed the deadline.

### 4. Record the Task 5 independent verification

Round 35 required an explicit statement, with evidence, on whether `dad839f` and
`d3b0473` correctly implement Task 5 — because the orchestrator wrote that code
and cannot review it.  None of this round's four commits carries a message body,
and no session log or other durable record states a conclusion.

State the finding explicitly in this round: either the specific defect you found,
or an affirmative statement of what you checked and why you conclude the
aggregate-coverage contract holds.  A silent pass is not a review.

### 5. Restore the merged-delta assertion in the rewritten aggregation test

`test_workflow_aggregation_merges_one_delta_with_thirteen_empty_shards` had to
change — its hand-built shard-13 report is no longer a valid worklist identity
under exact-coverage aggregation — and rebuilding it on the coverage fixture is
right.  But the rewrite dropped the assertion that the aggregate verdict delta
equals `_verdict_delta_from_reports(...)`, keeping only `report_count` and the
release-id list.  Delta-merge correctness through the real workflow shell body
is now unasserted.

Restore an equality assertion on the merged delta, and rename the test to match
what it now exercises.

### 6. Minor: honor `TRIVY_KEYRING_PATH` in the source list

`configure Trivy repository` hardcodes `signed-by=/usr/share/keyrings/trivy.gpg`
while the keyring is installed to `$TRIVY_KEYRING_PATH`.  The two disagree
whenever the variable is overridden.  Use the variable in both places.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note.  Do not
modify `security-verdicts.json`.  Do not start hosted workflows.  The plan's
Deferred verification items remain deferred.

STATUS: CHANGES_REQUESTED
