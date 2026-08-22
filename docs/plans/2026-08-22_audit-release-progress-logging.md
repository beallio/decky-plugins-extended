# Plan: Log Per-Release Audit Progress (audit-release-progress-logging)

## Context

When a shard hangs, nothing in the audit output says which release it was
working on. Diagnosis currently depends on the archived job log, and that log is
not guaranteed to exist.

Scheduled run `32590449724` (cron, `23818f6`, 2026-08-22) failed with shard 2
exceeding the audit step's configured 45-minute limit. The step began at
18:21:45 UTC and never completed; GitHub recorded the job complete at 19:11:18
UTC. Every other audit shard finished normally; representative peers were:

```text
shard  2  TIMEOUT (>45m)      shard  9   22.2 min
shard  5    7.8 min           shard  4   20.3 min
shard  0    9.5 min           shard 11   19.2 min
shard 13   18.1 min           shard  1   15.8 min
```

The obvious workload and bootstrap explanations do not fit the available
evidence. Shard 2 was assigned 43 of 621 items, below the 44.4-item mean, while
shard 13 processed 55 in 18.1 minutes. Scanner setup took 18 seconds. The
`Restore audit cache` step succeeded, but that step's conclusion alone does not
prove a cache hit; the configured shard-2 restore prefix was
`audit-cache-v2-e9a265edded89e40-shard-2-of-14`. Shard 2 itself had run
8.3–11.0 minutes in each of the five preceding runs.

The stall is inside `Run audit on all configured repositories`, whose hot path
is the per-release loop, and it could not be attributed further. GitHub's job-log
endpoint returned `BlobNotFound`. The timeout also prevented the audit shell
from recording `publishable=true`, so the conditional evidence-upload step did
not run and shard 2 has no artifact.

On the current `dev` tree, `main()` configures the root logger with
`logging.basicConfig()` at `audit_plugins.py:6428`; its default stream is stderr.
It logs `"Auditing shard %d/%d with %d eligible release(s)."` before the loop at
line 6913. There is per-release output today, but none identifies uncached work
before it can stall: cache-hit messages appear at lines 3372 and 3410, a resumed
checkpoint is logged at line 7148, and the ordinary classification/result line
at line 7192 is emitted only after `audit_release()` returns and the per-release
checkpoint succeeds. The loop begins at `audit_plugins.py:7087`.

This plan adds observability and nothing else. It must not change what the audit
decides, how long it waits, how work is sharded, what artifacts are produced, or
what aggregation accepts. A run before and after this change must produce
identical reports and verdict deltas for the same inputs.

Two scoping decisions are settled and are not open questions for the
implementer. Progress goes to stderr only through the existing logger: no new
artifact, no change to the manifest-bound worker output paths, and no GitHub
workflow-command output from the audit CLI. A slow completed release is flagged
at the fixed documented default of 300 seconds rather than through a new CLI
flag, environment variable, or policy key, so the worker's contract-tested
argument surface is unchanged.

Expected implementation scope is `audit_plugins.py`, focused tests, and current
documentation. Changing audit behavior, timeouts, sharding, the worklist
producer, worker artifact paths, the shard manifest, aggregation, workflows, or
`security-verdicts.json` is outside this plan.

**Slug used throughout this plan:** `audit-release-progress-logging`

---

## Orchestration Contract

**Slug:** `audit-release-progress-logging`

**Plan file:**

```text
docs/plans/2026-08-22_audit-release-progress-logging.md
```

**Implementation branch:**

```text
feat/audit-release-progress-logging
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-release-progress-logging_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-release-progress-logging_finalized
```

**Review notes:**

```text
docs/review/audit-release-progress-logging-review-*.md
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
git checkout -b feat/audit-release-progress-logging
```

Commit this plan first:

```bash
git add docs/plans/2026-08-22_audit-release-progress-logging.md
git commit -m "docs(plan): add audit-release-progress-logging implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add the failing observability contracts first

- In `tests/test_audit_worklist.py`, exercise `main()` with a deterministic
  multi-release work list and pin these one-line records (the normal logging
  prefix may precede them):

  ```text
  release_progress phase=start position=1/3 repository=https://github.com/owner/repo github_release_id=1 asset_id=10
  release_progress phase=complete position=1/3 repository=https://github.com/owner/repo github_release_id=1 asset_id=10 classification=PASS elapsed_seconds=1.250
  ```

  Both are `INFO`. Assert that every successfully checkpointed release iteration
  has exactly one start and one completion record, that its start precedes its
  completion, and that progress intervals do not overlap. Other existing
  diagnostic lines may occur inside an interval; do not require the pair to be
  adjacent.
- Pin the identity to the loop inputs — canonical repository URL, GitHub release
  ID, and asset ID — rather than `AuditReport.release_id`, because a start record
  must be available before an `AuditReport` exists. Pin `position=n/total` on
  both records and the final classification plus a three-decimal monotonic
  duration on completion.
- Pin the fixed contract `SLOW_RELEASE_SECONDS == 300.0`. With a fake monotonic
  clock, 299.999 seconds produces no warning and 300.000 seconds produces exactly
  one `WARNING` with this exact message shape:

  ```text
  release_progress phase=slow position=1/3 repository=https://github.com/owner/repo github_release_id=1 asset_id=10 classification=PASS elapsed_seconds=300.000 threshold_seconds=300.000
  ```

  Use fixed fake-clock values in these tests; do not derive the elapsed test
  value from the production constant.
- Cover the paths already present in the loop: a fresh audit, a resumed report,
  an `audit_release()` return representing either cache path, and a release-local
  `AUDIT_ERROR` all pair normally after a successful checkpoint. An unexpected
  `audit_release()` exception and a per-release checkpoint exception retain exit
  1 and leave that release's start unmatched; the existing error record must
  follow and no false completion may be emitted. Separately fail the redundant
  final post-loop checkpoint and assert every release pair remains complete.
- Add a subprocess-level worker test asserting that progress reaches stderr and
  worker stdout stays empty. Retain the existing producer tests in
  `tests/test_audit_plugins.py` that require preparation mode to emit exactly one
  `worklist_fingerprint=<64 lowercase hex>` stdout line, no stderr, and no
  `GITHUB_OUTPUT` write. Progress logging must not execute in producer,
  aggregation, or verdict-merge modes.
- Add a deterministic parity test that runs the same worker inputs once with
  logging enabled and once with logging disabled only through Python's logging
  API. Require identical return codes and byte-identical `progress`, report JSON,
  report Markdown, and verdict-delta artifacts plus the shard-manifest file.
  Freeze every report timestamp and use isolated output/cache directories so
  wall-clock or resume state cannot invalidate the comparison. Before changing
  production code, record and pin the baseline SHA-256 of each deterministic
  artifact as a literal expected value; confirm this parity test passes on the
  unmodified loop. Do not regenerate or update those expected hashes after the
  implementation.
- Add a test for the progress-field formatter itself using overlong, token-like,
  CR/LF-containing values. Assert `redact_secrets()` runs before the existing
  `EVIDENCE_MAX_LEN` bound, no secret or injected physical log line survives,
  and every rendered field is bounded. Do not use a credential-bearing
  repository or asset URL as a CLI fixture: the worklist validators correctly
  reject non-canonical URLs before the release loop.

Record node IDs and failing assertions before implementing.

### Task 2 — Emit per-release progress

- Change the current loop to `enumerate(work_items, start=1)` and compute the
  total once. After the item has been converted to `repository`, `release`, and
  `asset`, but before digest/resume checks or `audit_release()`, capture
  `time.monotonic()` and emit the start record specified in Task 1. This loop is
  shared by worklist workers and local/smoke audit modes, so all modes that
  traverse it receive the same stderr records; producer, aggregation, and
  verdict-merge modes return before it.
- Treat the complete per-release iteration as the observed interval: resume
  validation or audit, report/progress insertion, and `checkpoint_outputs()`.
  After a successful checkpoint, compute elapsed time from the same monotonic
  clock and emit the completion record. Replace the existing post-checkpoint
  emoji/classification log at current lines 7190–7199 with this completion
  record; do not emit both.
- This placement deliberately pairs resumed reports, both internal cache-return
  paths, and release-local `AUDIT_ERROR` reports. A killed process, unexpected
  audit exception, or checkpoint failure deliberately leaves an unmatched
  start. In the synchronous failure cases the following existing error record
  distinguishes failure from a silent stall; do not invent a completion outcome
  when no checkpoint committed.
- The final post-loop `checkpoint_outputs()` call is outside every release
  interval. If it stalls or fails after all releases paired, the truthful
  diagnosis is “no release in flight; failure occurred after the release loop.”
  Do not leave the last release unmatched or otherwise misattribute that phase.
- Emit at `INFO` through the existing module logger. In a fresh CLI process,
  `main()`'s current `logging.basicConfig()` installs a stderr `StreamHandler`,
  and `StreamHandler.emit()` flushes each record; embedded callers may already
  have configured logging, which this feature must not replace. Do not call
  `print()`, write or flush `sys.stderr` directly, walk/flush handlers, add a
  handler, or introduce a second logging configuration. The
  terminated-subprocess test is the proof that the last emitted start record is
  observable without clean shutdown.
- Add one small field-formatting helper that converts to text, neutralizes CR/LF
  and the other Unicode line separators (`\v`, `\f`, U+0085, U+2028, U+2029)
  into visible escaped text, then calls the existing `_compose_component_detail()`
  so secret redaction happens before `EVIDENCE_MAX_LEN` truncation. Use it on
  every interpolated identity or outcome field. This is log-line sanitization,
  not a second secret-redaction implementation.
- Keep hot-loop work bounded to a few field normalizations, two monotonic-clock
  reads, and the logger calls. Do not serialize reports, hash artifacts, probe
  scanners, log per file/finding/scanner, or add concurrency/timers for this
  feature.
- The two primary records add one net line per release because completion
  replaces the current result line: at most 110 primary progress lines for the
  observed 55-item shard. Existing cache-hit or resume diagnostics can add one
  more line per release, and a slow completion can add one warning; preserve
  those diagnostics rather than duplicating or removing them in this plan.

### Task 3 — Warn when a single release runs long

- Define `SLOW_RELEASE_SECONDS = 300.0` as the documented module-level default.
  The observed shards complete 43–55 releases in 8–22 minutes, so five minutes
  is far above the shard-level mean per release while still useful inside a
  45-minute step limit.
- Immediately after the completion record, log exactly one warning when that
  release's monotonic elapsed time is greater than or equal to the threshold.
  Name the same identity and position fields and include
  `elapsed_seconds=... threshold_seconds=300.000` for correlation.
- Evaluate the warning synchronously at completion. Do not add a timer, thread,
  signal handler, watchdog, or periodic poll: a release that never returns is
  identified by its unmatched start record and cannot truthfully receive a
  completion-time slow warning.
- Do not add a CLI flag, environment variable, or policy key for the threshold.
  The worker's argument surface is contract-tested by the workflow tests and
  stays unchanged.
- The warning is advisory. It must not abort the release, change its
  classification, alter any exit code, or affect aggregation.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` where they describe audit
observability, stating what a shard now logs per release and that the slow-
release warning is advisory. Update the overview's current-state date from
2026-08-18 to 2026-08-22 when adding the new current-state bullet.

State plainly that this improves attribution of a stall and does not prevent
one; a warning is emitted only when processing completes, while an unmatched
start identifies a still-running or abruptly terminated iteration. Also state
that a job killed by its step timeout may still lose its archived log and skip
artifact publication. Add focused assertions in `tests/test_audit_documentation.py`.
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

After adding the Task 1 tests and before implementing:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_audit_plugins.py \
  tests/test_audit_worklist.py \
  tests/test_audit_documentation.py \
  2>&1 | tee /tmp/decky-plugins-extended/audit-release-progress-logging-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

The failures must be the absent progress records, not fixture or setup errors.

### 2. Prove the change is observability-only

Run the deterministic multi-release worker integration test from Task 1 twice
through `main()`: once with normal logging and once with logging disabled via
the Python logging API. There is intentionally no CLI suppression flag. The
test must restore global logging state in `finally`, use fixed report timestamps
and independent clean output/cache directories, and assert equal return codes
plus byte equality for the four manifest-bound artifacts — progress, report
JSON, report Markdown, and verdict delta — and for the shard manifest itself. It
must also assert each artifact still matches the literal SHA-256 recorded from
the unmodified loop before implementation and that the tracked
`security-verdicts.json` bytes are unchanged. This baseline fence is what makes
the check a before/after comparison; enabled-versus-disabled logging alone would
not catch an unrelated output change made identically in both runs.

Have the focused test print the two SHA-256 values for each artifact only after
equality has passed, then run it with passed-test capture enabled and record the
real output:

```bash
set -o pipefail
PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -rP -p no:cacheprovider \
  tests/test_audit_worklist.py -k 'release_progress_artifact_parity' \
  2>&1 | tee /tmp/decky-plugins-extended/audit-release-progress-logging-parity.log
```

This is the check that decides whether the plan is safe: an observability change
that alters a verdict is a defect regardless of how useful its output is.

### 3. Reconstruct the failure this plan exists to diagnose

Add a bounded subprocess test around the real worker loop. A test-only child
harness (inline or under `tests/`, never in production code) must load a valid
three-release worklist, complete and checkpoint release 1, block inside release
2, and never reach release 3. The parent waits at most five seconds for release
2's start record, sends SIGTERM without allowing Python cleanup, and asserts:

- stderr contains release 1's ordered start/completion pair followed by release
  2's start;
- release 2 has no completion and is the only unmatched start;
- release 3 does not appear;
- stdout is empty; and
- the child did not exit normally.

Do not wait 300 seconds or patch the production threshold for this test. The
slow warning is completion-time advisory output; the unmatched, promptly flushed
start record is what diagnoses a process that never returns. Run the test with
passed-test capture enabled so its sanitized child stderr transcript is retained:

```bash
set -o pipefail
PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -rP -p no:cacheprovider \
  tests/test_audit_worklist.py -k 'release_progress_survives_terminated_worker' \
  2>&1 | tee /tmp/decky-plugins-extended/audit-release-progress-logging-stall.log
```

Record the transcript and the identification under
`/tmp/decky-plugins-extended/audit-release-progress-logging-stall.log`. If the
in-flight release cannot be named from that output, the plan has not achieved
its purpose and is not complete.

### 4. Exercise the failure controls, then the valid controls

- a release ending in release-local `AUDIT_ERROR`, either cache-return path, and
  the resumed-report path still emit a completion record after checkpoint;
- an unexpected audit exception or per-release checkpoint failure leaves an
  unmatched start, emits its existing run-global error, returns 1, and does not
  fabricate a completion;
- a failure of the separate final post-loop checkpoint returns 1 with every
  release pair complete, proving it is not misattributed to the last release;
- token-like and line-breaking content does not appear unredacted or create a
  second physical record, and rendered fields remain bounded;
- worker stdout remains empty; producer mode still prints exactly one
  `worklist_fingerprint=` line and remains free of progress stderr; aggregation
  and merge modes emit no release progress;
- the existing `test_release_outcome_exit_precedence`, mixed-release exit-4,
  report-only, and run-global failure tests still pin exit codes 0, 2, 3, 4, and
  1 without changing their expected results.

Then the valid controls: a healthy multi-release shard emits paired
start/completion records in order with no slow warnings, and a slow release
emits exactly one warning naming it. At exactly 300.000 seconds the warning is
present; at 299.999 seconds it is absent.

### 5. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that removes
the completion record, and require the pairing test to fail. Make a second that
changes `SLOW_RELEASE_SECONDS` from `300.0` to `301.0`, and require both the
constant-contract assertion and the fixed-300.000-second warning test to fail.
The fake elapsed value must not be calculated from the mutated constant, or this
control proves nothing. Save both diffs under
`/tmp/decky-plugins-extended/audit-release-progress-logging-mutation-*.patch`,
reverse each with `git apply -R`, rerun to exit 0, and verify
`git diff --exit-code`. Do not restore with a destructive checkout or reset.

### 6. Run the complete repository gate

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
test/subtest tallies.

`uv`'s experimental OSV malware check has been failing intermittently with
`Request failed after N retries`, failing a different
`tests/test_workflow_selection.py` parametrization each run. If the gate fails
only that way, re-run and record both outcomes; do not report a network flake as
a passing gate, and do not change a test to accommodate it.

### Deferred verification

Local tests can prove the records are emitted, paired, redacted, and
behaviour-neutral. They cannot prove what GitHub retains. Defer until the user
authorizes a run on the default branch:

1. a scheduled run whose shard logs show paired start/completion records for
   every successfully checkpointed release and no unexplained unmatched start;
2. confirmation of how many fixed-threshold slow-release warnings a healthy run
   produces; the 300-second default is not adjusted automatically by this plan;
3. if a shard stalls again, confirmation that the in-flight release is
   identifiable from the run's output.

Item 3 cannot be scheduled and may not recur. Do not treat its absence as
success, and do not induce a stall in production to obtain it.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-release-progress-logging
```

This writes:

```text
/tmp/decky-plugins-extended/audit-release-progress-logging_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-release-progress-logging`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-release-progress-logging-review-*.md
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
   scripts/orchestration/clear-finished audit-release-progress-logging
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
   git add docs/review/audit-release-progress-logging-review-*.md
   git commit -m "docs(review): record audit-release-progress-logging review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-release-progress-logging
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-release-progress-logging` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-release-progress-logging
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-release-progress-logging
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-release-progress-logging_finalized
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
scripts/orchestration/finalize audit-release-progress-logging
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-release-progress-logging_finished
/tmp/decky-plugins-extended/audit-release-progress-logging_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
