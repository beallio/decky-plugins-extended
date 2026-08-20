# Plan: Retain Downloaded Scanner Packages For Reuse (scanner-cache-retention)

## Context

The scanner package cache never populates, so it has no effect. APT deletes the
archives it downloads before the workflow can save them, and every run is
therefore still a cold run.

Two consecutive hosted runs demonstrate it. Run `32307634112` installed cold on
every shard and reported:

```text
phase=install base packages cache=cold downloaded=true
  archive-dir=/home/runner/work/.../.scanner-package-cache/apt-archives
```

Its `Save scanner package cache` step reported success, but no
`Cache saved with key: scanner-package-cache-...` line appears anywhere in that
job's log — only the unrelated audit cache was written. The next run,
`32312956716`, then logged:

```text
Cache not found for input keys:
  scanner-package-cache-v1-ubuntu24-20260810.271.1-8c3ae367...-2e4d7d83...,
  scanner-package-cache-v1-ubuntu24-20260810.271.1-
```

and installed cold again. The save step found an empty directory and stored
nothing, so the restore had nothing to find.

The cause is that `scripts/install-security-scanners` never sets
`APT::Keep-Downloaded-Packages`. Ubuntu runner images commonly ship APT
configured to remove downloaded `.deb` files immediately after a successful
install, so pointing `Dir::Cache::archives` at a workspace directory changes
where APT downloads but not whether it keeps. The archives exist only for the
duration of the install.

The existing tests cannot see this. `tests/test_scanner_bootstrap.py` replaces
`apt-get` with a fake that writes archives and never deletes them, so the warm,
cold, and tamper cases all pass against a model of APT that does not reproduce
the behavior that breaks the feature.

Nothing about the current state is unsafe — the cache is inert, not wrong. Every
install still verifies against the signed package index, and both runs completed
all fourteen shards and published verdicts successfully. What is missing is the
benefit the cache was built for: removing the repeated mirror download that
failed shards in runs `32222340066`, `32275727649`, and `32285669639`.

Cache integrity remains the governing constraint and is unchanged by this plan.
A restored Actions cache is untrusted input; installation must continue to run
through `apt-get` with its verification against the signed index, there must be
no `dpkg -i` and no option permitting unauthenticated packages, and a hash
mismatch must continue to discard the restored archives and fall back to a cold
install.

Expected implementation scope is `scripts/install-security-scanners`,
`tests/test_scanner_bootstrap.py`, and current documentation. Changing the
workflows' cache wiring, the worklist producer, the shard data plane,
aggregation, the twelve-minute scanner step cap, the 600-second bootstrap
budget, the phase allocation model, or `security-verdicts.json` is outside this
plan.

**Slug used throughout this plan:** `scanner-cache-retention`

---

## Orchestration Contract

**Slug:** `scanner-cache-retention`

**Plan file:**

```text
docs/plans/2026-08-19_scanner-cache-retention.md
```

**Implementation branch:**

```text
feat/scanner-cache-retention
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-cache-retention_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-cache-retention_finalized
```

**Review notes:**

```text
docs/review/scanner-cache-retention-review-*.md
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
git checkout -b feat/scanner-cache-retention
```

Commit this plan first:

```bash
git add docs/plans/2026-08-19_scanner-cache-retention.md
git commit -m "docs(plan): add scanner-cache-retention implementation plan"
```

---

## Implementation Tasks

### Task 1 — Make the harness reproduce APT's deletion behavior first

The current fake `apt-get` never deletes what it downloads, which is why a
feature that cannot work passed every test. Fix the model before fixing the
code.

- Change the fake `apt-get` so that, by default, a successful install removes
  the archives it downloaded — matching an image configured with
  `APT::Keep-Downloaded-Packages "false"`. Make it honor the option that
  requests retention, so the fake distinguishes the two configurations rather
  than hard-coding either.
- Add a test asserting that after a cold install the archive directory still
  contains the downloaded archives. Against the current script and the corrected
  fake, this must fail.
- Add a test asserting the resulting archives are exactly what a subsequent warm
  run consumes: a second bootstrap run over the same directory must report
  `cache=warm downloaded=false`.
- Re-run the existing cache tests against the corrected fake and fix any that
  were passing only because deletion was not modeled. Record in the session log
  which tests changed and why; do not weaken an assertion to make it pass.

### Task 2 — Retain the downloaded archives

- Pass `APT::Keep-Downloaded-Packages=true` on the APT invocations that populate
  the archive directory, so a successful install leaves its archives behind for
  the workflow to save. Prefer setting it on the specific invocations the cache
  depends on rather than globally.
- Verify the retention actually holds rather than assuming it: after the install
  phase, confirm the archive directory is non-empty and report that in the phase
  outcome line alongside the existing `cache=` and `downloaded=` fields, so a
  future regression is visible in the job log rather than silent for two runs.
- If the directory is unexpectedly empty after a successful cold install, say so
  loudly on stderr. Do not fail the step for it — an empty cache is a lost
  optimization, not a correctness problem, and failing closed here would trade a
  working audit for a warm cache.
- Preserve every existing property: budget-derived phase allocation with retry
  splitting, process-group reaping, the dpkg-lock guard with its fail-closed
  `fuser` check, named UTC phase logging, retry only for idempotent work, and
  fail-closed exit on an exhausted phase.

### Task 3 — Keep the integrity contract exactly as it is

This task adds no behavior; it exists so the integrity properties are re-proven
against the corrected harness rather than assumed to survive.

- Installation continues through `apt-get` with `Dir::Cache::archives`, relying
  on its verification against the signed package index. No `dpkg -i`. No option
  permitting unauthenticated or unverified packages.
- A tampered or stale archive still causes the restored archives to be
  discarded, logged with the offending path, and replaced by a cold install that
  re-obtains and re-verifies them.
- Re-run the tamper and verification tests against the corrected fake and
  confirm they still hold. If retention changes when the discard happens
  relative to the install, adjust the implementation rather than the assertion.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` only where they describe
the package cache, so the description matches a cache that actually retains
archives.

State plainly that the first run after any key change is still cold, that a
sufficiently slow mirror on a cold run still fails the shard closed and blocks
publication, and that cache reuse never bypasses signed-index verification.

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

After correcting the fake `apt-get` and adding the Task 1 tests, and before
changing the script:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_scanner_bootstrap.py \
  2>&1 | tee /tmp/decky-plugins-extended/scanner-cache-retention-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

The retention case must fail because the archive directory is empty after a
successful install, reproducing what runs `32307634112` and `32312956716`
showed. A red phase that fails for any other reason does not establish this
one.

### 2. Prove the two-run cycle locally

Demonstrate the behavior the hosted runs failed to produce, using the fake
harness only:

- run the bootstrap once against an empty archive directory, and show the
  directory is non-empty afterwards;
- run it a second time against that same directory, and show it reports
  `cache=warm downloaded=false` and performs no download.

Save the transcript under
`/tmp/decky-plugins-extended/scanner-cache-retention-two-run.log`. This is the
check that decides whether the plan achieved anything; a green suite without it
proves nothing.

### 3. Exercise the failure controls, then the valid controls

- a tampered cached archive is still discarded, logged with its path, and
  replaced by a cold install that re-verifies;
- no code path installs a cached archive with `dpkg -i`, and no APT invocation
  permits unauthenticated or unverified packages;
- an empty archive directory after a successful cold install reports loudly on
  stderr and does not fail the step;
- every previously established control still holds: budget exhaustion reports
  `125`, a phase timeout reports `124` and reaps its process group, the
  dpkg-lock guard fails closed without `fuser`, the Trivy signing-key
  fingerprint is verified, Semgrep `1.132.0` is enforced, and the ClamAV
  database check still runs.

Then the valid controls: the full happy path succeeds cold and warm, and the
warm path performs no download.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that removes
the retention option, and require the retention test to fail because of it.
Save the diff to
`/tmp/decky-plugins-extended/scanner-cache-retention-mutation.patch`, reverse it
with `git apply -R`, rerun to exit 0, and verify `git diff --exit-code`. Do not
restore with a destructive checkout or reset.

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
test/subtest tallies.

Note for this repository at this time: `uv`'s experimental OSV malware check has
been failing intermittently with `Request failed after N retries`, which fails a
different `tests/test_workflow_selection.py` parametrization on each run. If the
gate fails only that way, re-run and record both outcomes; do not report a
network flake as a passing gate, and do not change any test to accommodate it.

Do not invoke real APT, ClamAV refresh, Trivy installation, or Semgrep
installation locally. The fake-tool harness is the only permitted local
execution of the installer.

### Deferred verification

Local tests can prove retention against a corrected model of APT. They cannot
prove the runner image's actual APT configuration. Defer until the user
authorizes a run on the default branch:

1. a run whose `Save scanner package cache` step logs
   `Cache saved with key: scanner-package-cache-...`, which neither
   `32307634112` nor `32312956716` did;
2. a following run whose shards report `cache=warm downloaded=false`;
3. `install base packages` durations on that warm run showing the tail observed
   in run `32285669639` no longer occurring.

Two runs are required to evaluate this, and the first is still cold by
definition. A single green run is not evidence either way.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-cache-retention
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-cache-retention_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-cache-retention`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-cache-retention-review-*.md
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
   scripts/orchestration/clear-finished scanner-cache-retention
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
   git add docs/review/scanner-cache-retention-review-*.md
   git commit -m "docs(review): record scanner-cache-retention review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-cache-retention
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-cache-retention` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed scanner-cache-retention
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-cache-retention
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-cache-retention_finalized
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
scripts/orchestration/finalize scanner-cache-retention
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-cache-retention_finished
/tmp/decky-plugins-extended/scanner-cache-retention_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
