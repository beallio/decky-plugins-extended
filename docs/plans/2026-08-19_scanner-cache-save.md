# Plan: Make The Scanner Package Cache Saveable (scanner-cache-save)

## Context

The scanner package archives are now retained, but the cache still cannot be
saved: APT leaves root-owned working files in the archive directory that the
cache action cannot read, so `tar` aborts and the whole save is discarded.

Run `32325583672` (`workflow_dispatch` on `main` at `a53b0c3`, 2026-08-20) was
the first fully green audit — producer, all fourteen shards, aggregation,
verdict publication, and `Enforcement result: success`. Every shard confirmed
the retention fix:

```text
phase=install base packages cache=cold downloaded=true archive-retained=true
  archive-dir=/home/runner/work/.../.scanner-package-cache/apt-archives
```

The save then failed on every shard:

```text
/usr/bin/tar: .scanner-package-cache/apt-archives/lock: Cannot open: Permission denied
/usr/bin/tar: .scanner-package-cache/apt-archives/partial: Cannot open: Permission denied
/usr/bin/tar: Exiting with failure status due to previous errors
##[warning]Failed to save: "/usr/bin/tar" failed with error: exit code 2
```

`apt-get` runs under `sudo`, so it creates `lock` and `partial/` inside the
archive directory as root with restrictive permissions. The cache save runs as
the unprivileged `runner` user. The `.deb` files themselves are readable; two
pieces of transient APT working state are not, and `tar` treats that as fatal
for the entire archive.

The step reported success regardless, because it carries
`continue-on-error: true`. That flag is correct — a failed cache save must never
fail a shard — but it means a permanently broken save is invisible in step
conclusions and surfaces only in the raw log. The `archive-retained` field added
by the previous plan is what made this diagnosable on the first run instead of
the third; the save outcome deserves the same treatment.

A second defect is visible in the same run. The cache key pins the runner image
build, and that build is not constant within a single run:

```text
shard 0: ubuntu24-20260810.271.1     shard 5: ubuntu24-20260810.271.1
shard 1: ubuntu24-20260816.277.1     shard 7: ubuntu24-20260816.277.1
shard 13: ubuntu24-20260816.277.1
```

Shards therefore compute different keys, and the `restore-keys` prefix pins the
same build so it does not bridge them. Even with saving repaired, a run would
split across multiple cache entries and warm only partially. The archives
themselves come from the Ubuntu release's package pool and do not depend on the
image build number; the build only affects which packages are already present,
which the package-set hash and the missing-package computation already handle.

Nothing here is a correctness problem. The audit is healthy, publication works,
and every install still verifies against the signed package index. This plan is
about the optimization actually landing.

Cache integrity is unchanged and remains the governing constraint. A restored
Actions cache is untrusted input; installation must continue to run through
`apt-get` with signed-index verification, with no `dpkg -i` and no option
permitting unauthenticated packages, and a hash mismatch must continue to
discard the restored archives and fall back to a verified cold install.

Expected implementation scope is `scripts/install-security-scanners`, both audit
workflows' cache key computation, `tests/test_scanner_bootstrap.py`,
`tests/test_workflow_security.py`, and current documentation. Changing the
worklist producer, the shard data plane, aggregation, the twelve-minute scanner
step cap, the 600-second bootstrap budget, the phase allocation model, or
`security-verdicts.json` is outside this plan.

**Slug used throughout this plan:** `scanner-cache-save`

---

## Orchestration Contract

**Slug:** `scanner-cache-save`

**Plan file:**

```text
docs/plans/2026-08-19_scanner-cache-save.md
```

**Implementation branch:**

```text
feat/scanner-cache-save
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-cache-save_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-cache-save_finalized
```

**Review notes:**

```text
docs/review/scanner-cache-save-review-*.md
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
git checkout -b feat/scanner-cache-save
```

Commit this plan first:

```bash
git add docs/plans/2026-08-19_scanner-cache-save.md
git commit -m "docs(plan): add scanner-cache-save implementation plan"
```

---

## Implementation Tasks

### Task 1 — Model the unreadable working state in the harness first

The fake `apt-get` creates only readable archives, which is why a directory the
cache action cannot read passed every test. Correct the model before the code,
exactly as the previous plan did for deletion.

- Make the fake `apt-get` create the working state real APT leaves behind — a
  `lock` file and a `partial/` directory — and make them unreadable to the test
  user where the platform allows it, so the harness reproduces the condition
  that broke the save.
- Add a test asserting the archive directory is readable end to end after a
  successful install: every entry must be openable by the unprivileged user, so
  an archiver walking the tree cannot fail. Against the current script this must
  fail.
- Add a test asserting the retained `.deb` archives still survive that cleanup —
  removing the working state must not remove the cache contents.
- Keep every existing cache test passing on its current assertions. If one must
  change, record which and why in the session log, and do not weaken it.

### Task 2 — Leave the archive directory saveable

- After a successful install, remove APT's transient working state from the
  archive directory so only cacheable content remains. `lock` and `partial/` are
  working files, not cache contents; deleting them is preferable to broadening
  their permissions.
- Do not use `sudo` to widen ownership of the retained archives unless deletion
  proves insufficient. If ownership must change, restrict it to exactly what the
  archiver needs to read.
- Verify rather than assume: after the cleanup, confirm no entry in the archive
  directory is unreadable to the current user, and report the result in the
  install phase outcome line alongside the existing `cache=`, `downloaded=`, and
  `archive-retained=` fields. Name the field so a future regression is greppable
  in one run's log.
- If unreadable entries remain, say so loudly on stderr and continue. As with an
  empty cache, an unsaveable cache is a lost optimization, not a correctness
  problem, and must never fail the audit.
- Preserve every existing property: budget-derived allocation with retry
  splitting, process-group reaping, the dpkg-lock guard with its fail-closed
  `fuser` check, named UTC phase logging, retry only for idempotent work, and
  fail-closed exit on an exhausted phase.

### Task 3 — Key the cache at a granularity that is stable within a run

- Derive the cache key from the runner OS identity that actually determines
  package resolution, not the image build number. Run `32325583672` used two
  image builds across fourteen shards, so a build-pinned key cannot warm a whole
  run.
- Keep the package-set hash and the bootstrap script hash in the key: both do
  change what the cache should contain.
- Keep a `restore-keys` prefix that can still bridge a partial match, and make
  sure that prefix is itself stable within a run.
- Apply the change to both workflows in lockstep, and extend the workflow
  contract tests so a key that reintroduces the build number fails.
- Note explicitly in the implementation that loosening the key is safe because a
  restored archive that does not match the current index is discarded and
  replaced by a verified cold install. That existing behavior is what makes this
  granularity acceptable; do not change it.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` only where they describe
the package cache, covering what is now removed before saving, the key
granularity and why it is safe, and the fields the install phase reports.

State plainly that the first run after any key change is still cold, that a
slow mirror on a cold run still fails the shard closed and blocks publication,
and that cache reuse never bypasses signed-index verification.

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

After correcting the harness and adding the Task 1 tests, and before changing
the script:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_scanner_bootstrap.py \
  tests/test_workflow_security.py \
  2>&1 | tee /tmp/decky-plugins-extended/scanner-cache-save-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

The readability case must fail because unreadable working state remains in the
archive directory, reproducing what run `32325583672` showed. A red phase that
fails for another reason does not establish this one.

### 2. Prove the directory is archivable

Reproduce what the cache action actually does, rather than asserting a proxy.
After a successful cold install in the harness, run a real `tar` over the
archive directory as the unprivileged user and require exit 0:

```bash
tar --posix -cf /dev/null -C "<workspace>" .scanner-package-cache/apt-archives
```

Record the command, its exit status, and the archive directory listing under
`/tmp/decky-plugins-extended/scanner-cache-save-archivable.log`. This is the
check that decides whether the plan achieved anything: run `32325583672` failed
at exactly this step with `tar` exit 2, and a green suite that does not exercise
`tar` proves nothing about it.

Then repeat over a warm second run and require exit 0 again.

### 3. Exercise the failure controls, then the valid controls

- unreadable entries that cannot be removed are reported loudly on stderr and do
  not fail the step;
- the retained `.deb` archives survive the cleanup, and a warm second run still
  reports `cache=warm downloaded=false`;
- a tampered cached archive is still discarded, logged with its path, and
  replaced by a verified cold install;
- no code path installs a cached archive with `dpkg -i`, and no APT invocation
  permits unauthenticated or unverified packages;
- every previously established control still holds: budget exhaustion reports
  `125`, a phase timeout reports `124` and reaps its process group, the
  dpkg-lock guard fails closed without `fuser`, the Trivy signing-key
  fingerprint is verified, Semgrep `1.132.0` is enforced, and the ClamAV
  database check still runs.

Then the valid controls: the full happy path succeeds cold and warm, and both
workflows compute a cache key that is identical for two shards given two
different runner image builds.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that skips
the working-state cleanup, and require the archivability test to fail because of
it. Save the diff to
`/tmp/decky-plugins-extended/scanner-cache-save-mutation.patch`, reverse it with
`git apply -R`, rerun to exit 0, and verify `git diff --exit-code`. Do not
restore with a destructive checkout or reset.

The existing actionlint mutation controls must still reject invalid YAML,
invalid expressions, and invalid job dependencies after the workflow changes.

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

`uv`'s experimental OSV malware check has been failing intermittently with
`Request failed after N retries`, failing a different
`tests/test_workflow_selection.py` parametrization each time. If the gate fails
only that way, re-run and record both outcomes; do not report a network flake as
a passing gate, and do not change any test to accommodate it.

Do not invoke real APT, ClamAV refresh, Trivy installation, or Semgrep
installation locally. The fake-tool harness is the only permitted local
execution of the installer.

### Deferred verification

Local tests can prove the directory is archivable and the key is build-stable.
They cannot prove the hosted cache service accepts the upload. Defer until the
user authorizes a run on the default branch:

1. a run whose `Save scanner package cache` step logs
   `Cache saved with key: scanner-package-cache-...` with no `Failed to save`
   warning — runs `32307634112`, `32312956716`, and `32325583672` all failed
   this, the last with `tar` exit 2;
2. all fourteen shards in that run computing one identical cache key despite
   differing image builds;
3. a following run whose shards report `cache=warm downloaded=false`;
4. `install base packages` durations on that warm run showing the tail observed
   in run `32285669639` no longer occurring.

Two runs are required and the first is still cold by definition. Read the save
step's log body rather than its conclusion: it carries `continue-on-error: true`
and reported success in run `32325583672` while saving nothing.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-cache-save
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-cache-save_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-cache-save`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-cache-save-review-*.md
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
   scripts/orchestration/clear-finished scanner-cache-save
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
   git add docs/review/scanner-cache-save-review-*.md
   git commit -m "docs(review): record scanner-cache-save review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-cache-save
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-cache-save` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed scanner-cache-save
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-cache-save
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-cache-save_finalized
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
scripts/orchestration/finalize scanner-cache-save
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-cache-save_finished
/tmp/decky-plugins-extended/scanner-cache-save_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
