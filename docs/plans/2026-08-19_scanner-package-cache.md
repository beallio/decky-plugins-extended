# Plan: Cache Scanner Packages Across Shards And Runs (scanner-package-cache)

## Context

Every shard downloads the same packages from the same mirror on every run, and
the audit's reliability is therefore bounded by that mirror's worst-case
throughput. Fourteen shards times four scheduled runs a day is fifty-six
identical `clamav` downloads, and when the mirror is slow a shard fails and
blocks publication for the whole corpus.

Run `32285669639` (`workflow_dispatch` on `main` at `a679a08`, 2026-08-19)
measured `install base packages` on every shard:

```text
shards 0,3,5,6,7,9,10,11     4-19s    first attempt
shards 1,2,8                32-41s    first attempt
shard 12                   133s/124 -> retry  64s/0   recovered
shard 13                   136s/124 -> retry 122s/124  failed
```

Twelve shards finished in under 45 seconds; two hit a tail an order of magnitude
longer on the same image doing the same work. Budget allocation is already doing
its job — shard 12 recovered precisely because a long first attempt still left a
usable retry, and no phase reported budget-exhaustion status `125`, so nothing
was starved by the reserve table. Shard 13 received 131 then 117 seconds, 248
against the 180 the previous fixed budgets allowed, and still timed out twice.

`refresh base package index` took 5–21 seconds on every shard including the one
that failed, so index fetching is not the cost. The cost is downloading and
unpacking `clamav`.

More budget cannot fix this. The bootstrap already has 600 seconds inside a
720-second step cap, and shard 13's reserve of 320 seconds is the sum of the
later phases' declared minimums, so it cannot be reduced without risking
starvation elsewhere. Two prior plans made slowness survivable —
`scanner-bootstrap-retry-safety` made retries able to succeed at all, and
`scanner-budget-allocation` gave phases the unused budget and preserved retry
capacity. Both were necessary and both work. Neither removes the dependency on
a mirror we do not control.

This plan removes the repeated download. Packages are fetched once, cached, and
reused across shards and runs, so the common path performs no mirror download at
all and the slow tail stops being reachable for cached content.

Cache integrity is the governing constraint. GitHub Actions caches are writable
by any workflow run in the repository, so a restored cache is untrusted input.
`apt-get install` verifies each archive's checksum against the signed `Packages`
index before installing it, and that verification is what makes reuse safe.
`dpkg -i` performs no such check and must not be used to install cached
archives. A cache hit must never be able to install a package that a cold run
would have rejected.

Expected implementation scope is `scripts/install-security-scanners`, both audit
workflows, `tests/test_scanner_bootstrap.py`, the workflow contract tests, and
current documentation. Changing the worklist producer, the shard data plane,
aggregation, the twelve-minute scanner step cap, the 600-second bootstrap
budget, the phase allocation model, or `security-verdicts.json` is outside this
plan.

**Slug used throughout this plan:** `scanner-package-cache`

---

## Orchestration Contract

**Slug:** `scanner-package-cache`

**Plan file:**

```text
docs/plans/2026-08-19_scanner-package-cache.md
```

**Implementation branch:**

```text
feat/scanner-package-cache
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-package-cache_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-package-cache_finalized
```

**Review notes:**

```text
docs/review/scanner-package-cache-review-*.md
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
git checkout -b feat/scanner-package-cache
```

Commit this plan first:

```bash
git add docs/plans/2026-08-19_scanner-package-cache.md
git commit -m "docs(plan): add scanner-package-cache implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add failing contracts before changing behavior

- Add a bootstrap test proving a warm cache installs without contacting a
  mirror: with the archive directory pre-populated, the install phase must
  succeed and must not perform a package download.
- Add a test proving a cold cache still works exactly as it does today, and that
  the archives it produces are left where the workflow can save them.
- Add the integrity test, which is the one that matters most: a cached archive
  whose bytes do not match the signed index must be rejected and must not be
  installed. Prove the rejection comes from checksum verification rather than
  from the file merely being absent, and assert the run fails closed with a named
  phase rather than silently falling back.
- Add a test proving `dpkg -i` is not used to install cached archives.
- In `tests/test_workflow_security.py`, add contract cases for the new cache
  steps in both workflows: restore before scanner installation, a key bound to
  the runner image and the package set, and no unpinned action.

Record node IDs and failing assertions before implementing.

### Task 2 — Fetch base packages into a cacheable archive directory

- Give the bootstrap an explicit archive directory under the workspace, not the
  system `/var/cache/apt/archives`, so the workflow can cache it without root
  and without capturing unrelated system state. Make its path configurable by
  environment variable with a documented default, as the existing
  `TRIVY_KEYRING_PATH` and `CLAMAV_DB_GLOB` are.
- Install with APT pointed at that directory, so APT reuses any archive already
  present and downloads only what is missing. Keep `apt-get install` as the
  installing command: its checksum verification against the signed index is the
  security property that makes cache reuse safe. Do not install cached archives
  with `dpkg -i`, and do not disable or weaken APT's verification with any
  option that permits unauthenticated or unverified packages.
- Preserve every existing property: named UTC phases, budget-derived allocation
  with retry splitting, dpkg-lock waiting with its fail-closed `fuser` check,
  process-group reaping, retry only for idempotent work, and fail-closed exit.
- Report cache effectiveness observably. The install phase must record whether it
  downloaded anything, so a run's log shows whether the cache was warm. A warm
  run that still downloads is a signal worth being able to see.

### Task 3 — Wire the package cache into both workflows

Update `.github/workflows/plugin-security-audit.yml` and
`.github/workflows/scheduled-security-audit.yml` in lockstep, for all three
places the scanner bootstrap runs.

- Restore the archive directory before `Install required security scanners` and
  save it afterwards, following the repository's existing
  `actions/cache/restore` and `actions/cache/save` pattern and pinning to the
  same commit SHA already used.
- Key the cache on the runner image identifier, the exact base package set, and
  the bootstrap script's own hash, so a change to any of them cannot serve a
  stale archive set. Provide a restore-key prefix so a near-miss still warms
  most of the download.
- Avoid fourteen shards racing to save the same key. Either save from a single
  designated job, or make the key shard-independent and accept that only the
  first save wins — whichever you choose, the log must not fill with save
  conflicts and a failed save must not fail the shard.
- Restoring must be best-effort: a cache miss, a corrupt entry, or an
  unavailable cache service degrades to a cold install and must never fail the
  step by itself.
- Do not change the twelve-minute scanner step cap, the fourteen-shard topology,
  job dependencies, credential boundaries, `persist-credentials: false` on
  worker checkouts, or any existing cache used for audit results.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` to describe the package
cache: what is cached, how the key is derived, and — most importantly — that a
restored cache is untrusted input whose archives are still verified against the
signed index before installation, so a cache hit cannot install anything a cold
run would reject.

State plainly that this removes the repeated download on the common path and
does not guarantee scanner setup: a cold cache still depends on the mirror, and
a shard that cannot install its scanners still fails closed and blocks
publication.

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
  tests/test_scanner_bootstrap.py \
  tests/test_workflow_security.py \
  2>&1 | tee /tmp/decky-plugins-extended/scanner-package-cache-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

Record the specific expected failures. The warm-cache case must fail because no
archive directory exists yet, not because of a fixture error.

### 2. Prove the integrity property explicitly

This is the check that decides whether the plan is safe to ship. Demonstrate,
with real APT semantics in the fake-tool harness, that:

- a cached archive matching the signed index is installed without a download;
- a cached archive whose bytes have been altered is rejected, the run fails
  closed with its named phase, and the tampered archive is never installed;
- no code path installs a cached archive with `dpkg -i`;
- no APT invocation passes an option permitting unauthenticated or unverified
  packages.

Save the transcript under
`/tmp/decky-plugins-extended/scanner-package-cache-integrity.log`. A plan that
cannot demonstrate the tamper rejection must not be marked complete.

### 3. Exercise the failure controls, then the valid controls

Prove each fails closed or degrades correctly:

- a cache miss performs a normal cold install and still succeeds;
- an unreadable or partially populated archive directory degrades to a cold
  install rather than failing the step;
- a mirror failure on a cold path still fails closed with its named phase;
- every previously established control still holds: budget exhaustion reports
  `125`, a phase timeout reports `124` and reaps its process group, the
  dpkg-lock guard fails closed without `fuser`, the Trivy signing-key
  fingerprint is verified, Semgrep `1.132.0` is enforced, and the ClamAV
  database check still runs.

Then the valid controls: a warm run installs with no download and records that
it did not download; a cold run populates the archive directory; and both
workflows' contract tests pass with the new cache steps.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that
installs cached archives without checksum verification — for example by
switching the install to `dpkg -i` or by adding an option that permits
unverified packages — and require the tamper-rejection test to fail because of
it. Save the diff to
`/tmp/decky-plugins-extended/scanner-package-cache-mutation.patch`, reverse it
with `git apply -R`, rerun to exit 0, and verify `git diff --exit-code`. Do not
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
test/subtest tallies. Confirm the worktree is clean and `security-verdicts.json`
has not changed.

Do not invoke real APT, ClamAV refresh, Trivy installation, or Semgrep
installation locally. The fake-tool harness is the only permitted local
execution of the installer.

### Deferred verification

Local tests can prove cache reuse, tamper rejection, and degradation to a cold
install. They cannot prove hosted cache hit rates or mirror throughput. Defer
until the user authorizes a run on the default branch:

1. a first run that populates the cache, followed by a second run in which the
   install phase reports no download on every shard;
2. `install base packages` durations on a warm run that show the 130-second-plus
   tail observed in run `32285669639` no longer occurring;
3. all fourteen shards completing scanner setup inside the unchanged
   twelve-minute cap;
4. aggregation publishing on fourteen triples. This has never happened. Runs
   `32222340066`, `32275727649`, and `32285669639` reached aggregation with
   thirteen, four, and thirteen shards respectively and all three correctly
   refused. The verdict merge, snapshot, and publish path remains unexercised on
   real evidence.

A single warm green run does not prove the mirror dependency is gone: the cold
path still exists on the first run after any key change, and mirror throughput
has already been observed to vary by an order of magnitude within hours.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-package-cache
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-package-cache_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-package-cache`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-package-cache-review-*.md
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
   scripts/orchestration/clear-finished scanner-package-cache
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
   git add docs/review/scanner-package-cache-review-*.md
   git commit -m "docs(review): record scanner-package-cache review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-package-cache
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-package-cache` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed scanner-package-cache
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-package-cache
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-package-cache_finalized
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
scripts/orchestration/finalize scanner-package-cache
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-package-cache_finished
/tmp/decky-plugins-extended/scanner-package-cache_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
