# Plan: Survive Renamed Plugin Repositories (repository-rename-resilience)

## Context

The scheduled security audit is dead for the whole corpus because one configured
repository was renamed.

Run `32219524259` (`workflow_dispatch` on `main` at `082e972`, 2026-08-19) failed
ten seconds in, during the worklist producer:

```text
ERROR Failed to prepare audit worklist: Repository metadata mismatch for
https://github.com/danielcopper/decky-romm-sync: 'danielcopper/romm-tender'
```

`danielcopper/decky-romm-sync` has been renamed to `danielcopper/romm-tender`.
GitHub answers the metadata request through its rename redirect, so the response
carries the new `full_name`. `_normalise_worklist_item()` in `audit_worklist.py`
compares that name against the configured URL, raises on the mismatch, and the
exception propagates out of `prepare_audit_worklist()` as a run-global failure
that produces no worklist at all.

The fail-closed machinery around it behaved correctly and must be preserved: all
fourteen workers were skipped by `needs: prepare-audit-worklist`, the aggregate
job's `Require prepared worklist success` guard failed before any download, and
every publication step — verdict-delta merge, verdict snapshot, verdict publish,
enforcement — was skipped. Nothing partial was published and the verdict store
was untouched.

The defect is blast radius, not the check itself. One stale URL out of the 41
repositories in `additional_plugins.txt` takes down the audit for the other 40.
The identity check must stay: the verdict store is keyed by repository URL, and
silently adopting whatever a redirect resolves to would let a renamed-then-
re-registered name (the repo-jacking pattern) be audited and recorded under the
configured identity. Following the redirect is therefore *not* an acceptable
fix. Adopting a new upstream name must remain an explicit, reviewed edit to
`additional_plugins.txt`.

This plan does two things: correct the one stale URL so the corpus audits again,
and make a repository-identity mismatch a per-repository failure that is loudly
visible without preventing every other repository from being audited and
published.

The existing plan-level contracts stay intact. In particular the exact-coverage
aggregation contract from `docs/plans/2026-08-18_quota-safe-security-audit.md`
must continue to hold: the union of identity-complete shard reports must equal
the worklist identity set exactly, with one common fingerprint, and a repository
that fails identity validation must not become a silent hole in that accounting.

Expected implementation scope is `additional_plugins.txt`, `audit_worklist.py`,
`audit_plugins.py`, focused tests, and current documentation. Changing the
worklist producer's REST/Git transport, the API budget, the scanner bootstrap,
the workflows' job topology, catalog generation, the public catalog schemas, or
`security-verdicts.json` is outside this plan.

**Slug used throughout this plan:** `repository-rename-resilience`

---

## Orchestration Contract

**Slug:** `repository-rename-resilience`

**Plan file:**

```text
docs/plans/2026-08-18_repository-rename-resilience.md
```

**Implementation branch:**

```text
feat/repository-rename-resilience
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/repository-rename-resilience_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/repository-rename-resilience_finalized
```

**Review notes:**

```text
docs/review/repository-rename-resilience-review-*.md
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
git checkout -b feat/repository-rename-resilience
```

Commit this plan first:

```bash
git add docs/plans/2026-08-18_repository-rename-resilience.md
git commit -m "docs(plan): add repository-rename-resilience implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add failing contracts before changing runtime behavior

Write the red tests first, and record their node IDs and failing assertions
before implementing.

- In `tests/test_audit_worklist.py`, add producer cases proving that one
  repository whose metadata `full_name` does not match its configured URL no
  longer aborts preparation: the other repositories still produce their normal
  items, the worklist still validates and fingerprints, and the mismatch is
  carried in the document rather than discarded.
- Add a case proving the mismatch is never silently adopted: the produced
  worklist must contain no item whose identity uses the redirect target
  (`danielcopper/romm-tender` in the observed failure), and no verdict key may
  ever be produced under the configured URL from redirected metadata.
- Add cases for a repository whose metadata is missing `full_name` entirely, and
  for one whose metadata request itself fails, so both remain per-repository
  outcomes rather than run-global ones.
- In `tests/test_audit_plugins.py` and `tests/test_enforcement_workflow.py`, add
  aggregation cases proving a repository-level error is surfaced as
  `AUDIT_ERROR` with run exit 4, that the other repositories' verdict deltas are
  still merged and published, and that exact coverage still validates.
- In `tests/test_audit_documentation.py`, assert the configured repository list
  contains no URL that the audit would reject for identity mismatch, so a future
  stale entry is caught by the test suite rather than by a dead scheduled run.

The initial focused run must fail because the current producer raises run-global.
Verify the failures are the missing behavior rather than fixture errors.

### Task 2 — Correct the stale repository URL

Update the `danielcopper/decky-romm-sync` entry in `additional_plugins.txt` to
`https://github.com/danielcopper/romm-tender`.

Confirm before editing that the new name is the rename target of the configured
repository and not an unrelated project that claimed a freed name: check that
the repository's owner is unchanged, that its release history is continuous with
what the tracked verdict store already records for the old URL, and record that
evidence in the commit message.

Keep the file's existing ordering and formatting conventions. Do not edit
`security-verdicts.json`; existing verdicts keyed to the old URL are historical
records and are not this plan's concern.

### Task 3 — Make a repository-identity mismatch per-repository

Change the producer so a repository whose identity cannot be validated degrades
to a visible per-repository failure instead of aborting the run.

- Keep the strict comparison in `_normalise_worklist_item()`. Do not follow,
  canonicalize toward, or otherwise adopt the redirect target. The check's
  security purpose is to prevent a re-registered name from being audited under
  the configured identity, and that property must survive this change.
- Extend the worklist payload with a deterministically ordered
  `repository_errors` list. Each entry binds the canonical configured repository
  URL to one redacted, bounded reason string. It must be covered by the existing
  canonical-JSON fingerprint, must be validated as strictly as every other
  payload field, and a valid document with zero errors must serialize
  identically to today's so existing fingerprints do not churn without cause.
- A repository that lands in `repository_errors` contributes no work items. The
  remaining repositories are enumerated, resolved, and sharded exactly as they
  are today.
- Preserve run-global failure for conditions that are genuinely run-global:
  malformed payloads, serialization failures, an exhausted API budget, and a
  repository-wide Git transport failure during tag resolution. Only per-
  repository identity/metadata outcomes become entries.
- The producer must still print exactly one `worklist_fingerprint=<64-hex>` line
  on stdout and send every diagnostic to stderr. It must log each repository
  error at warning level or higher so the preparation job's log names the
  offending repository.

### Task 4 — Surface repository errors through aggregation without weakening coverage

- Teach aggregation to read `repository_errors` from the expected worklist and
  emit one `AUDIT_ERROR` report per entry in the aggregate report, so the run
  exits 4 under the existing precedence and the failure is visible in published
  evidence rather than only in a producer log.
- These synthetic reports carry no release identity, produce no verdict-delta
  record, and must never write to the verdict store. A repository in
  `repository_errors` must not have any existing verdict removed, rewritten, or
  marked stale.
- The exact-coverage contract is unchanged: the union of identity-complete shard
  report identities must still equal the worklist item identity set exactly.
  Repository errors are accounted separately and must not be able to mask a
  missing, unexpected, duplicated, or wrong-shard release identity. Add a test
  proving a run with one repository error still rejects a missing release
  identity elsewhere in the corpus.
- Preserve deterministic aggregate ordering, the documented 4/2/3/0 exit
  precedence, PR enforcement after safe publication, and scheduled atomic
  verdict publication.

Exercise the real workflow aggregate shell body, not only helper functions.

### Task 5 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` to state that a
repository whose upstream identity no longer matches its configured URL is a
per-repository `AUDIT_ERROR` that does not stop the rest of the corpus, that the
audit never follows a rename redirect, and that adopting a new upstream name is
an explicit reviewed edit to `additional_plugins.txt`.

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

Every check below must report its real exit status and tallies. A missing
fixture or command is a failure, not an implicit pass.

### 1. Record the red phase

After adding the Task 1 tests and before implementing their behavior:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_audit_worklist.py \
  tests/test_audit_plugins.py \
  tests/test_enforcement_workflow.py \
  tests/test_audit_documentation.py \
  2>&1 | tee /tmp/decky-plugins-extended/repository-rename-resilience-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

Record the specific expected failures from the saved log. Exit 0, no new
collected nodes, or a collection/setup error does not establish the red phase.

### 2. Reproduce the observed production failure as a test

Add and run a producer test that reconstructs run `32219524259`'s exact
condition: a corpus in which one repository's metadata returns a `full_name`
that differs from its configured URL. Require that preparation now succeeds,
that the other repositories produce their normal items, that the mismatched
repository contributes zero items and exactly one `repository_errors` entry, and
that no produced identity references the redirect target.

### 3. Exercise the failure controls, then the valid controls

Prove each of these fails closed with its specific diagnostic and no unsafe
output:

- a worklist whose `repository_errors` list is reordered, duplicated, or altered
  without updating the fingerprint;
- an aggregation whose expected worklist declares a repository error the shard
  evidence does not account for;
- a run with one repository error that also omits one expected release identity
  elsewhere — this must still be rejected as a coverage failure;
- a genuinely run-global condition (exhausted API budget, Git transport failure
  during tag resolution) still producing no worklist and exit 1.

Then run the valid controls: a full multi-repository fixture with zero
repository errors producing a byte-identical document to today's for the same
inputs, and a fixture with one repository error producing exit 4 while every
other repository's verdict delta still merges.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation to the
implementation — not the tests — that makes the producer adopt the redirect
target instead of recording a repository error. Run the identity tests and
require them to fail because the mutation was detected. Save the diff to
`/tmp/decky-plugins-extended/repository-rename-resilience-mutation.patch`,
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
test/subtest tallies. Confirm the worktree is clean and that
`security-verdicts.json` has not changed.

### Deferred verification

Do not claim local tests prove hosted behavior. This plan does not push, merge,
or start external workflows. Defer until the user authorizes a run on the
default branch:

1. a scheduled or dispatched run whose producer completes, uploads one worklist
   artifact, and names any repository error in its job log;
2. fourteen workers consuming that fingerprint with exact aggregate coverage;
3. confirmation that a corpus containing one renamed repository still publishes
   verdicts for every other repository and exits 4 rather than failing the
   producer.

The quota behavior of the worklist data plane also remains unproven on hosted
infrastructure: run `32219524259` failed before reaching it, so no run has yet
exercised the full fourteen-shard path end to end.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished repository-rename-resilience
```

This writes:

```text
/tmp/decky-plugins-extended/repository-rename-resilience_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer repository-rename-resilience`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/repository-rename-resilience-review-*.md
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
   scripts/orchestration/clear-finished repository-rename-resilience
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
   git add docs/review/repository-rename-resilience-review-*.md
   git commit -m "docs(review): record repository-rename-resilience review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished repository-rename-resilience
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer repository-rename-resilience` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed repository-rename-resilience
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize repository-rename-resilience
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/repository-rename-resilience_finalized
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
scripts/orchestration/finalize repository-rename-resilience
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/repository-rename-resilience_finished
/tmp/decky-plugins-extended/repository-rename-resilience_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
