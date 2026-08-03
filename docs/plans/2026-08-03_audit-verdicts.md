# Plan: Add a per-release audit entry point and a durable verdict store (audit-verdicts)

## Context

`audit_repository()` (`audit_plugins.py:2210`) audits exactly one release, chosen
internally by `find_best_release()` (line 2266). The catalog carries every eligible release per
plugin. Per-release gating and last-clean fallback are therefore impossible against the fork's
API — this sub-plan builds the interface `catalog-gate` consumes.

`AUDIT_ERROR` results are never cached (`audit_plugins.py:2502-2503`), so "keep the last known
verdict" has nothing to read from. That is what the verdict store is for.

Still no gating after this sub-plan. It adds the query surface; `catalog-gate` acts on it.

Ported code comes from the fork `zany130/decky-plugins-extended` @ `77cc3ca`, which is 13
commits ahead of this repo's `1f444b2` with no divergence. Re-clone it and
`git remote add upstream https://github.com/beallio/decky-plugins-extended` to reproduce
`git diff upstream/main..HEAD`. All fork line citations refer to that tree.

Full design rationale, the decision table, and the cross-cutting defect analysis live in
`docs/audit-gating-overview.md`. Read it before starting; this sub-plan is one slice of it.

### Where this sits in the sequence

Sub-plans execute in this order, each finalized into `dev` before the next begins:

1. `release-utils` — shared release selection
2. `audit-port` — the auditor itself, deps, cache correctness
3. `audit-scanners` — scanner correctness fixes
4. `audit-verdicts` — per-release entry point and verdict store
5. `catalog-gate` — the actual gate plus the rebuild-loop fix
6. `audit-ci` — workflows and docs
7. `plugin-additions` — the 13 new plugin entries

**This sub-plan is #4: `audit-verdicts`.**  Depends on `audit-port`. Independent of `audit-scanners`.

**Slug used throughout this plan:** `audit-verdicts`

---

## Orchestration Contract

**Slug:** `audit-verdicts`

**Plan file:**

```text
docs/plans/2026-08-03_audit-verdicts.md
```

**Implementation branch:**

```text
feat/audit-verdicts
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-verdicts_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-verdicts_finalized
```

**Review notes:**

```text
docs/review/audit-verdicts-review-*.md
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
git checkout -b feat/audit-verdicts
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_audit-verdicts.md
git commit -m "docs(plan): add audit-verdicts implementation plan"
```

---

## Implementation Tasks

Add to `audit_plugins.py`:

```python
def audit_release(repo_url, release, policy, exceptions,
                  cache_dir=CACHE_DIR, skip_cache=False) -> AuditReport
```

It audits the exact release passed in, rather than one chosen by `find_best_release()`.
Refactor `audit_repository()` (line 2210) to select a release and delegate to it, so there is
one audit path and no duplicated logic.

Add a verdict store — `.audit-cache/verdicts.json` — mapping
`repository -> release_id -> {classification, blocking_rule_ids, artifact_sha256,
audit_context_hash, audited_at}`. Write to it on every audit that reaches a real
classification. Never overwrite an existing entry with `AUDIT_ERROR`; that is what makes
fail-open-with-last-verdict work, since error results are not cached today
(`audit_plugins.py:2502-2503`). Write atomically (temp file + `os.replace`) — the generator,
the scheduled audit, and the PR audit can all touch this file, and a torn write loses every
verdict at once.

Add the adapter the generator will call:

```python
def classification_for(repository, release, verdicts) -> VerdictResult
```

Return a struct, not a bare string: `effective_classification` (what the gate acts on),
`audit_classification` (what this attempt actually produced), and `blocking_rule_ids`.
Task 7 needs the rule IDs to log *why* a release was dropped, and a bare string cannot carry
them.

When the current attempt yields `AUDIT_ERROR` and a previous non-error verdict exists, set
`effective_classification` to that previous verdict. When nothing is known **and** the audit
could not run, set both fields to `AUDIT_ERROR` — do **not** synthesise `PASS`. Task 7 already
admits `AUDIT_ERROR` into the catalog, so this fails open exactly as decided while keeping
"never audited" distinguishable from "audited clean" in the reports.

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

Follow `~/.claude/skills/orchestration-plan-author/references/verification-standards.md`.
Failure cases run before the negative control. Run everything with `set -o pipefail`.
Report actual output and tallies, not conclusions.

1. **`audit_release()` audits the release it was handed.** Pass a release that
   `find_best_release()` would *not* pick and assert the returned report's `release` field
   matches the one passed. Against a delegating stub that ignores its argument this fails.

2. **`audit_repository()` still behaves identically.** Its existing tests must pass unchanged
   after it is refactored to delegate. Record the tally.

3. **Errors never overwrite a good verdict.** Seed `verdicts.json` with `PASS` for a release,
   force `audit_release()` to return `AUDIT_ERROR`, and assert the stored entry is still
   `PASS`. Then assert the returned `VerdictResult` has `effective_classification == "PASS"`
   and `audit_classification == "AUDIT_ERROR"` — both fields, so a struct that collapses them
   cannot pass.

4. **First-seen failure is not laundered into PASS.** With no stored verdict and a forced
   error, assert **both** fields are `AUDIT_ERROR`. An implementation returning `PASS` here
   would make "never audited" indistinguishable from "audited clean".

5. **Blocking rule IDs survive the round trip.** Assert a `BLOCK` verdict's
   `blocking_rule_ids` are non-empty on the returned struct *and* present in `verdicts.json`
   after reload. `catalog-gate` needs them to log why a release was dropped.

6. **Atomic writes.** Kill the process mid-write (or monkeypatch `os.replace` to raise after
   the temp file is written) and assert `verdicts.json` still parses as valid JSON with its
   prior contents. A plain `open(...).write()` fails this.

7. **Negative control, runs last.** Full round trip on a clean fixture: audit two releases of
   one plugin, reload the store from disk, assert both verdicts and their rule IDs are
   readable and correct.

8. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- **Concurrency is untested.** Atomic writes are asserted, but no test runs the generator, the
  scheduled audit, and the PR audit against the store simultaneously.
- No catalog behaviour changes in this sub-plan; nothing here proves the gate works.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-verdicts
```

This writes:

```text
/tmp/decky-plugins-extended/audit-verdicts_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-verdicts`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-verdicts-review-*.md
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
   scripts/orchestration/clear-finished audit-verdicts
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
   git add docs/review/audit-verdicts-review-*.md
   git commit -m "docs(review): record audit-verdicts review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-verdicts
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-verdicts` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-verdicts
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-verdicts
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-verdicts_finalized
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
scripts/orchestration/finalize audit-verdicts
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-verdicts_finished
/tmp/decky-plugins-extended/audit-verdicts_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
