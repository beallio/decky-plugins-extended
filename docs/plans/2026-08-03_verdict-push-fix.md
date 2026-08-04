# Plan: Make the scheduled verdict publish survive a dirty working tree (verdict-push-fix)

## Context

**The scheduled verdict publication has never worked.** Its first real run, `30870480232` at
2026-08-04T02:00Z, failed. The next run at 06:00Z will fail identically unless this lands.

The audit itself was fine: 41 repositories scanned in about 12 minutes, verdicts produced, and
the commit created — `chore(security): publish 40 changed verdicts`, 784 insertions. Then:

```
[main 97fa885] chore(security): publish 40 changed verdicts
 1 file changed, 784 insertions(+)
error: cannot pull with rebase: You have unstaged changes.
error: Please commit or stash them.
##[error]Process completed with exit code 128.
```

### Cause

The publish step in `.github/workflows/scheduled-security-audit.yml` stages exactly one path —
`git add -- security-verdicts.json` — which is deliberate and should stay that way. It then
commits and runs `git pull --rebase`.

`git pull --rebase` refuses to run when the working tree has **any** unstaged modification, not
merely a conflicting one. The audit run leaves other files modified, so the pull aborts, the
push never happens, and the commit dies with the runner.

`security-reports/` and `.audit-cache/` are both gitignored (`.gitignore:6-7`), so neither is
the culprit. The specific dirtying file is **not identifiable from the run log** — do not guess
at it. The fix must be correct regardless of which file it is, and Task 2 exists so the next
failure is diagnosable.

### Blast radius

Contained. The commit was made on a disposable runner and discarded with it. Nothing was
pushed, nothing was corrupted, and `security-verdicts.json` on `main` still holds only its
single hand-written record. The cost is that the store is not being populated, so
`catalog-gate` has no verdicts to act on and nothing is being excluded.

### What the review missed

Worth recording. `verdict-publication` (#10) verified that the step makes no commit when
nothing changed, and that it stages only one path. It never exercised the case where the audit
leaves other files dirty — which is the normal case, not an edge case. The fresh-clone test
proved the reading side end to end; nothing proved the writing side at all.

---

**Slug used throughout this plan:** `verdict-push-fix`

---

## Orchestration Contract

**Slug:** `verdict-push-fix`

**Plan file:**

```text
docs/plans/2026-08-03_verdict-push-fix.md
```

**Implementation branch:**

```text
feat/verdict-push-fix
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/verdict-push-fix_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/verdict-push-fix_finalized
```

**Review notes:**

```text
docs/review/verdict-push-fix-review-*.md
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
git checkout -b feat/verdict-push-fix
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_verdict-push-fix.md
git commit -m "docs(plan): add verdict-push-fix implementation plan"
```

---

## Implementation Tasks

### Task 1 — Publish from a clean tree

After the verdict commit succeeds, discard every other working-tree modification before
synchronising with the remote. The verdict is already committed at that point, and everything
else on the runner is disposable build output.

Suggested shape, but use your judgement on the exact commands:

```
git add -- security-verdicts.json
git commit -m "..."
git reset --hard HEAD          # verdict is committed; drop all other tree noise
git fetch origin "$GITHUB_REF_NAME"
git rebase "origin/$GITHUB_REF_NAME"
git push origin "HEAD:$GITHUB_REF_NAME"
```

Constraints:

- **Keep staging a single path.** `git add -- security-verdicts.json` must remain; do not
  switch to `git add -A`. The reset happens *after* the commit precisely so the narrow add is
  preserved.
- `git reset --hard` must run **only after** a successful commit. If the commit fails, the reset
  would destroy the audit's output with nothing recorded — guard the ordering explicitly.
- Keep the existing single rebase-and-retry on a losing race, and keep the `git diff --quiet`
  early exit when nothing changed. Never force-push.
- Do not weaken the `permissions: contents: write` scoping.

### Task 2 — Leave a diagnostic

The dirtying file could not be identified from the failed run. Before synchronising, print
`git status --porcelain` so the next failure is diagnosable without archaeology.

Keep it to the status output only. Do not print file contents — this job handles third-party
plugin source and audit output.

### Task 3 — Do not let the audit's own output dirty the tree, if it does

If Task 2's diagnostic (run locally against a real audit) shows the audit writing a tracked
file it should not, fix that at the source rather than relying on the reset. Report what you
found either way; "nothing else was dirty locally" is a useful result, because it means the
dirtying is runner-specific.

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
Failure cases run before the negative control. Run with `set -o pipefail`. Report actual output
and tallies, not conclusions. **Do not push to any remote and do not trigger a workflow run.**

The point of this sub-plan is a shell sequence, so it must be tested as one — against real git
repositories in a temporary directory, not by reading the YAML.

1. **Reproduce the failure first.** Build a fixture: a bare repo as `origin`, a clone, a
   committed `security-verdicts.json`. Modify the verdicts file **and** a second tracked file.
   Run the **current** published sequence (`add` one path, `commit`, `pull --rebase`) and record
   the exact failure — expect `cannot pull with rebase: You have unstaged changes`. A fix whose
   failure case was never observed is not evidence.

2. **The fixed sequence publishes with a dirty tree — the negative control.** Same fixture, new
   sequence. Assert it exits 0 and that `origin` now contains the new verdict commit. This is
   the case that is failing in production every six hours.

3. **The narrow staging survived.** In the fixture, dirty a second tracked file, run the fixed
   sequence, and assert the pushed commit touches **only** `security-verdicts.json`. If the
   implementation reached for `git add -A`, this fails. It must.

4. **Unchanged verdicts still publish nothing.** Leave `security-verdicts.json` untouched, dirty
   another file, run the sequence, and assert no commit was created and `origin` is unchanged.
   The `git diff --quiet` early exit must survive.

5. **A losing race still resolves.** Push a competing commit to `origin` between the clone and
   the push, run the sequence, and assert it rebases and lands without force-pushing. Assert the
   competing commit is still present afterwards.

6. **A failed commit does not destroy the audit output.** Force the commit to fail — for example
   by staging nothing while the diff guard is bypassed — and assert `git reset --hard` did not
   run and the modified `security-verdicts.json` still exists. This is the dangerous ordering
   the plan warns about; it must be proven, not assumed.

7. **The diagnostic prints and leaks nothing.** Assert the step emits `git status --porcelain`
   output, and that it contains no file contents — only paths and status codes.

8. **Mutation test (runs last).** Remove the `git reset --hard` and confirm step 2 goes red.
   Then restore.

9. **Full suite and gates.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.
   Baseline entering this sub-plan is 242 passed / 21 subtests. Also assert every action in
   `.github/workflows/` is still SHA-pinned and no secret is interpolated into a `run:` block,
   since `audit-ci`'s tests cover that and this sub-plan edits a workflow.

### Explicitly not verified

- **No real scheduled run is exercised.** The fixture reproduces the git sequence faithfully;
  it does not prove GitHub's runner behaves identically. The real proof is the next scheduled
  run at 06:00Z, which is observation rather than verification.
- The file that dirties the tree on the runner is still unidentified. The fix is robust to any
  file; Task 2 exists so it can be named next time.
- This changes publication only. No classification, catalog output or gate behaviour should
  differ.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished verdict-push-fix
```

This writes:

```text
/tmp/decky-plugins-extended/verdict-push-fix_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer verdict-push-fix`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/verdict-push-fix-review-*.md
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
   scripts/orchestration/clear-finished verdict-push-fix
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
   git add docs/review/verdict-push-fix-review-*.md
   git commit -m "docs(review): record verdict-push-fix review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished verdict-push-fix
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer verdict-push-fix` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed verdict-push-fix
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize verdict-push-fix
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/verdict-push-fix_finalized
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
scripts/orchestration/finalize verdict-push-fix
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/verdict-push-fix_finished
/tmp/decky-plugins-extended/verdict-push-fix_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
