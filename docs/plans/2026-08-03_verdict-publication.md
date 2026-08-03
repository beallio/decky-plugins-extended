# Plan: Make audit verdicts reach the Cloudflare build so the catalog gate actually fires (verdict-publication)

## Context

**The catalog gate does not fire in production.** Everything `catalog-gate` (#5) built works,
and is mutation-tested, but it is not connected to anything at runtime.

The chain breaks here:

- The live catalog is **not** built by GitHub Actions. `generate.yml:25-27` says so directly:
  "Cloudflare Pages runs the generator itself on every push, so this job does not publish
  anything." The Actions `build` job is a pre-flight check.
- Cloudflare Pages builds from a **fresh clone** and runs `generate_json.py`.
- `generate_json.py` calls `load_verdicts()`, which reads
  `.audit-cache/verdicts.json` (`audit_plugins.py:60-61, 2797-2801`).
- `.audit-cache/` is gitignored (`.gitignore:7`), so it is **not in the clone**.
- `load_verdicts()` returns `{}`; `classification_for` yields `AUDIT_ERROR` for every release;
  `AUDIT_ERROR` ships under the fail-open policy. Nothing is ever excluded.

Every `catalog-gate` test seeds or mocks the verdict store directly, so the whole suite passes
while production does nothing. The mechanism was proven; the wiring was never checked.

This is worse than having no gate, because the README and the workflows now advertise one.

### What must change

The durable verdict store has to be a **tracked file in the repository**, so a fresh clone
carries it. That is a different thing from `.audit-cache/`, which is an ephemeral report cache
that is fine to lose and correctly gitignored. Keep them separate — do not un-ignore
`.audit-cache/`.

### Facts established on `dev`, do not re-derive

- A verdict record holds only `classification`, `blocking_rule_ids`, `artifact_sha256` and
  `audited_at` (`audit_plugins.py:2852-2857`). No evidence strings, no secrets. Safe to commit.
- `generate.yml`'s push trigger filters on `additional_plugins.txt`, `generate_json.py`,
  `pyproject.toml`, `uv.lock` (`generate.yml:4-10`). A verdicts file is not in that list.
- Cloudflare rebuilds on **every** push to the deployed branch, so committing verdicts is
  itself sufficient to refresh the catalog. No deploy-hook change is needed.
- `scheduled-security-audit.yml` currently declares `permissions: contents: read` (line 23-24).

---

**Slug used throughout this plan:** `verdict-publication`

---

## Orchestration Contract

**Slug:** `verdict-publication`

**Plan file:**

```text
docs/plans/2026-08-03_verdict-publication.md
```

**Implementation branch:**

```text
feat/verdict-publication
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/verdict-publication_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/verdict-publication_finalized
```

**Review notes:**

```text
docs/review/verdict-publication-review-*.md
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
git checkout -b feat/verdict-publication
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_verdict-publication.md
git commit -m "docs(plan): add verdict-publication implementation plan"
```

---

## Implementation Tasks

### Task 1 — Move the durable verdict store to a tracked path

Introduce a tracked file — `security-verdicts.json` at the repository root — as the durable
store, distinct from the ephemeral `.audit-cache/`.

- `load_verdicts()` must read the tracked file. Keep a fallback read of the old
  `.audit-cache/verdicts.json` location so an existing local cache is not silently ignored,
  but the tracked file wins when both exist.
- `_record_verdict()` must write the tracked file.
- Leave `.audit-cache/` gitignored and continue using it for cached audit **reports**. Only
  the verdict store moves.
- Do not change the record shape. `catalog-gate` and `audit-verdicts` both read these fields.

### Task 2 — Write the file deterministically

The file is committed every six hours, so identical state must produce identical bytes or
every run generates a spurious commit and a spurious Cloudflare rebuild.

- Serialise with sorted keys at every level and a fixed indent, with a trailing newline.
- `audited_at` is a timestamp and will differ on every audit even when the verdict does not.
  **Do not** update `audited_at` when the classification, rule IDs and artifact hash are all
  unchanged — otherwise determinism is impossible. Preserve the original timestamp in that
  case.
- Keep the atomic-write behaviour from `audit-verdicts` (`_write_verdicts_atomic`, temp file
  plus `os.replace`). It applies to the new path too.

### Task 3 — Commit the verdict store from the scheduled audit

In `.github/workflows/scheduled-security-audit.yml`:

- Raise the permission to `contents: write`, scoped to the job that needs it, not the whole
  workflow if the file allows per-job scoping.
- After the audit, commit `security-verdicts.json` **only when it actually changed**
  (`git diff --quiet` before committing). An unchanged run must produce no commit.
- Commit only that one path. Never `git add -A`.
- Use a clear author and a message naming how many verdicts changed.
- Handle the race: another run may have pushed since checkout. Pull with rebase and retry once
  before failing. Do not force-push.

Do not add the verdicts path to `generate.yml`'s push-path filter. Cloudflare already rebuilds
on every push, and adding it would run the Actions pre-flight build on every verdict change for
no benefit.

### Task 4 — Prove the production path, not just the mechanism

This is the task the sub-plan exists for. Add a test that reproduces the **Cloudflare
build shape**: a clean checkout with **no `.audit-cache/` directory at all**, a
`security-verdicts.json` present as a tracked file containing a `BLOCK` verdict, and
`generate_json.py` run against it.

Assert the blocked release is absent from both catalogs.

Run this test against `dev`'s code first. It must **fail** there — that failure is the bug this
sub-plan fixes, and a test that cannot demonstrate it is not evidence of anything.

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
and tallies, not conclusions. Do not push, and do not create GitHub repositories.

1. **Demonstrate the bug first.** On `dev`, with no `.audit-cache/` present, generate the
   catalog for a fixture whose newest release has a `BLOCK` verdict recorded, and record that
   the blocked release **is present** in the output. That is the current production behaviour.
   Keep the recorded output; it is the before half of step 5.

2. **The tracked file is read when `.audit-cache/` is absent.** Assert `load_verdicts()`
   returns the seeded verdicts with no `.audit-cache/` directory on disk. Delete the directory
   in the test rather than assuming it is missing.

3. **Determinism.** Run the writer twice over unchanged state and assert the file bytes are
   **identical**, including that `audited_at` did not move. Then change one classification and
   assert the bytes do change. Both halves are required — a writer that never updates anything
   passes the first half alone.

4. **No unchanged-state commit.** Simulate the workflow's commit step against unchanged
   verdicts and assert `git diff --quiet` reports no change, so no commit would be made. Then
   change a verdict and assert it reports a change. If this only ever runs green, a spurious
   commit and Cloudflare rebuild fires every six hours forever.

5. **Negative control — the gate now fires in a fresh-clone shape (runs last).** The Task 4
   test: no `.audit-cache/`, tracked `security-verdicts.json` with a `BLOCK`, run the
   generator, assert the blocked release's normalised version and artifact hash are absent from
   both `plugins.json` and `testing_plugins.json`, and that the fallback release is at
   `versions[0]`. Report this next to step 1's recorded before-output.

6. **Mutation test.** Point `load_verdicts()` back at `.audit-cache/verdicts.json` only, and
   confirm the step 5 test goes red. This proves the test pins the wiring rather than the gate
   logic that `catalog-gate` already covers.

7. **Nothing sensitive is committed.** Assert the serialised store contains no `evidence` key
   and no value matching a secret shape, across a fixture whose audit produced a
   `SECRET_*` finding. The record shape excludes evidence today; this pins it so a later
   field addition cannot leak.

8. **Existing behaviour intact.** `catalog-gate` and `audit-verdicts` tests must still pass
   unchanged. Record the tally. Baseline entering this sub-plan is whatever
   `secret-rule-precision` (#9) left; report both numbers.

9. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.

### Explicitly not verified

- **No end-to-end Cloudflare deploy is exercised.** The tests reproduce the fresh-clone shape;
  they do not run a real Pages build. Do not push or trigger a deploy to prove this — the
  fresh-clone test is the evidence, and a real deploy is a promotion decision for the repo
  owner.
- **The first real run will produce a large first commit** as every plugin gets an initial
  verdict. That is expected, not a determinism failure.
- Concurrent writes from the PR audit and the scheduled audit are handled by rebase-and-retry,
  not by locking. A sustained collision could still fail a run; it will not corrupt the file,
  because writes stay atomic.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished verdict-publication
```

This writes:

```text
/tmp/decky-plugins-extended/verdict-publication_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer verdict-publication`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/verdict-publication-review-*.md
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
   scripts/orchestration/clear-finished verdict-publication
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
   git add docs/review/verdict-publication-review-*.md
   git commit -m "docs(review): record verdict-publication review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished verdict-publication
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer verdict-publication` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed verdict-publication
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize verdict-publication
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/verdict-publication_finalized
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
scripts/orchestration/finalize verdict-publication
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/verdict-publication_finished
/tmp/decky-plugins-extended/verdict-publication_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
