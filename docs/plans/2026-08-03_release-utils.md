# Plan: Extract shared release-selection helpers and fix testing-channel semver (release-utils)

## Context

`generate_json.py` and (later) the auditor both need to answer "which release counts?".
Today that logic is inline in `generate_json.py` only. Extracting it first means the auditor
lands on top of a shared, already-corrected implementation rather than duplicating it.

The fork's extraction is sound but carries one real bug, described below. Fix it here, before
anything depends on it.

`main()` loops releases at `generate_json.py:385` and appends to `testing_versions` (line 391)
and, for non-prereleases, `stable_versions` (line 394). `sort_versions()` at lines 400-401
orders both.

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

**This sub-plan is #1: `release-utils`.**  Nothing depends on the auditor yet; this touches only release selection.

**Slug used throughout this plan:** `release-utils`

---

## Orchestration Contract

**Slug:** `release-utils`

**Plan file:**

```text
docs/plans/2026-08-03_release-utils.md
```

**Implementation branch:**

```text
feat/release-utils
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/release-utils_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/release-utils_finalized
```

**Review notes:**

```text
docs/review/release-utils-review-*.md
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
git checkout -b feat/release-utils
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_release-utils.md
git commit -m "docs(plan): add release-utils implementation plan"
```

---

## Implementation Tasks

- Copy the fork's `plugin_release_utils.py`. Exports: `normalize_version` (line 29),
  `parse_semver` (44), `version_sort_key` (61), `has_exactly_one_zip` (81), `get_zip_asset`
  (88), `select_best_release` (95).
- Replace the equivalent inline logic in `generate_json.py` with calls to them, matching the
  fork's call sites.
- **Fix before porting:** `select_best_release(releases, allow_prerelease=True)` returns a
  stable release even when a higher prerelease exists. That is wrong for the testing
  catalog and is baked into a fork test at `tests/test_audit_plugins.py:1941-1947`. With
  `allow_prerelease=True` it must return the highest semver release, prerelease or not.
  Do not port that test as written.
- Note the one intentional behaviour change: `has_exactly_one_zip` matches `.zip`
  case-insensitively, so a release shipping `Plugin.ZIP` becomes eligible where it was not
  before.

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

1. **The prerelease fix actually changed behaviour.** Write a test asserting
   `select_best_release([stable 1.0.0, prerelease 2.0.0-beta.1], allow_prerelease=True)`
   returns `2.0.0-beta.1`. Run it against the fork's unmodified helper first and record the
   failure — the fork returns `1.0.0` and encodes that in
   `tests/test_audit_plugins.py:1941-1947`. Only then apply the fix.

2. **Case-insensitive ZIP matching.** Assert `has_exactly_one_zip()` accepts a release whose
   sole asset is `Plugin.ZIP` and still rejects one with two `.zip` assets. The second half is
   what stops this being a one-way "accept everything" change.

3. **No catalog output regression (negative control, runs last).** Capture
   `plugins.json`/`testing_plugins.json` from a fixture run on `dev` before the change, run
   again after, and diff. The only permitted difference is releases newly eligible via the
   `.ZIP` casing rule. Any other delta means the extraction changed behaviour and must be
   investigated, not accepted.

4. **Mutation test.** Revert `select_best_release`'s prerelease branch to the fork's
   behaviour and confirm the test from step 1 goes red.

5. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- Nothing about plugin safety; no auditor exists yet at this point in the sequence.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished release-utils
```

This writes:

```text
/tmp/decky-plugins-extended/release-utils_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer release-utils`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/release-utils-review-*.md
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
   scripts/orchestration/clear-finished release-utils
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
   git add docs/review/release-utils-review-*.md
   git commit -m "docs(review): record release-utils review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished release-utils
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer release-utils` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed release-utils
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize release-utils
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/release-utils_finalized
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
scripts/orchestration/finalize release-utils
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/release-utils_finished
/tmp/decky-plugins-extended/release-utils_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
