# Plan: Fix the auditor redaction leak and source-artifact comparison (audit-scanners)

## Context

Two correctness defects in the ported scanners. Both are live in the fork and both
would otherwise be inherited silently, because neither makes a test fail — the fork's suite
passes with both present.

The redaction one is the more serious: it writes secrets into three separate report surfaces,
one of which (the GitHub job summary) is visible to anyone who can read the Actions run.

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

**This sub-plan is #3: `audit-scanners`.**  Depends on `audit-port`.

**Slug used throughout this plan:** `audit-scanners`

---

## Orchestration Contract

**Slug:** `audit-scanners`

**Plan file:**

```text
docs/plans/2026-08-03_audit-scanners.md
```

**Implementation branch:**

```text
feat/audit-scanners
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-scanners_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-scanners_finalized
```

**Review notes:**

```text
docs/review/audit-scanners-review-*.md
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
git checkout -b feat/audit-scanners
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_audit-scanners.md
git commit -m "docs(plan): add audit-scanners implementation plan"
```

---

## Implementation Tasks

- **Redaction leak.** Static-rule findings at `audit_plugins.py:1176-1188` store the entire
  matched source line, so a secret sharing a line with a matched pattern reaches the JSON
  report, the Markdown report, and the GitHub job summary — even though the secret scanner
  redacts its own findings inline at `audit_plugins.py:1272-1293`. There is **no** reusable
  redaction helper today; write one based on `_SECRET_PATTERNS` and apply it wherever
  `Finding.evidence` is constructed, not at render time.
- **Dead entropy detector.** `_shannon_entropy()` (`audit_plugins.py:1256-1263`) is defined
  and never called. Either wire it into the secret scanner or delete it — do not leave it
  as decoration implying coverage that does not exist.
- **Source/artifact diff compares names only.** `audit_plugins.py:1799-1825` compares path
  membership, treating both the full extracted path and a one-component-stripped path as
  candidates. It never compares contents, so a plugin that modifies a file already present in
  the repo source is invisible to it. Add content-hash comparison for paths present on both
  sides. Specify how you hash before writing code: Git blob hashing vs raw bytes, how
  generated/built files are excluded, symlink handling, archives with no single common root,
  and case-colliding paths. Getting this wrong produces noisy false positives on every
  plugin that ships a build step.

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

1. **Redaction.** Build a fixture ZIP containing a line that trips a non-secret static rule
   *and* carries a plausible token on the same line, e.g.
   `subprocess.run(cmd)  # token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`. Audit it with
   `GITHUB_STEP_SUMMARY` pointed at a real file so the summary is captured too. Assert the
   reports exist and are non-empty **before** searching them — a `grep -r` over a missing
   directory finds nothing and would otherwise read as success:
   ```bash
   set -o pipefail
   token='ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
   reports=(security-reports/security-report.json security-reports/security-report.md "$GITHUB_STEP_SUMMARY")
   for f in "${reports[@]}"; do
     [ -s "$f" ] || { echo "FAIL: $f missing or empty - audit did not run"; exit 1; }
   done
   if grep -l --fixed-strings "$token" "${reports[@]}"; then
     echo "FAIL: token leaked into the files listed above"; exit 1
   fi
   echo "PASS: token redacted in all three outputs"
   ```
   **Run against the unfixed code first and confirm it reports a leak.** If it does not, the
   fixture is not tripping a rule — fix the fixture before trusting the fix.

2. **Modified same-path file is detected.** Fixture where the ZIP contains `main.py` with
   different bytes than the repo's `main.py`. Assert a finding is raised. Against the fork's
   name-only comparison this produces nothing.

3. **No new false positives on a normal plugin.** Audit a real plugin that ships a build step
   (compiled frontend assets present in the ZIP, absent from source) and assert the
   source/artifact scanner does not flag it. This is the step that catches an over-eager
   content comparison, and it is why the hashing rules must be written down before coding.

4. **Entropy detector resolved.** Either assert `_shannon_entropy()` is reachable from the
   secret scanner via a fixture that only a high-entropy string can trigger, or assert the
   symbol is gone. A defined-but-uncalled detector must not survive this sub-plan.

5. **Mutation test (negative control, runs last).** Revert the redaction helper call and
   confirm step 1 goes red; revert the content comparison and confirm step 2 goes red.

6. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- Redaction is verified against one token shape. Other credential formats in
  `_SECRET_PATTERNS` are not individually exercised.
- Symlink, case-collision, and no-common-root archive handling are specified in the task but
  only the cases with fixtures are proven.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-scanners
```

This writes:

```text
/tmp/decky-plugins-extended/audit-scanners_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-scanners`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-scanners-review-*.md
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
   scripts/orchestration/clear-finished audit-scanners
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
   git add docs/review/audit-scanners-review-*.md
   git commit -m "docs(review): record audit-scanners review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-scanners
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-scanners` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-scanners
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-scanners
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-scanners_finalized
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
scripts/orchestration/finalize audit-scanners
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-scanners_finished
/tmp/decky-plugins-extended/audit-scanners_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
