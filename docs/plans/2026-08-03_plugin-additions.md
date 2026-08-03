# Plan: Vet and add the thirteen fork plugin entries (plugin-additions)

## Context

The fork adds 13 entries to `additional_plugins.txt`. All 13 were confirmed public,
unarchived, carrying a root `plugin.json`/`package.json`, and having at least one single-ZIP
release. That is catalog *compatibility*, not safety, and none has been through the audit.

This runs last precisely so the audit exists to vet them. Four are from a single author
(`Rayekkk`) and two belong to the fork owner — not disqualifying, but worth knowing while
reading their reports.

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
7. `scanner-precision` — cut the false-positive rate
8. `plugin-additions` — the 13 new plugin entries

**This sub-plan is #8: `plugin-additions`.**  Depends on every preceding sub-plan — this is the
first one whose additions are actually vetted, and the first that uses the auditor for its
intended purpose rather than building it.

`scanner-precision` (#7) was inserted before this one for a reason that matters here. Auditing
`beallio/SDH-Ludusavi`, a known-good plugin, produced 14 findings that were all false
positives; after #7 it produces 11, with the three high-severity ones gone. The reports you are
about to read are therefore usable, but **still noisy** — `PRIVILEGE_SYSTEMCTL` and
`SENSITIVE_ENV_HARVEST` are deliberately left firing on legitimate behaviour. Do not treat a
non-empty findings list as disqualifying. Read what the rules actually matched.

**Slug used throughout this plan:** `plugin-additions`

---

## Orchestration Contract

**Slug:** `plugin-additions`

**Plan file:**

```text
docs/plans/2026-08-03_plugin-additions.md
```

**Implementation branch:**

```text
feat/plugin-additions
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/plugin-additions_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/plugin-additions_finalized
```

**Review notes:**

```text
docs/review/plugin-additions-review-*.md
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
git checkout -b feat/plugin-additions
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_plugin-additions.md
git commit -m "docs(plan): add plugin-additions implementation plan"
```

---

## Implementation Tasks

The fork adds 13 entries to `additional_plugins.txt`. All 13 are public, unarchived repos
with a root `plugin.json`/`package.json` and at least one single-ZIP release, so they are
catalog-compatible. That is compatibility, not safety, and none has been through the audit.
Add them only after Tasks 3–7 are green, then read the resulting audit report for each before
committing. Four are from a single author (`Rayekkk`) and two belong to the fork owner.

---

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

1. **Every added repo produces a report.** After adding the entries, assert
   `security-reports/security-report.json` contains one entry per new repository with a
   `final_classification` that is not `AUDIT_ERROR`. An entry that errored has not been vetted
   and must not be added on this round — drop it and say so.

2. **Findings were read, not just generated.** For each repository classified
   `MANUAL_REVIEW` or `PASS_WITH_WARNINGS`, record the rule IDs and a one-line disposition in
   the commit message. A count alone is not evidence anyone looked.

3. **No `BLOCK` lands.** Assert no added repository's newest release is classified `BLOCK`. If
   one is, the gate from `catalog-gate` will silently drop it — remove the entry instead of
   shipping a line that generates nothing.

4. **Negative control (runs last).** Regenerate the catalog and assert each added plugin
   appears with at least one version, and that the total plugin count increased by exactly the
   number of entries actually kept.

5. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- **No safety claim is made about these plugins.** A passing audit is static analysis only; it
  cannot evaluate runtime behaviour or perfectly-mimicking obfuscation.
- Only the newest eligible release of each is audited, not the full release history.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished plugin-additions
```

This writes:

```text
/tmp/decky-plugins-extended/plugin-additions_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer plugin-additions`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/plugin-additions-review-*.md
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
   scripts/orchestration/clear-finished plugin-additions
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
   git add docs/review/plugin-additions-review-*.md
   git commit -m "docs(review): record plugin-additions review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished plugin-additions
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer plugin-additions` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed plugin-additions
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize plugin-additions
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/plugin-additions_finalized
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
scripts/orchestration/finalize plugin-additions
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/plugin-additions_finished
/tmp/decky-plugins-extended/plugin-additions_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
