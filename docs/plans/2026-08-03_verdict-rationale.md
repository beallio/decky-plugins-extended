# Plan: Record why a release was flagged in the durable verdict store (verdict-rationale)

## Context

`security-verdicts.json` records a verdict without recording why. A `MANUAL_REVIEW` entry looks
like this today:

```json
"v0.6.0@437908781": {
  "artifact_sha256": "5069f38e...",
  "audit_context_hash": "2b0aaa28...",
  "audited_at": "2026-08-03T23:59:40.088915Z",
  "blocking_rule_ids": [],
  "classification": "MANUAL_REVIEW"
}
```

It says a human should look at this release and gives them nothing to look at.

`_blocking_rule_ids()` (`audit_plugins.py:2876-2883`) collects rule IDs only from findings
classified `BLOCK`. That was a deliberate choice in `audit-verdicts` (#4), and correct for its
purpose: `catalog-gate` needs exactly two facts — is this release `BLOCK`, and which rules
blocked it, so it can name a reason when dropping it. Nothing consumes the reasons behind a
`MANUAL_REVIEW`, so they were never stored.

That was defensible while the store lived in the gitignored `.audit-cache/`. `verdict-publication`
(#10) committed it to git, which changed what the file *is* — from a private cache into a
version-controlled audit record — without revisiting the shape. A cache need only answer the
gate's question. A record in git history should answer a reader's.

The reasons do exist, in the audit report, which is an ephemeral CI artifact that expires. The
durable file keeps the verdict and discards the evidence for it.

### Sizing

`lopesleo/DeckTools` produces 47 findings that collapse to 9 unique rule IDs: 6
`MANUAL_REVIEW`, 2 `PASS_WITH_WARNINGS`, 1 `BLOCK` before #12 downgraded it. File growth is not
a concern.

---

**Slug used throughout this plan:** `verdict-rationale`

---

## Orchestration Contract

**Slug:** `verdict-rationale`

**Plan file:**

```text
docs/plans/2026-08-03_verdict-rationale.md
```

**Implementation branch:**

```text
feat/verdict-rationale
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/verdict-rationale_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/verdict-rationale_finalized
```

**Review notes:**

```text
docs/review/verdict-rationale-review-*.md
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
git checkout -b feat/verdict-rationale
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_verdict-rationale.md
git commit -m "docs(plan): add verdict-rationale implementation plan"
```

---

## Implementation Tasks

### Task 1 — Record the rule IDs behind the classification

Add two sibling fields to each verdict record:

- `review_rule_ids` — deduplicated, sorted rule IDs of findings classified `MANUAL_REVIEW`
- `warning_rule_ids` — deduplicated, sorted rule IDs of findings classified `PASS_WITH_WARNINGS`

Constraints:

- **Leave `blocking_rule_ids` exactly as it is.** `catalog-gate` and `classification_for` read
  it; changing or renaming it is out of scope and would touch shipping behaviour.
- Exclude allowlisted findings, matching `_blocking_rule_ids()`'s existing behaviour. A finding
  that was explicitly excepted is not a reason to review.
- **Rule IDs only. Never evidence strings.** Evidence can carry secrets, and this file is
  committed to a public repository. This is the hard constraint of the sub-plan.
- Emit the fields always, including as empty lists, so every record has the same keys and diffs
  stay readable.

Note the resulting asymmetry is intentional and worth a comment in the code: an empty
`blocking_rule_ids` on a `MANUAL_REVIEW` record is correct but reads as "nothing wrong" in
isolation. The presence of a populated `review_rule_ids` alongside it removes the ambiguity.

### Task 2 — Backfill existing records without breaking determinism

This is the part that will be got wrong if it is not handled deliberately.

`_record_verdict()` compares `stable_fields = ("classification", "blocking_rule_ids",
"artifact_sha256")` and returns early when they all match, writing nothing. The new fields are
not in that tuple, so an existing record whose verdict has not changed will **never** gain
them — the store would stay half-populated indefinitely, with old entries missing the very
fields this sub-plan adds.

Handle it the same way `audit-invariants` (#11) handled the context hash: when the early return
would fire but the record is missing the new fields, or the new fields differ from what the
current audit produced, update those fields alone and write.

The determinism guarantee from `verdict-publication` still holds and is the constraint:

- verdict unchanged, rationale fields already correct -> no write, byte-identical file;
- verdict unchanged, rationale fields missing or stale -> update those fields, **preserve
  `audited_at`**, write;
- verdict changed -> update everything including `audited_at`, as today.

Do not add the new fields to `stable_fields`. That inverts the logic and rewrites `audited_at`
across the store.

### Task 3 — Migrate the one existing record

`security-verdicts.json` currently holds a single `lopesleo/DeckTools` entry. Re-audit it so the
committed file gains the new fields, and confirm the resulting file is what a fresh audit would
produce. Doing this now, while there is one record, avoids a large mixed-shape diff on the first
scheduled run.

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

1. **Reasons are recorded.** Audit a fixture producing findings at all three levels and assert
   `review_rule_ids` and `warning_rule_ids` contain exactly the expected deduplicated sorted
   IDs, and that `blocking_rule_ids` is unchanged from its current behaviour.

2. **Allowlisted findings are excluded.** Allowlist one `MANUAL_REVIEW` rule and assert it is
   absent from `review_rule_ids` while the others remain. Without this the fields would report
   reasons that were explicitly waived.

3. **No evidence reaches the file — the safety control.** Audit a fixture whose findings carry a
   secret-shaped value in their evidence, serialise the store, and assert the file contains
   neither the value, any four-character substring of it, nor its sha256. Run this before
   trusting anything else in this sub-plan.

4. **Backfill fires for a record missing the new fields.** Seed a record in the *old* shape —
   no `review_rule_ids`, no `warning_rule_ids` — re-record an unchanged verdict, and assert the
   fields appear **and** `audited_at` is unchanged from the seed. Both halves; asserting only
   the first would pass an implementation that rewrites the whole record.

5. **Determinism survives.** Record twice with everything identical and the clock moved between
   calls; assert the file bytes are identical and no write occurred. This is
   `verdict-publication`'s guarantee and `audit-invariants` extended it; this sub-plan must not
   break it.

6. **Changed verdict still moves the timestamp.** Re-record with a different classification and
   assert `audited_at` moves. This is the control that stops Task 2 freezing `audited_at`.

7. **Mutation test (negative control, runs last).** Remove Task 2's backfill branch and confirm
   step 4 goes red while steps 5 and 6 stay green. Three separately pinned behaviours, not one
   over-broad assertion.

8. **The committed file is migrated and reproducible.** Assert `security-verdicts.json` on the
   branch contains `review_rule_ids` for the DeckTools entry, and that re-running the audit
   produces byte-identical content.

9. **Nothing else moved.** `catalog-gate`, `audit-verdicts`, `verdict-publication` and
   `audit-invariants` tests must pass unchanged. Record the tally; baseline entering this
   sub-plan is 237 passed / 21 subtests.

10. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.

### Explicitly not verified

- This changes what is recorded, not what is decided. No classification, no catalog output and
  no gate behaviour should differ; step 9 is what checks that.
- Rule IDs are not human-readable explanations. `PRIVILEGE_MOUNT` tells a reader which rule
  fired, not what the plugin does with it. Mapping rule IDs to prose descriptions is a
  reasonable follow-up and is out of scope here.
- Only the single existing record is migrated. Records written by future scheduled runs get the
  fields natively.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished verdict-rationale
```

This writes:

```text
/tmp/decky-plugins-extended/verdict-rationale_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer verdict-rationale`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/verdict-rationale-review-*.md
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
   scripts/orchestration/clear-finished verdict-rationale
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
   git add docs/review/verdict-rationale-review-*.md
   git commit -m "docs(review): record verdict-rationale review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished verdict-rationale
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer verdict-rationale` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed verdict-rationale
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize verdict-rationale
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/verdict-rationale_finalized
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
scripts/orchestration/finalize verdict-rationale
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/verdict-rationale_finished
/tmp/decky-plugins-extended/verdict-rationale_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
