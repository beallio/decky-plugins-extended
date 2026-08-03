# Plan: Enforce the placeholder-pattern invariant and keep verdict context hashes current (audit-invariants)

## Context

Two loose ends recorded during review of `secret-rule-precision` (#9) and
`verdict-publication` (#10). Neither blocked its sub-plan; both are small, and one is a real
crash rather than a theoretical one.

### Item A — an unenforced invariant that crashes the scanner

`scan_for_secrets()` at `audit_plugins.py:1719-1721` reads a named group:

```python
is_placeholder = (
    name in _PLACEHOLDER_SECRET_PATTERNS
    and _looks_like_secret_placeholder(m.group("value"))
)
```

This requires every pattern named in `_PLACEHOLDER_SECRET_PATTERNS` (line 1680) to define a
`value` named group. Today they are in sync — `generic_api_key`, `bearer_token` and
`cloudflare_token` define one; `github_token`, `aws_key`, `private_key_header` and
`password_literal` do not and are not in the set. Python's short-circuiting `and` means the
shape-matching rules never reach `m.group`.

Nothing enforces the coupling. Adding a name to the set without a `value` group raises
`IndexError` the moment a matching line is scanned. Confirmed, not inferred:

```
>>> ap._PLACEHOLDER_SECRET_PATTERNS |= {'github_token'}
>>> ap.scan_for_secrets('tok = "ghp_AAAA...36"', 'main.py')
IndexError: no such group
```

The blast radius is a crash mid-scan over arbitrary third-party plugin content, which surfaces
as `AUDIT_ERROR`. Under the fail-open policy that ships the plugin unaudited rather than
breaking the catalog — so it fails safe, but it silently stops auditing.

### Item B — verdict records can carry a stale context hash

`_record_verdict()` at `audit_plugins.py:2865` compares three fields before its early return:

```python
stable_fields = ("classification", "blocking_rule_ids", "artifact_sha256")
```

`audit_context_hash` is not among them, and the early return skips the write entirely. So when
the policy or allowlist changes but a re-audit produces the same verdict, the stored record
keeps the **old** context hash and misreports which policy produced it.

This is cosmetic, not functional: `classification_for()` reads `classification` and
`blocking_rule_ids` only, never the context hash. Do not "fix" this by adding
`audit_context_hash` to `stable_fields` — that would make every policy edit rewrite every
record and break the determinism `verdict-publication` established. See Task 2.

---

**Slug used throughout this plan:** `audit-invariants`

---

## Orchestration Contract

**Slug:** `audit-invariants`

**Plan file:**

```text
docs/plans/2026-08-03_audit-invariants.md
```

**Implementation branch:**

```text
feat/audit-invariants
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-invariants_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-invariants_finalized
```

**Review notes:**

```text
docs/review/audit-invariants-review-*.md
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
git checkout -b feat/audit-invariants
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_audit-invariants.md
git commit -m "docs(plan): add audit-invariants implementation plan"
```

---

## Implementation Tasks

### Task 1 — Pin the placeholder-pattern invariant

Add a test asserting that, for every `(name, pattern)` in `_SECRET_PATTERNS`, membership in
`_PLACEHOLDER_SECRET_PATTERNS` matches whether the compiled pattern defines a `value` group:

```python
("value" in pattern.groupindex) == (name in _PLACEHOLDER_SECRET_PATTERNS)
```

Assert the biconditional, not just one direction. A pattern that defines a `value` group but is
absent from the set is also a mistake — it means placeholder downgrading was intended and
silently is not happening.

Keep it a test rather than a module-level assertion. An `assert` at import time is stripped by
`python -O`, which is the same footgun `release-utils` removed from `generate_json.py`.

### Task 2 — Refresh the context hash without breaking determinism

When the early return in `_record_verdict()` fires because the three stable fields are
unchanged, but the incoming `audit_context_hash` differs from the stored one, update **only**
that field and write.

The determinism requirement from `verdict-publication` still holds and is the constraint that
makes this non-trivial:

- unchanged verdict **and** unchanged context -> no write at all, byte-identical file;
- unchanged verdict, **changed** context -> update `audit_context_hash`, preserve
  `audited_at`, write;
- changed verdict -> update everything including `audited_at`, as today.

Preserving `audited_at` in the middle case matters: the verdict was not re-established, only
re-confirmed under a new policy, and letting the timestamp move would make every policy edit
produce a diff on every record.

Do not add `audit_context_hash` to `stable_fields`. That inverts the logic and rewrites
`audited_at` across the whole store on any policy change.

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

1. **The invariant test can fail.** Temporarily add `github_token` to
   `_PLACEHOLDER_SECRET_PATTERNS` and confirm the Task 1 test goes red. Then remove a `value`
   group from one of the three placeholder-enabled patterns and confirm it goes red for the
   opposite reason. Both directions, because the assertion is a biconditional. Record both
   failures, then restore.

2. **The crash it guards against is real.** With `github_token` still added to the set, call
   `scan_for_secrets` on a line containing a `ghp_` token and record the `IndexError`. This is
   what the test exists to prevent reaching CI; showing the test red is not the same as showing
   the consequence.

3. **Determinism unchanged when nothing changed.** Record a verdict twice with the same
   classification, rule IDs, artifact hash **and** context hash, with the clock moved between
   calls. Assert the file bytes are identical and no write occurred. This is
   `verdict-publication`'s guarantee and must survive Task 2.

4. **Context-only change updates exactly one field.** Record a verdict, then re-record with the
   same three stable fields but a different `audit_context_hash`. Assert the stored
   `audit_context_hash` is the new value **and** `audited_at` is unchanged from the first write.
   Both halves — asserting only the first would pass an implementation that rewrites the whole
   record.

5. **Changed verdict still updates the timestamp.** Re-record with a different classification
   and assert `audited_at` moves. This is the control that stops Task 2 from freezing
   `audited_at` everywhere.

6. **Mutation test (negative control, runs last).** Revert Task 2's context-hash branch and
   confirm step 4 goes red. Then revert Task 1's test and confirm step 1 has nothing to report.

7. **Nothing else moved.** `catalog-gate`, `audit-verdicts`, `verdict-publication` and
   `secret-rule-precision` tests must all pass unchanged. Record the tally; baseline entering
   this sub-plan is what `verdict-publication` left on `dev`.

8. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.

### Explicitly not verified

- Item A's crash is only reachable by a future edit that breaks the coupling. The test prevents
  that edit landing; it does not prove the current pattern set is otherwise correct.
- Item B is cosmetic. No behaviour depends on `audit_context_hash` in the verdict record today,
  so this sub-plan does not change any classification, and no catalog output should differ.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-invariants
```

This writes:

```text
/tmp/decky-plugins-extended/audit-invariants_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-invariants`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-invariants-review-*.md
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
   scripts/orchestration/clear-finished audit-invariants
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
   git add docs/review/audit-invariants-review-*.md
   git commit -m "docs(review): record audit-invariants review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-invariants
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-invariants` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-invariants
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-invariants
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-invariants_finalized
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
scripts/orchestration/finalize audit-invariants
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-invariants_finished
/tmp/decky-plugins-extended/audit-invariants_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
