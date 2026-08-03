# Plan: Require quoted literals in the loose secret patterns and re-evaluate the three wrongly excluded plugins (secret-rule-precision)

## Context

Three of the auditor's secret patterns make the quote optional and therefore match an
unquoted identifier on the right-hand side of an assignment. This was found while reviewing
`plugin-additions` (#8), where it caused three legitimate plugins to be excluded from the
catalog.

The offending patterns, at `audit_plugins.py:97-112`:

| Name | Pattern | Problem |
|---|---|---|
| `generic_api_key` | `(?i)(?:api[_\-]?key\|apikey\|api_secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})` | quote optional |
| `bearer_token` | `(?i)(?:bearer\|token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_\.]{20,})` | quote optional, and `token` alone is a very broad keyword |
| `cloudflare_token` | `(?i)cf[-_](?:token\|key\|api)['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})` | quote optional |

Demonstrated by running `scan_for_secrets()` over ordinary lines:

```
token   = get_steam_authentication_token()          -> SECRET_BEARER_TOKEN
api_key = _resolve_api_key_for_provider(payload)    -> SECRET_GENERIC_API_KEY
bearer  = build_authorization_header_value(user)    -> SECRET_BEARER_TOKEN
```

### Why this is more serious than `scanner-precision`

`SECRET_*` findings are `severity="critical"`, `classification="BLOCK"`
(`audit_plugins.py:1684-1686`), and `catalog-gate` excludes `BLOCK` from both catalogs. The
false positives corrected in #7 were `MANUAL_REVIEW` and shipped regardless. These do not:
a plugin already in the store that writes `token = fetch_access_token()` is **removed from the
catalog**, with no signal to the user beyond a log line. The scheduled audit runs against every
configured repository, so the blast radius is not limited to the three plugins that surfaced it.

### The model already exists in this file

`password_literal` (`audit_plugins.py:113`) is the correct form and needs no change:

```python
re.compile(r"(?i)password\s*=\s*['\"]([^'\"]{8,})['\"]")
```

The quote is mandatory and the value is delimited on both sides. Match the three loose
patterns to this shape rather than inventing a new approach.

### Do not touch these

`github_token`, `aws_key` and `private_key_header` (`audit_plugins.py:86-96`) match on literal
credential *shapes* (`ghp_` + 36 chars, `AKIA` + 16, the PEM header). They have no
false-positive problem and must keep working exactly as they do.

There is no entropy helper available — `_shannon_entropy` was deliberately removed in
`audit-scanners` and `test_shannon_entropy_removed` asserts it stays gone. Do not reintroduce
it as part of this sub-plan; requiring a quoted literal is the fix.

---

**Slug used throughout this plan:** `secret-rule-precision`

---

## Orchestration Contract

**Slug:** `secret-rule-precision`

**Plan file:**

```text
docs/plans/2026-08-03_secret-rule-precision.md
```

**Implementation branch:**

```text
feat/secret-rule-precision
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/secret-rule-precision_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/secret-rule-precision_finalized
```

**Review notes:**

```text
docs/review/secret-rule-precision-review-*.md
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
git checkout -b feat/secret-rule-precision
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_secret-rule-precision.md
git commit -m "docs(plan): add secret-rule-precision implementation plan"
```

---

## Implementation Tasks

### Task 1 — Require a quoted literal in the three loose patterns

Rewrite `generic_api_key`, `bearer_token` and `cloudflare_token` (`audit_plugins.py:97-112`)
so the captured value must be enclosed in quotes on both sides, following the
`password_literal` form at line 113.

Constraints:

- The opening and closing quote must match. `key = "abc'` is not a secret.
- Keep the existing minimum lengths (16 for api key, 20 for the token patterns).
- Keep the keyword alternations as they are. Narrowing *which* keywords match is a separate
  judgement call and is not in scope here — the defect is the optional quote, not the keyword
  list.
- Preserve `is_fixture` handling at `audit_plugins.py:1685-1686` unchanged. Test-path
  detection already downgrades fixtures to `PASS_WITH_WARNINGS`; that behaviour is correct and
  orthogonal.

### Task 2 — Placeholder values should not BLOCK

Once quotes are required, `api_key = "your-api-key-here"` still matches and still returns
`BLOCK`. Documentation and example config in plugin repos routinely contain exactly that.

Add a small placeholder check: when the captured value matches an obvious placeholder — a
run of one repeated character, or a value containing `example`, `placeholder`, `changeme`,
`your-`, `xxx`, `<`, `>`, `{{`, or `TODO` — downgrade to `PASS_WITH_WARNINGS` rather than
dropping the finding. Keep it visible; do not suppress it entirely.

If during implementation you judge the placeholder list to be unreliable or over-broad, leave
Task 2 unimplemented, say so in the session log, and note it for a follow-up. A `BLOCK` on a
placeholder is bad, but a silent miss on a real credential is worse. Do not guess.

### Task 3 — Re-evaluate the three plugins excluded by `plugin-additions`

`plugin-additions` (#8) dropped these on the false positives above:

```
https://github.com/lopesleo/DeckTools
https://github.com/Rayekkk/DeckyVibranceHDR
https://github.com/parvagans/achievement-companion
```

Re-audit each against the corrected rules. For each one:

- if it now classifies anything other than `BLOCK`, add it back to `additional_plugins.txt`
  and record its release, classification, rule IDs and a written disposition in the session
  log, exactly as `plugin-additions` did for the nine it retained;
- if it still classifies `BLOCK`, leave it out and record the surviving rule IDs and why the
  finding looks genuine.

Do not add a plugin back without reading its report. The point of this sub-plan is that an
unread verdict is worthless, whichever direction it points.

Note that `zany130/decky-notifications` was excluded for an unrelated and correct reason —
already present upstream at a newer version. Leave it out and do not revisit it.

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

1. **The benign assignments currently fire — prove it before fixing.** Run against `dev`'s
   auditor and record the output:
   ```bash
   uv run python -c "
   import audit_plugins as ap
   for line in ['token = get_steam_authentication_token()',
                'api_key = _resolve_api_key_for_provider(payload)',
                'bearer = build_authorization_header_value(user)']:
       print([f.rule_id for f in ap.scan_for_secrets(line + chr(10), 'main.py')], line)
   "
   ```
   Expected on `dev`: `SECRET_BEARER_TOKEN`, `SECRET_GENERIC_API_KEY`, `SECRET_BEARER_TOKEN`.
   Add these as regression tests asserting **no** finding, and confirm they fail before Task 1.

2. **Real quoted secrets must still BLOCK — this is the negative control for Task 1.** Assert
   each of these still produces a `BLOCK` finding:
   - `api_key = "aB3dE5gH7jK9mN1pQ3rS"` (quoted, high-entropy-looking, 20 chars)
   - `token = 'xY9zA1bC3dE5fG7hJ9kL2mN4'`
   - a `Bearer` header with a quoted literal value
   If Task 1 is implemented by simply deleting the patterns, this step fails. It must.

3. **The untouched patterns are untouched.** Assert `ghp_` + 36 chars, an `AKIA` key, and a
   PEM `PRIVATE KEY` header each still produce `BLOCK`. `scanner-precision`'s fixture depends
   on the `ghp_` case — confirm `test_scanner_precision_fixture_keeps_only_intended_survivors`
   still passes, since that fixture's `BLOCK` classification comes from this rule.

4. **Placeholders downgrade but stay visible.** If Task 2 was implemented: assert
   `api_key = "your-api-key-here"` and `token = "xxxxxxxxxxxxxxxxxxxxxxxx"` classify
   `PASS_WITH_WARNINGS` and are still present in the findings list, not absent. Skip and say so
   if Task 2 was intentionally left out.

5. **Mutation test.** Restore the optional quote in `bearer_token` only, and confirm the step-1
   regression tests go red. Then restore. This proves the tests pin the actual fix rather than
   passing incidentally.

6. **Negative control — the three plugins, runs last.** Re-audit each of the three and record,
   for each: previous classification (`BLOCK`), new classification, and the surviving rule IDs.
   State plainly how many were added back. Do not report "re-evaluated" without the numbers.

   Local audits return `AUDIT_ERROR` at the top level because `trivy` and `clamav` are not
   installed and `security-policy.yml` marks them required. Read the findings list and
   per-scanner statuses, not the top-level classification. Do not edit the committed policy.

7. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`. Record the
   tally. Baseline entering this sub-plan is 219 passed / 21 subtests.

### Explicitly not verified

- **This does not measure the secret rules' recall.** Requiring quotes removes a class of false
  positives; it does not establish that real credentials are reliably caught. A credential
  assigned via an unquoted constant elsewhere in the file will now be missed, and that is an
  accepted trade for removing a `BLOCK`-severity false-positive generator.
- The keyword alternations are unchanged, so `token` remains a broad trigger word.
- Only the three named plugins are re-evaluated. Other repositories already audited under the
  old rules may hold cached `BLOCK` verdicts; the audit context hash changes when
  `audit_plugins.py` changes, so those will be re-audited naturally rather than needing a manual
  cache purge. Confirm that reasoning holds rather than assuming it.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished secret-rule-precision
```

This writes:

```text
/tmp/decky-plugins-extended/secret-rule-precision_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer secret-rule-precision`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/secret-rule-precision-review-*.md
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
   scripts/orchestration/clear-finished secret-rule-precision
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
   git add docs/review/secret-rule-precision-review-*.md
   git commit -m "docs(review): record secret-rule-precision review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished secret-rule-precision
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer secret-rule-precision` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed secret-rule-precision
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize secret-rule-precision
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/secret-rule-precision_finalized
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
scripts/orchestration/finalize secret-rule-precision
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/secret-rule-precision_finished
/tmp/decky-plugins-extended/secret-rule-precision_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
