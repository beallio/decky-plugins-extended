# Plan: Reject prose values in the secret patterns and restore DeckTools (secret-value-precision)

## Context

`secret-rule-precision` (#9) fixed one half of a problem and left the other half standing.
Requiring a quoted literal stopped the patterns matching unquoted identifiers like
`token = get_access_token()`. It did nothing about quoted **prose**, which is a large category.

`lopesleo/DeckTools` was excluded from the catalog on this finding:

```
SECRET_GENERIC_API_KEY  DeckTools/dist/index.js:523  BLOCK
```

The matched value is `"Chave API Hubcap"` — Portuguese for "Hubcap API Key". It is a **UI
label in a translation dictionary**, sitting between `saveCookie: "Salvar Cookie"` and
`saveMorrenusKey: "Salvar Chave Hubcap"`. The key name is `morrenusApiKey`, so the pattern's
keyword alternation fires, the value is quoted, and it is over the 16-character minimum.

This matters beyond one plugin. Any localised application with an "API Key" settings label
trips it, and `SECRET_*` is `critical`/`BLOCK`, which `catalog-gate` silently excludes.

### How the review missed it

Worth recording, because the failure mode is instructive. The value was described — accurately
— as "a quoted, non-placeholder 16-character mixed-case value with a symbol". Every one of
those facts is also true of a short Portuguese sentence. The "symbol" was a space; the "mixed
case" was a capitalised word. Both the implementer and the reviewer reasoned about the *shape*
of a redacted value neither had looked at, and a shape description felt like evidence when it
was only a description.

The check that resolved it was downloading the release ZIP and reading the surrounding lines,
which is exactly what the auditor already does.

### Current state

- The three quoted-literal patterns are at `audit_plugins.py:97-112`.
- `_looks_like_secret_placeholder` already downgrades obvious placeholders; it does not
  recognise prose.
- `_PLACEHOLDER_SECRET_PATTERNS` and the patterns defining a `value` group are pinned to each
  other by `test_placeholder_pattern_membership_matches_named_value_group` (#11). Any change
  here must keep that biconditional true.
- DeckTools' full profile is 47 findings; the only `BLOCK` is this false positive. The rest are
  `PRIVILEGE_MOUNT`, `SENSITIVE_STEAM_AUTH`, `ROOT_ACCESS`, `PERSIST_LD_PRELOAD` and
  subprocess use — ordinary for a system-tools plugin, and all `MANUAL_REVIEW` or
  `PASS_WITH_WARNINGS`, which ship under `BLOCK`-only gating.

---

**Slug used throughout this plan:** `secret-value-precision`

---

## Orchestration Contract

**Slug:** `secret-value-precision`

**Plan file:**

```text
docs/plans/2026-08-03_secret-value-precision.md
```

**Implementation branch:**

```text
feat/secret-value-precision
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/secret-value-precision_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/secret-value-precision_finalized
```

**Review notes:**

```text
docs/review/secret-value-precision-review-*.md
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
git checkout -b feat/secret-value-precision
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_secret-value-precision.md
git commit -m "docs(plan): add secret-value-precision implementation plan"
```

---

## Implementation Tasks

### Task 1 — A credential-shaped value test, applied to the three quoted patterns

Real API keys and tokens do not contain spaces and are not natural language. Add a check that
a matched `value` looks like a credential before raising a `BLOCK`, applied to
`generic_api_key`, `bearer_token` and `cloudflare_token` only.

Minimum rules, in rough order of confidence:

- **Reject any value containing whitespace.** `"Chave API Hubcap"` has three spaces; no real
  key does. This alone resolves the DeckTools case and is the highest-confidence signal here.
- **Reject values that are plausibly natural language**, e.g. multiple runs of alphabetic
  characters separated by spaces, or a high proportion of vowels with no digits.
- Keep the existing `_looks_like_secret_placeholder` downgrade; this is an additional filter,
  not a replacement.

Downgrade rather than drop: classify a non-credential-shaped match as `PASS_WITH_WARNINGS` and
keep it in the findings list, the same treatment placeholders get. A rule that silently
disappears is one nobody can audit later.

Do not touch `github_token`, `aws_key`, `private_key_header` or `password_literal`. The first
three match literal credential shapes and have no false-positive problem. `password_literal`
is deliberately out of scope — a natural-language password is a plausible real finding.

### Task 2 — Restore DeckTools

Once Task 1 lands and DeckTools no longer classifies `BLOCK`, add it back:

```
https://github.com/lopesleo/DeckTools
```

Re-audit it and record release, classification, rule IDs and a written disposition in the
session log, exactly as `plugin-additions` did for the nine it retained. If it still classifies
`BLOCK` for any reason, leave it out and record why instead.

Order matters: the rule fix must land before the entry. Adding it first would put the plugin
in the catalog until the next scheduled audit recorded a `BLOCK` verdict, at which point it
would silently disappear.

### Task 3 — Make the reviewer's mistake harder to repeat

Extend the finding's evidence string so a reviewer can judge a redacted value without fetching
the artifact. Alongside the existing `[<name> pattern matched at position N] [REDACTED]`,
include non-identifying shape facts: value length, whether it contains whitespace, and whether
it is entirely alphabetic.

Never include the value, any substring of it, or its hash. The point is to distinguish
"16 chars, contains spaces, all letters" from "32 chars, no spaces, mixed alnum" — which would
have resolved this case at review time.

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

1. **Reproduce the false positive first.** On `dev`, assert
   `api_key = "Chave API Hubcap"` produces a `SECRET_GENERIC_API_KEY` finding classified
   `BLOCK`. Record it. Add it as a regression test expecting `PASS_WITH_WARNINGS`, and confirm
   it fails before Task 1.

2. **Real credentials must still BLOCK — negative control for Task 1.** Assert each still
   classifies `BLOCK`:
   - `api_key = "aB3dE5gH7jK9mN1pQ3rS"`
   - `token = 'xY9zA1bC3dE5fG7hJ9kL2mN4'`
   - a 40-character hex string assigned to `apikey`
   If Task 1 is implemented by loosening until nothing matches, this fails. It must.

3. **Prose variants across languages.** Assert `"Clé API Hubcap"`, `"API Key Settings"` and
   `"Save API Key"` all downgrade. One example is not a rule.

4. **The findings are downgraded, not dropped.** Assert the prose match is still present in the
   findings list with `PASS_WITH_WARNINGS`, not absent. A filter that deletes findings is not
   the requested behaviour.

5. **Untouched patterns unchanged.** `ghp_` + 36, an `AKIA` key, a PEM header and
   `password = "correct horse battery"` must all still `BLOCK`. The last one is deliberate:
   `password_literal` is out of scope and a spaced passphrase is a plausible real finding.

6. **The #11 invariant still holds.** `test_placeholder_pattern_membership_matches_named_value_group`
   must still pass. If Task 1 introduces a new set of pattern names, extend that test rather
   than working around it.

7. **Evidence shape facts leak nothing.** Assert the evidence string for a known value contains
   neither the value, any 4-character substring of it, nor its sha256 — while still reporting
   length and the whitespace flag.

8. **Mutation test.** Remove the whitespace rejection and confirm step 1's regression test goes
   red. Then restore.

9. **Negative control — DeckTools (runs last).** Re-audit `lopesleo/DeckTools` and record the
   previous classification (`BLOCK`), the new classification, and the surviving rule IDs. State
   plainly whether it was added back. Baseline for comparison: 47 findings, of which exactly
   one was `BLOCK`.

   Local runs return `AUDIT_ERROR` at the top level because `trivy` and `clamav` are absent and
   `security-policy.yml` marks them required. Read the findings list and per-scanner statuses,
   not the top-level classification. Do not edit the committed policy.

10. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`. Baseline
    entering this sub-plan is 234 passed / 21 subtests.

### Explicitly not verified

- **This does not improve recall.** Rejecting spaced values removes false positives; a real
  credential that happens to contain whitespace would now be missed. That is an accepted trade
  against a `BLOCK`-severity false-positive generator, and it is the same trade #9 made.
- The natural-language heuristic is judgement, not science. If it proves unreliable during
  implementation, ship the whitespace rule alone, say so in the session log, and leave the rest.
- Only DeckTools is re-evaluated. Other plugins already audited may hold cached `BLOCK`
  verdicts from this rule; the audit context hash covers `audit_plugins.py`, so they re-audit
  naturally. Confirm that rather than assuming it.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished secret-value-precision
```

This writes:

```text
/tmp/decky-plugins-extended/secret-value-precision_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer secret-value-precision`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/secret-value-precision-review-*.md
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
   scripts/orchestration/clear-finished secret-value-precision
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
   git add docs/review/secret-value-precision-review-*.md
   git commit -m "docs(review): record secret-value-precision review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished secret-value-precision
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer secret-value-precision` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed secret-value-precision
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize secret-value-precision
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/secret-value-precision_finalized
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
scripts/orchestration/finalize secret-value-precision
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/secret-value-precision_finished
/tmp/decky-plugins-extended/secret-value-precision_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
