# Plan: Stop platform-baseline rules driving MANUAL_REVIEW and make classifications policy-tunable (rule-tuning)

## Context

The audit now has a real corpus to tune against: 42 audited releases in the committed
`security-verdicts.json`. Aggregating it shows the classifier is not discriminating.

```
42 releases:  MANUAL_REVIEW 32   BLOCK 8   PASS 2
```

The two `PASS` entries are the same plugin (`SheffeyG/CheatDeck`) counted twice, so **41 of 42
releases are flagged**. A classifier that flags 98% of its input carries no information — it is
distinguishing Decky plugins from nothing, not risky plugins from ordinary ones.

The rules responsible are describing the platform rather than risk:

| Rule | Fires on | Currently |
|---|---|---|
| `EXEC_SUBPROCESS_RUN` | 22/42 (52%) | `PASS_WITH_WARNINGS` |
| `PRIVILEGE_MOUNT` | 21/42 (50%) | `MANUAL_REVIEW` |
| `PRIVILEGE_SYSTEMCTL` | 18/42 (42%) | `MANUAL_REVIEW` |
| `PRIVILEGE_SUDO` | 16/42 (38%) | `MANUAL_REVIEW` |
| `ROOT_ACCESS` | 15/42 (36%) | `MANUAL_REVIEW` |
| `PRIVILEGE_SUDO_SHELL` | 15/42 (36%) | `MANUAL_REVIEW` |

SteamOS has a read-only root filesystem. A plugin that does anything useful to the system needs
sudo, mount or systemctl. Half the corpus tripping these is the expected baseline, not a signal.

By contrast the tail discriminates. Rules firing on 1–4 of 42 include `EXEC_FUNCTION_CTOR` (1),
`OBFUSCATION_MARSHAL` (2), `EXEC_SHELL_TRUE` (2), `NETWORK_DISABLED_TLS` (3),
`OBFUSCATION_PICKLE` (3) and `EXEC_EVAL` (4). Those are rare enough to be worth a human look.
Their signal is currently buried under the baseline noise.

### Why this needs a policy mechanism, not an edit

Rule classifications are hardcoded as tuples in `audit_plugins.py` — 44 entries carry a literal
`"MANUAL_REVIEW"`, e.g. `PRIVILEGE_MOUNT` at `audit_plugins.py:1251-1253`. There is no per-rule
section in `security-policy.yml`.

Tuning is going to iterate as the corpus grows, and doing it by editing detection code conflates
*what we detect* with *how much we care*. A policy override also flows into
`audit_context_hash`, so changing it re-audits automatically instead of leaving stale verdicts.

### Scope discipline

`classify_findings` (`audit_plugins.py:536-540`) takes the maximum classification across
findings, so demoting a rule stops it escalating the plugin. **Detection must not change.** Every
rule keeps firing and keeps appearing in the report and in `warning_rule_ids`; only its
escalation weight changes. Losing the finding entirely would destroy the corpus this tuning
depends on.

The catalog gate is report-only and stays that way. Nothing here can affect what users see.

---

**Slug used throughout this plan:** `rule-tuning`

---

## Orchestration Contract

**Slug:** `rule-tuning`

**Plan file:**

```text
docs/plans/2026-08-04_rule-tuning.md
```

**Implementation branch:**

```text
feat/rule-tuning
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/rule-tuning_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/rule-tuning_finalized
```

**Review notes:**

```text
docs/review/rule-tuning-review-*.md
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
git checkout -b feat/rule-tuning
```

Commit this plan first:

```bash
git add docs/plans/2026-08-04_rule-tuning.md
git commit -m "docs(plan): add rule-tuning implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add per-rule classification overrides to policy

Add a `rule_classifications:` mapping to `security-policy.yml`, applied when a `Finding` is
constructed so the override wins over the rule table's built-in classification.

Constraints:

- An unknown rule ID in the mapping is a **policy error**, not a silent no-op. A typo must not
  quietly leave a rule at its default — fail loudly or report it in the scanner status.
- Only allow demotion or promotion between the existing classifications
  (`PASS`, `PASS_WITH_WARNINGS`, `MANUAL_REVIEW`, `BLOCK`). Do not invent a new tier.
- The override must be part of `audit_context_hash`, so changing it invalidates cached verdicts
  and forces a re-audit. Verify this rather than assuming it — the hash covers the policy file
  today, so this may already hold.
- Detection is untouched. The finding is still produced, still carries its `rule_id`, and still
  appears in the report.

### Task 2 — Demote the platform-baseline rules

Compute the firing rate of every rule across the committed `security-verdicts.json` and demote
those above **35% of the corpus** from `MANUAL_REVIEW` to `PASS_WITH_WARNINGS` via the new
policy mapping.

Do not hardcode the list from this plan's Context table — recompute it, because the corpus has
grown since and will grow again. Record the computed rates and the resulting list in the session
log, so the decision is auditable and repeatable.

Add a comment in `security-policy.yml` explaining *why* each demoted rule is baseline for this
platform — a future reader needs to know these were measured, not guessed.

### Task 3 — Report the flag rate

The audit should state how much of the corpus it is flagging, so this failure mode is visible
next time rather than needing manual aggregation.

Add to the run summary: total releases audited, the count per classification, and the top rules
by firing rate. Keep it to counts and rule IDs — no evidence, no file contents.

### Task 4 — Do not touch the BLOCK rules

`SHELL_CURL_PIPE`, `DESTRUCTIVE_RM_RF`, `DESTRUCTIVE_RM_RF_SHELL`, `SECRET_PRIVATE_KEY_HEADER`,
`SECRET_PASSWORD_LITERAL` and `SECRET_GENERIC_API_KEY` are all confirmed false-positive
generators, but fixing them is a separate sub-plan with different work — scoping matches out of
READMEs, comments and vendored dependency trees.

Leave them alone here. Demoting them via policy would hide the problem rather than fix it, and
they are harmless while the gate is report-only.

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

1. **Measure the flag rate before changing anything.** Aggregate the committed
   `security-verdicts.json` and record the classification counts and per-rule firing rates.
   Expected starting point: 42 releases, 32 `MANUAL_REVIEW`, 8 `BLOCK`, 2 `PASS`. If the corpus
   has grown, report the new numbers — they are the baseline for step 7.

2. **An override actually changes classification.** Audit a fixture that trips a demoted rule
   and assert the release classifies `PASS_WITH_WARNINGS` rather than `MANUAL_REVIEW`, while the
   finding is **still present** with its original `rule_id`. Both halves — a test asserting only
   the classification would pass an implementation that drops the finding.

3. **An unknown rule ID in policy is not silent.** Put a typo'd rule ID in
   `rule_classifications:` and assert it is surfaced as an error or scanner status, not ignored.
   Run this before the fix and confirm it currently passes silently.

4. **The override reaches the context hash.** Compute `audit_context_hash`, change a
   `rule_classifications:` entry, recompute, and assert the two differ. If they do not, cached
   verdicts survive a policy change and the tuning never takes effect — that is the failure this
   step exists to catch.

5. **A promoted rule still escalates.** Override a low-frequency rule *up* to `MANUAL_REVIEW` and
   assert the release classifies accordingly. This proves the mechanism is general rather than a
   one-way mute.

6. **BLOCK behaviour is unchanged.** Assert the six current `BLOCK` rules still classify `BLOCK`,
   and that `catalog-gate` tests pass unchanged with enforcement still `report-only`.

7. **Negative control — the flag rate actually falls (runs last).** Re-audit the corpus, or
   recompute classifications from the existing findings, and report the new distribution against
   step 1's baseline. State the numbers. If `MANUAL_REVIEW` has not fallen substantially, the
   demotions did not take effect and the sub-plan has not achieved its purpose.

8. **Mutation test.** Remove the override application so the rule table wins again, and confirm
   step 2 goes red.

9. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`. Baseline
   entering this sub-plan is 256 passed / 21 subtests.

### Explicitly not verified

- **Demoting a rule is a judgement, not a proof of safety.** `PRIVILEGE_SUDO` firing on 38% of
  plugins means it does not discriminate on this corpus; it does not mean sudo is harmless. A
  plugin abusing sudo now surfaces as `PASS_WITH_WARNINGS`, and is still reported.
- The 35% threshold is a starting heuristic chosen from a 42-release corpus, not a derived
  constant. It should be revisited as the corpus grows.
- This does not address the six false-positive `BLOCK` rules, which remain the blocker for ever
  re-enabling enforcement.
- No claim is made that the rare-firing tail represents real threats; that requires reading them
  by hand and is separate work.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished rule-tuning
```

This writes:

```text
/tmp/decky-plugins-extended/rule-tuning_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer rule-tuning`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/rule-tuning-review-*.md
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
   scripts/orchestration/clear-finished rule-tuning
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
   git add docs/review/rule-tuning-review-*.md
   git commit -m "docs(review): record rule-tuning review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished rule-tuning
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer rule-tuning` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed rule-tuning
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize rule-tuning
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/rule-tuning_finalized
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
scripts/orchestration/finalize rule-tuning
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/rule-tuning_finished
/tmp/decky-plugins-extended/rule-tuning_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
