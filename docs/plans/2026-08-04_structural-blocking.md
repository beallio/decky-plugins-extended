# Plan: Restrict BLOCK to structural facts and rank the review queue by rarity (structural-blocking)

## Context

Across 42 audited releases, the rules that should gate never fired, and every rule that fired
should never have gated.

```
structural rules fired:   ARCHIVE_DUPLICATE_PATH x1, nothing else
rules that produced BLOCK: SHELL_CURL_PIPE 3, DESTRUCTIVE_RM_RF 3,
                           DESTRUCTIVE_RM_RF_SHELL 2, SECRET_PRIVATE_KEY_HEADER 2,
                           SECRET_PASSWORD_LITERAL 1, SECRET_GENERIC_API_KEY 1
```

All eight `BLOCK` verdicts were false positives — README install documentation, uninstall
scripts running `rm -f` on files the plugin itself created, and PEM headers inside vendored
`cryptography` and `httpx`. They removed legitimate plugins from the live catalog on 2026-08-04
before the gate was switched to report-only.

### The distinction that matters

A **structural fact** is a deterministic property of the artifact. A ZIP either contains a
path-traversing member or it does not. A file either carries the setuid bit or it does not.
ClamAV either matches a signature or it does not. There is no context in which a Decky plugin
legitimately ships a device node, a symlink escaping the extraction root, or a 4000:1
compression ratio. These cannot false-positive.

A **behavioural heuristic** needs context the auditor does not have. "Uses sudo", "runs
`curl | sh`", "contains something shaped like a key" — each has a mundane explanation most of
the time, and judging it requires knowing what the plugin is for.

The design already had these tiers; the README lists malware, traversal and zip bombs as
`BLOCK`. The pattern rules were mixed into the same tier, and they are the ones that did damage.

### Rule inventory

`_NON_TABLE_RULE_IDS` (`audit_plugins.py:95-112`) is *close* to the structural set but not it —
it also contains metadata-validity rules like `INVALID_PACKAGE_JSON` and `MISSING_PLUGIN_JSON`,
which are audit problems rather than security facts. Do not reuse it as the blockable set.

### Rarity ranking

`rule-tuning` (#16) established that per-rule thresholding cannot separate baseline from signal
on this corpus — after demoting the five most common rules, 39 of 42 releases remained flagged
by a smooth gradient with no cutoff.

Weighting each rule by inverse corpus frequency does separate them. Prototyped over the
committed verdict store:

```
56.0  mubaraknumann/unifideck    rarest: PRIVILEGE_PKEXEC(1), EXEC_OS_POPEN(1), OBFUSCATION_MARSHAL(2)
38.6  jinzhongjia/decky-music    rarest: SECRET_PASSWORD_LITERAL(1), EXEC_SUBPROCESS_CALL(1)
22.1  panyiwei-home/Friendeck    rarest: EXEC_EVAL_JS(1), PRIVILEGE_IPTABLES(3), EXEC_EVAL(4)
 ...
 0.0  SheffeyG/CheatDeck
```

That is a review queue rather than a verdict, and it degrades gracefully: a false positive
misranks a plugin instead of removing it.

---

**Slug used throughout this plan:** `structural-blocking`

---

## Orchestration Contract

**Slug:** `structural-blocking`

**Plan file:**

```text
docs/plans/2026-08-04_structural-blocking.md
```

**Implementation branch:**

```text
feat/structural-blocking
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/structural-blocking_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/structural-blocking_finalized
```

**Review notes:**

```text
docs/review/structural-blocking-review-*.md
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
git checkout -b feat/structural-blocking
```

Commit this plan first:

```bash
git add docs/plans/2026-08-04_structural-blocking.md
git commit -m "docs(plan): add structural-blocking implementation plan"
```

---

## Implementation Tasks

### Task 1 — Define the blockable set explicitly

Add a `blockable_rules:` list to `security-policy.yml` naming the rules permitted to produce
`BLOCK`. Start from the structural facts only:

```
MALWARE
ARCHIVE_TRAVERSAL
ARCHIVE_ESCAPE_SYMLINK
ARCHIVE_BOMB_RATIO
ARCHIVE_BOMB_SIZE
ARCHIVE_SETUID_FILE
ARCHIVE_DEVICE_FILE
ARCHIVE_NAMED_PIPE
ARCHIVE_FILE_COUNT_EXCEEDED
ARCHIVE_SINGLE_FILE_TOO_LARGE
```

Judgement calls to make and record, rather than guess:

- `ARCHIVE_DUPLICATE_PATH` is a real zip-confusion technique but fired once on a legitimate
  plugin in this corpus. Decide whether it blocks or reviews, and say why.
- `CORRUPT_ARCHIVE` means the audit could not complete. That is arguably `AUDIT_ERROR` rather
  than `BLOCK`. Decide and record.
- Metadata-validity rules (`INVALID_PLUGIN_JSON`, `MISSING_PLUGIN_JSON`, and similar) are audit
  problems, not security facts. They must not be blockable.

### Task 2 — Enforce the cap centrally

Any finding whose `rule_id` is **not** in `blockable_rules` must be capped at `MANUAL_REVIEW`,
applied in one place so no individual rule can bypass it.

- Apply the cap after the `rule_classifications` overrides from #16, so the two compose
  predictably. Record the resulting precedence.
- A rule ID in `blockable_rules` that does not exist is a policy error, matching #16's
  behaviour for unknown override keys.
- The six textual rules that caused the incident — `SHELL_CURL_PIPE`, `DESTRUCTIVE_RM_RF`,
  `DESTRUCTIVE_RM_RF_SHELL`, `SECRET_PRIVATE_KEY_HEADER`, `SECRET_PASSWORD_LITERAL`,
  `SECRET_GENERIC_API_KEY` — must land at `MANUAL_REVIEW` as a consequence of the cap, not by
  being individually demoted. The cap is the mechanism; individual demotion would leave the next
  textual rule free to block.

### Task 3 — Rank the review queue by rarity

Compute a rarity score per release: sum over its distinct rule IDs of `log(N / frequency)`,
where `N` is the number of audited releases in the verdict store and `frequency` is how many
carry that rule.

- **Ranking only.** The score must not alter any classification. It is a reporting aid, and
  introducing an unmeasured mechanism into gating is what this whole sequence has been correcting.
- Record the score in the verdict record so it is diffable over time, and keep the store
  deterministic — the score changes when the corpus changes, so confirm this does not make every
  run rewrite every record. If it does, keep the score out of the store and compute it at report
  time instead. State which you chose.
- Surface the top-ranked releases and their rarest contributing rules in the run summary.

### Task 4 — Correct the documentation

The README's classification table describes `BLOCK` in terms that no longer match. Update it to
say `BLOCK` is restricted to structural facts, name them, and state plainly that behavioural
findings inform review and never remove a plugin.

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

1. **Reproduce the incident classification first.** On `dev`, assert a fixture tripping
   `SHELL_CURL_PIPE` classifies `BLOCK`. Record it. That is the behaviour being removed.

2. **The cap works — negative control for Task 2.** Same fixture, after the change: assert it
   classifies `MANUAL_REVIEW`, and that the finding is **still present** with its `rule_id`.
   Repeat for all six incident rules. A test asserting only the classification would pass an
   implementation that drops findings.

3. **Structural rules still block.** Assert a fixture with a path-traversing archive member
   classifies `BLOCK`, and likewise for a setuid member and a simulated ClamAV signature hit.
   If Task 2 is implemented by capping everything, this fails. It must.

4. **An unknown rule in `blockable_rules` is not silent.** Add a typo'd ID and assert it is
   reported, not ignored.

5. **Precedence with #16 is deterministic.** Override a structural rule *down* via
   `rule_classifications` and assert the documented precedence holds. State which wins and why.
   Ambiguous precedence between two policy mechanisms is a defect regardless of which order is
   chosen.

6. **The rarity score changes nothing.** Assert that adding or removing the score leaves every
   release's classification identical across the corpus. This is the guard against a reporting
   aid quietly becoming a gate.

7. **Determinism survives.** Record a verdict twice with an unchanged corpus and assert
   byte-identical output, per `verdict-publication`'s guarantee. If storing the score breaks
   this, keep it out of the store — and say so.

8. **Ranking reproduces the prototype.** Compute the ranking over the committed verdict store
   and assert `unifideck`, `decky-music` and `Friendeck` occupy the top three, with `CheatDeck`
   last. Report the actual scores.

9. **Mutation test.** Remove the cap and confirm step 2 goes red while step 3 stays green.

10. **Full suite and gate posture.** `uv run pytest` plus
    `scripts/orchestration/run-quality-gates`. Baseline is 264 passed / 21 subtests. Enforcement
    must remain `report-only`; this sub-plan does not re-enable gating.

### Explicitly not verified

- **This does not make `BLOCK` correct, only defensible.** The structural rules have never fired
  on this corpus, so their true-positive rate is unmeasured — they are trusted on the argument
  that they cannot false-positive, not on evidence that they catch anything.
- Rarity ranking inherits the existing false positives. `unifideck` and `decky-music` rank top
  partly on vendored-library `SECRET_*` matches. The ranking misplaces them; it does not remove
  them.
- Whether to re-enable enforcement is out of scope and remains a human decision.
- The ~107 plugins inherited from the upstream Decky catalogs are still not audited at all.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished structural-blocking
```

This writes:

```text
/tmp/decky-plugins-extended/structural-blocking_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer structural-blocking`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/structural-blocking-review-*.md
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
   scripts/orchestration/clear-finished structural-blocking
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
   git add docs/review/structural-blocking-review-*.md
   git commit -m "docs(review): record structural-blocking review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished structural-blocking
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer structural-blocking` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed structural-blocking
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize structural-blocking
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/structural-blocking_finalized
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
scripts/orchestration/finalize structural-blocking
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/structural-blocking_finished
/tmp/decky-plugins-extended/structural-blocking_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
