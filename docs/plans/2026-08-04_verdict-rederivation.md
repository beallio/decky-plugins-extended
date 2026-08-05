# Plan: Re-derive BLOCK from rule IDs so stale verdicts cannot exclude plugins (verdict-rederivation)

## Context

The catalog gate trusts a stored classification that may have been produced by rules which can
no longer block. This is the single reason enforcement is still held at `report-only`.

`structural-blocking` (#17) restricted `BLOCK` to structural facts by capping findings when they
are **classified**, during an audit. The gate reads the `classification` field that was
**already written** to `security-verdicts.json`. Those are different moments, and nothing
reconciles them.

The committed store currently holds eight `BLOCK` records written by a scheduled audit under the
old rules:

```
DeckFilter/DeckyZone                       SHELL_CURL_PIPE
PixelAddictUnlocked/allycenter             SHELL_CURL_PIPE
hostsrc/decky-prysm                        SHELL_CURL_PIPE
Kentronix57/Decky-Loader-XGMobile-Manager  DESTRUCTIVE_RM_RF, DESTRUCTIVE_RM_RF_SHELL
SavageCore/xone-decky-plugin               DESTRUCTIVE_RM_RF, DESTRUCTIVE_RM_RF_SHELL
chillibeaver/DeckSMB                       DESTRUCTIVE_RM_RF
jinzhongjia/decky-music                    SECRET_PASSWORD_LITERAL, SECRET_PRIVATE_KEY_HEADER
mubaraknumann/unifideck                    SECRET_GENERIC_API_KEY, SECRET_PRIVATE_KEY_HEADER
```

None of those rule IDs is in `blockable_rules`. A fresh audit would classify all eight
`MANUAL_REVIEW`. Enabling enforcement today would nonetheless exclude all eight — the same
false positives that were removed from the live catalog on 2026-08-04.

### Why a re-audit is not sufficient

Waiting for the scheduled audit to rewrite the store would clear this instance and leave the
defect. Every future policy change reopens the same window: Cloudflare rebuilds on every push,
while the audit that would rewrite verdicts runs six-hourly. The gap between them is when
plugins disappear.

Re-deriving at gate time closes the class permanently and makes the store's `classification`
field advisory rather than authoritative.

### The two trust points

Both must change; fixing one leaves the other exploitable.

- `classification_for()` (`audit_plugins.py:3147-3153`) — the dict-lookup path used for
  configured plugins. Returns `entry.get("classification")` verbatim.
- `catalog_version_is_blocked()` (`generate_json.py:345-360`) — the upstream-catalog path.
  Tests `entry.get("classification") == "BLOCK"` directly.

The `AuditReport` branch of `classification_for` (`audit_plugins.py:3130-3136`) is a *fresh*
audit result, already capped at classification time, and needs no change.

### Established facts, do not re-derive

- Every `BLOCK` record in the committed store carries non-empty `blocking_rule_ids` — verified,
  count is zero for the empty case. The underivable case is therefore theoretical today, but
  the plan must still specify behaviour for it.
- `blockable_rules` lives in `security-policy.yml` and is validated on load
  (`_validate_blockable_rules`).
- Enforcement is currently `report-only`, so nothing in this sub-plan can change what users see.

---

**Slug used throughout this plan:** `verdict-rederivation`

---

## Orchestration Contract

**Slug:** `verdict-rederivation`

**Plan file:**

```text
docs/plans/2026-08-04_verdict-rederivation.md
```

**Implementation branch:**

```text
feat/verdict-rederivation
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/verdict-rederivation_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/verdict-rederivation_finalized
```

**Review notes:**

```text
docs/review/verdict-rederivation-review-*.md
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
git checkout -b feat/verdict-rederivation
```

Commit this plan first:

```bash
git add docs/plans/2026-08-04_verdict-rederivation.md
git commit -m "docs(plan): add verdict-rederivation implementation plan"
```

---

## Implementation Tasks

### Task 1 — Re-derive the effective classification at gate time

A stored `BLOCK` must only be treated as blocking when at least one of its `blocking_rule_ids`
is in the current `blockable_rules`. Apply this in both trust points named in the Context.

Rules:

- Re-derivation **demotes only**. A stored `MANUAL_REVIEW` must never become `BLOCK` because
  some rule is now blockable — promotion on stale data is the same class of bug in the opposite
  direction, and would be worse.
- A stored `BLOCK` whose `blocking_rule_ids` is empty or missing cannot be re-derived. Treat it
  as **non-blocking** and surface it. This matches the project's established fail-open posture:
  a release the auditor cannot currently justify excluding should not be excluded. Record this
  decision in the session log rather than leaving it implicit.
- Keep `audit_classification` reporting what was **stored**, so a demotion is visible rather
  than silent. `VerdictResult` already separates effective from audit classification — use it.

### Task 2 — Make the demotion observable

When re-derivation demotes a stored `BLOCK`, log it during catalog generation: the plugin, the
release, the stored rule IDs, and that they are not currently blockable.

A silent correction is indistinguishable from the bug. Someone reading build output should be
able to see that the store and the policy disagree, which is the signal that a re-audit is
overdue.

Keep it to rule IDs. No evidence.

### Task 3 — Reflect it on the published audit page

`public/audit.html` and `public/audit.json` currently render the stored classification. Where
re-derivation would demote, the page must not claim a release is blocked when it would not be.

Show the effective classification, and make the stored-versus-effective disagreement legible —
a reader should understand that the verdict predates the current policy. Do not silently
overwrite the stored value in the output.

### Task 4 — Do not change enforcement

`security-policy.yml` stays at `mode: report-only` in this sub-plan. Enabling enforcement is a
separate decision that follows from this work; bundling it would make the change untestable in
isolation and repeat the mistake this sub-plan exists to correct.

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

1. **Reproduce the danger first.** On `dev`, with enforcement temporarily forced to `enforce` in
   an in-memory policy only, generate the catalog against the committed 42-release store and
   record which releases are excluded. Expect the eight named in the Context. Do not commit an
   enforcement change to do this. That output is the bug.

2. **Re-derivation demotes stale BLOCKs — negative control.** Same store, same forced
   enforcement, after Task 1: assert **zero** releases are excluded, and that all eight
   previously-excluded plugins appear in both catalogs.

3. **A genuinely blockable stored verdict still blocks.** Seed a record with
   `classification: BLOCK` and `blocking_rule_ids: ["ARCHIVE_TRAVERSAL"]`, force enforcement,
   and assert the release **is** excluded. If Task 1 is implemented by ignoring stored `BLOCK`
   entirely, this fails. It must.

4. **Demotion never promotes.** Seed `classification: MANUAL_REVIEW` with
   `blocking_rule_ids: ["MALWARE"]` — an inconsistent record — and assert it is **not**
   excluded. Re-derivation must only ever lower.

5. **The underivable case fails open.** Seed `classification: BLOCK` with empty
   `blocking_rule_ids` and assert the release is not excluded and the situation is surfaced in
   output.

6. **Both trust points are fixed.** Repeat step 2 for an upstream-catalog entry, which takes the
   `catalog_version_is_blocked` path rather than `classification_for`. Fixing one path and not
   the other is the most likely incomplete implementation.

7. **The demotion is visible.** Assert catalog-generation output names the demoted plugin, its
   release and its stored rule IDs, and contains no evidence strings.

8. **The audit page does not claim a false block.** Render from the committed store and assert a
   demoted release is not presented as blocked, while its stored verdict remains legible.

9. **Mutation test.** Remove the re-derivation from `classification_for` only, and confirm step 2
   goes red while step 3 stays green. Then remove it from `catalog_version_is_blocked` only and
   confirm step 6 goes red.

10. **Full suite and posture.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.
    Baseline is 282 passed / 21 subtests. Assert `security-policy.yml` still reads
    `mode: report-only` at the end of the round.

### Explicitly not verified

- **This does not enable enforcement**, and makes no claim that enforcement is safe to enable.
  It removes the specific reason it is currently unsafe.
- Re-derivation makes the stored `classification` advisory for gating. It does not migrate or
  rewrite the store; stale values remain on disk until the next audit overwrites them.
- `BLOCK` remains entirely unexercised on this corpus — zero true and zero false positives.
  Nothing here changes that.
- The ~107 plugins inherited from the upstream Decky catalogs are still not audited.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished verdict-rederivation
```

This writes:

```text
/tmp/decky-plugins-extended/verdict-rederivation_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer verdict-rederivation`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/verdict-rederivation-review-*.md
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
   scripts/orchestration/clear-finished verdict-rederivation
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
   git add docs/review/verdict-rederivation-review-*.md
   git commit -m "docs(review): record verdict-rederivation review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished verdict-rederivation
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer verdict-rederivation` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed verdict-rederivation
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize verdict-rederivation
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/verdict-rederivation_finalized
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
scripts/orchestration/finalize verdict-rederivation
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/verdict-rederivation_finished
/tmp/decky-plugins-extended/verdict-rederivation_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
