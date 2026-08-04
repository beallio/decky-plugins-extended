# Plan: Publish a human-readable audit page so verdicts are visible without reading JSON (audit-transparency)

## Context

Audit verdicts are invisible unless you read JSON or dig through Actions logs.

The published site contains only `index.html`, `plugins.json` and `testing_plugins.json`.
`static/index.html` has zero audit references. If a release were excluded, the complete set of
places recording that fact would be:

- `security-verdicts.json` in the repository;
- the job summary on that Actions run;
- an artifact that expires after 90 days.

A user browsing the store would see the plugin simply absent — indistinguishable from one that
was never added. The plugin author would not be told at all, and would have no channel to
contest it. Given that all eight `BLOCK` verdicts produced so far were false positives, that is
not a hypothetical concern.

This is also how the 2026-08-04 incident went undetected until it was too late: the eight
blocks were found by aggregating the JSON by hand, not because anything surfaced them.

### Why this belongs before enforcement

Removing a plugin from a live store with no visible explanation anywhere is worse than not
removing it. Publishing the audit is the honest counterpart to acting on it.

### Mechanism already exists

`generate_json.py` writes `public/` and copies `static/` in on every build
(`generate_json.py:369-380`, `644-657`). Cloudflare Pages runs that generator from a fresh clone,
and `security-verdicts.json` is a tracked file, so the verdict data is available at build time.
An audit page is one more generated file in the same build — no new infrastructure, no new
deploy path, and no dependency on the audit itself running.

### The framing problem

41 of 42 audited releases currently carry at least one `MANUAL_REVIEW` rule. A page announcing
"31 plugins need review" would be alarming, misleading, and would make well-behaved plugins look
suspect. `MANUAL_REVIEW` on this corpus overwhelmingly means "does ordinary system integration on
SteamOS".

The page must make the tiers legible to a non-expert: `BLOCK` means a structural fact with no
innocent explanation, everything else is context for a human. Getting this wrong would damage
plugin authors for no security benefit.

---

**Slug used throughout this plan:** `audit-transparency`

---

## Orchestration Contract

**Slug:** `audit-transparency`

**Plan file:**

```text
docs/plans/2026-08-04_audit-transparency.md
```

**Implementation branch:**

```text
feat/audit-transparency
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-transparency_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-transparency_finalized
```

**Review notes:**

```text
docs/review/audit-transparency-review-*.md
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
git checkout -b feat/audit-transparency
```

Commit this plan first:

```bash
git add docs/plans/2026-08-04_audit-transparency.md
git commit -m "docs(plan): add audit-transparency implementation plan"
```

---

## Implementation Tasks

### Task 1 — Generate a published audit page

Have `generate_json.py` write `public/audit.html` from the committed `security-verdicts.json`
during the normal build.

Content, per audited release: repository, release, classification, the rule IDs behind it, and
when it was audited. Group or sort so anything `BLOCK` is unmissable at the top.

Constraints:

- **Rule IDs only. Never evidence.** The verdict store already excludes evidence strings; do not
  reintroduce them here. This page is public.
- **A missing or empty verdict store must render a valid page**, not crash the build and not
  emit a broken one. Cloudflare builds on every push, including before any audit has run.
- No network access at render time, and no JavaScript that fetches anything — this is a static
  page built from a local file.
- Keep it dependency-free. Do not add a templating library for one page.

### Task 2 — Frame the tiers honestly

The page must explain, in plain language a plugin user can follow:

- `BLOCK` means a deterministic structural fact — malware signature, archive traversal, setuid
  bit, zip bomb — with no innocent explanation, and is the only tier that can remove a plugin.
- `MANUAL_REVIEW` means a human should look, **not** that the plugin is dangerous. State the
  measured context: most Decky plugins trip these because SteamOS has a read-only root and
  useful plugins need sudo, mount or systemctl.
- Say plainly that a passing audit does not prove a plugin is safe.
- State the current enforcement mode, read from `security-policy.yml` rather than hardcoded, so
  the page cannot claim plugins are being blocked while the gate is report-only.

Do not present rule counts as a severity score. A plugin with eleven baseline findings is not
worse than one with two rare ones — that is precisely the inversion the rarity ranking exists to
correct.

### Task 3 — Machine-readable alongside it

Write `public/audit.json` with the same data, so the audit is consumable without scraping HTML.
Same constraints: no evidence, valid output when the store is empty.

### Task 4 — Link it from the landing page

Add a link from `static/index.html` to the audit page. Keep it consistent with the existing
page's style; do not restyle the landing page as part of this.

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

1. **Demonstrate the gap first.** On `dev`, run the generator and assert no file in `public/`
   mentions any audit verdict. That is the current state and the reason for this sub-plan.

2. **The page renders with an empty store — run before the happy path.** Delete or empty
   `security-verdicts.json`, run the generator, and assert it exits 0 and `public/audit.html`
   exists and is valid. Cloudflare builds before any audit has run, so this is the common case
   on a fresh clone, not an edge case.

3. **A missing store does not crash the build.** Remove the file entirely and assert the
   generator still succeeds and still writes both catalogs. The audit page must never be able to
   take the store offline.

4. **No evidence leaks — the safety control.** Render from a fixture verdict store, then assert
   `public/audit.html` and `public/audit.json` contain no `evidence` key, no secret-shaped value,
   and no file contents. Run this before trusting anything else.

5. **BLOCK is unmissable.** Fixture with one `BLOCK` among many `MANUAL_REVIEW` records; assert
   the blocked entry appears before any non-blocked entry in the rendered output.

6. **Enforcement mode is read, not asserted.** Set `mode: report-only` and assert the page says
   nothing is currently being excluded; set `enforce` and assert it says the opposite. A page
   that hardcodes either claim can be wrong in the most damaging direction.

7. **Negative control — real data (runs last).** Render from the committed 42-release store and
   report: total releases, the classification counts, and which entries appear at the top. State
   the numbers.

8. **Mutation test.** Break the audit-page write and confirm step 5 goes red while the catalog
   files are still produced.

9. **Full suite and posture.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`.
   Baseline is 274 passed / 21 subtests. Enforcement stays `report-only`; this sub-plan does not
   change gating.

### Explicitly not verified

- **No real Cloudflare deploy is exercised.** The generator's output is checked; whether the page
  renders acceptably in a browser is not, and is worth a manual look before promoting.
- Notifying plugin authors when their plugin is blocked — a GitHub issue on their repository, or
  similar — is deliberately out of scope. It is the natural next step and involves writing to
  repositories the project does not own, which needs its own decision.
- The page reports verdicts; it makes no claim that the verdicts are correct. Eight of the
  historical `BLOCK`s were false positives.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-transparency
```

This writes:

```text
/tmp/decky-plugins-extended/audit-transparency_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-transparency`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-transparency-review-*.md
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
   scripts/orchestration/clear-finished audit-transparency
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
   git add docs/review/audit-transparency-review-*.md
   git commit -m "docs(review): record audit-transparency review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-transparency
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-transparency` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-transparency
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-transparency
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-transparency_finalized
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
scripts/orchestration/finalize audit-transparency
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-transparency_finished
/tmp/decky-plugins-extended/audit-transparency_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
