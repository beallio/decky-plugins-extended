# Plan: Exclude BLOCKed releases from the catalog without looping the rebuild (catalog-gate)

## Context

This is where the audit starts affecting the catalog. Gate level is `BLOCK` only;
`AUDIT_ERROR` and `MANUAL_REVIEW` still ship. See the decision table in
`docs/audit-gating-overview.md`.

**The two halves must ship together.** Gating without the `check_for_updates.py` fix creates an
infinite rebuild loop: a held-back release is permanently absent from the live catalog, so
`changed=true` fires every 6 hours forever and triggers a Cloudflare rebuild each time. Do not
mark this round complete with only Task A done.

Both defects here are invisible in the fork, because the fork never turns gating on. Neither
makes an existing test fail.

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

**This sub-plan is #5: `catalog-gate`.**  Depends on `audit-verdicts`. This is the sub-plan that changes what users install.

**Slug used throughout this plan:** `catalog-gate`

---

## Orchestration Contract

**Slug:** `catalog-gate`

**Plan file:**

```text
docs/plans/2026-08-03_catalog-gate.md
```

**Implementation branch:**

```text
feat/catalog-gate
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/catalog-gate_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/catalog-gate_finalized
```

**Review notes:**

```text
docs/review/catalog-gate-review-*.md
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
git checkout -b feat/catalog-gate
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_catalog-gate.md
git commit -m "docs(plan): add catalog-gate implementation plan"
```

---

## Implementation Tasks

### A. Gate the catalog

In `generate_json.py`, inside the release loop at lines 385-394:

- After `build_version_object()` returns a non-`None` `v_obj`, look up the release's
  classification.
- If it is `BLOCK`, skip the release: append it to neither `testing_versions` nor
  `stable_versions`. Print a line naming the plugin, the tag, and the blocking rule IDs.
- Any other classification, including `AUDIT_ERROR` and `MANUAL_REVIEW`, appends as today.
- **Skipping the append is not sufficient for plugins already in the catalog.**
  `merge_plugin_versions()` (`generate_json.py:288-304`) only adds and replaces — it never
  removes. A blocked version already present in the catalog fetched at
  `generate_json.py:348-349` therefore survives the merge and can sort back to
  `versions[0]`. Before merging, actively remove versions corresponding to blocked releases
  from `existing_stable` and `existing_testing`, matching on the normalized version name
  **and** the audited artifact hash, then sort the reconciled list. Only then does the
  fallback actually put the newest passing release at the head.
- The existing guard at line 396 (`if not testing_versions: continue`) means a plugin whose
  every release is blocked disappears from the catalog entirely. That is correct. Make it log
  distinctly from the "no valid releases" case so the two are separable in CI output.

Load verdicts once before the repo loop at line 360; do not read the file per release.

### B. Stop the gate from spinning the rebuild loop

**Both** contributors to `changed` must apply the gate — `changed = bool(upstream or custom)`
at `check_for_updates.py:88`, so fixing one leaves the loop intact.

- `check_custom_repos()` (`check_for_updates.py:53-75`) picks the highest semver
  non-prerelease release straight from GitHub. Give it access to the verdict store and have
  it skip `BLOCK`ed releases.
- `check_upstream()` (`check_for_updates.py:41-50`) independently walks the **upstream Decky
  catalog** (`g.PLUGINS_URL`) and reports its newest version missing from live. Gating an
  upstream plugin's release makes it permanently missing, so this loops too. Apply the same
  gate here.

The cleaner alternative to patching both: build one gate-filtered expected catalog and
compare live output against that, so there is a single place the gate is applied.

Without this fix, `changed=true` fires on every scheduled run forever and triggers a
Cloudflare rebuild every 6 hours.

Verify by asserting `changed=false` on a second consecutive run against a fixture where the
newest release is blocked — see Verification step 5.

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

1. **The rebuild loop is closed.** Fixture: a plugin whose newest release audits `BLOCK` and
   whose previous release passes. Run `generate_json.py`, publish the output as the live
   catalog fixture, then run `check_for_updates.py` twice. Assert `changed=false` both times.
   **Run this before the fix and record `changed=true`** — otherwise you have not proven the
   step can fail.

2. **Both contributors are gated.** Repeat step 1 twice more: once with the blocked release
   belonging to a plugin from `additional_plugins.txt` (exercises `check_custom_repos()`), and
   once with it belonging to a plugin from the upstream Decky catalog (exercises
   `check_upstream()`). Fixing only one leaves `changed = bool(upstream or custom)` true.

3. **Blocked version already in the fetched catalog is removed.** Seed the fetched catalog
   fixture with the blocked version already present, run generation, and assert it is gone
   from the output. `merge_plugin_versions()` only adds and replaces
   (`generate_json.py:288-304`), so an implementation that merely skips the append leaves it
   in place and it can sort back to `versions[0]`.

4. **Fully-blocked plugin disappears, and says why.** Fixture where every release is blocked.
   Assert the plugin is absent from both catalogs and that the log line is distinguishable
   from the existing "No valid releases found" message.

5. **Negative control — the gate excludes and falls back (runs last).** Fixture plugin with
   three releases, newest audits `BLOCK`. Assert on **normalized** version names and artifact
   hashes, not raw tags: `normalize_version()` strips the leading `v`, so a blocked tag
   `v2.0.0` is trivially "absent" from a catalog storing `2.0.0` even with no gate at all
   (`generate_json.py:198-211, 238-245`).
   - the blocked release's normalized version **and** artifact hash are absent from both
     `plugins.json` and `testing_plugins.json`;
   - the fallback release's normalized version and hash are at `versions[0]`;
   - the plugin itself is still present.

6. **Mutation test.** Delete the `BLOCK` branch and re-run step 5. It must go red. If it stays
   green the gate is not wired into the code path that builds the catalog.

7. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- **Fail-open ships unaudited artifacts during an outage.** A first-seen release whose audit
  cannot run is admitted with no verdict. That is the settled policy, but the catalog gives
  users no signal it happened. A degraded-state marker is not designed here.
- **False-positive rate remains unmeasured**, which is why the gate is `BLOCK`-only. Before
  tightening to `MANUAL_REVIEW`, audit the full `additional_plugins.txt` and read every
  finding by hand.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished catalog-gate
```

This writes:

```text
/tmp/decky-plugins-extended/catalog-gate_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer catalog-gate`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/catalog-gate-review-*.md
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
   scripts/orchestration/clear-finished catalog-gate
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
   git add docs/review/catalog-gate-review-*.md
   git commit -m "docs(review): record catalog-gate review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished catalog-gate
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer catalog-gate` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed catalog-gate
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize catalog-gate
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/catalog-gate_finalized
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
scripts/orchestration/finalize catalog-gate
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/catalog-gate_finished
/tmp/decky-plugins-extended/catalog-gate_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
