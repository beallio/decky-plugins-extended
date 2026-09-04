# Plan: Fix merged plugin updated dates (merged-plugin-updated-date)

## Context

When the generator merges an extended repository into an existing official plugin, it adds newer releases but leaves the official entry's top-level `updated` value unchanged. The storefront displays and sorts by this field, so merged entries can show an older date than their newest installable release. Set each merged channel's top-level `updated` value to the newest valid `versions[].created` publication timestamp across all accepted post-merge versions. Repository activity dates must not affect it. Limit implementation changes to `plugin_release_utils.py`, `generate_json.py`, and `tests/test_generate_json.py`; `static/storefront.js` already consumes the top-level field and must remain unchanged.

**Slug used throughout this plan:** `merged-plugin-updated-date`

---

## Orchestration Contract

**Slug:** `merged-plugin-updated-date`

**Plan file:**

```text
docs/plans/2026-09-04_merged-plugin-updated-date.md
```

**Implementation branch:**

```text
feat/merged-plugin-updated-date
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/merged-plugin-updated-date_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/merged-plugin-updated-date_finalized
```

**Review notes:**

```text
docs/review/merged-plugin-updated-date-review-*.md
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
git checkout -b feat/merged-plugin-updated-date
```

Commit this plan first:

```bash
git add docs/plans/2026-09-04_merged-plugin-updated-date.md
git commit -m "docs(plan): add merged-plugin-updated-date implementation plan"
```

---

## Implementation Tasks

1. In `plugin_release_utils.py`, repeat the repository-wide reference search for `_timestamp_key`. Rename it to the public `timestamp_order_key(value: Any) -> tuple[int, datetime]`, migrate every caller, and leave no compatibility alias. Preserve UTC normalization for `Z` and explicit offsets, treatment of naive timestamps as UTC, and invalid-value ordering below valid timestamps. Update `release_order_key()` to use the public name.
2. In `generate_json.py`, import `timestamp_order_key`. After `merge_plugin_versions(existing_plugin, new_versions)` finishes its existing add/replace logic and calls `sort_versions()`, examine every post-merge `existing_plugin["versions"][*]["created"]`. Select the original timestamp string with the greatest valid `timestamp_order_key` and assign it to `existing_plugin["updated"]`. If no merged version has a valid publication timestamp, leave the existing top-level value unchanged. Do not change the function signature, semantic-version ordering, latest-version selection, repository metadata, or the stable/testing callsites.
3. In `tests/test_generate_json.py`, extend `test_merge_plugin_versions_updates_and_sorts_versions`. Seed an older official top-level `updated`; include official and extended `created` values whose chronological order differs from list and semantic-version order; assert that the newest valid publication timestamp becomes the plugin-level value while version ordering and preserved download/update counters remain unchanged. Add a missing/invalid-date case that proves the original top-level value is retained when no merged version has a parseable publication timestamp.
4. Extend `test_main_annotates_merged_entries_with_the_official_version` with top-level and per-version dates. Assert that generated `public/plugins.json` sets `Merged Plugin` to the newer extended release publication timestamp and leaves `Unconfigured Plugin` at its original timestamp. This is the persisted catalog contract used by card text, detail text, and updated-date sorting.

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

1. Run `GITHUB_TOKEN=test-token uv run pytest -q tests/test_generate_json.py tests/test_plugin_release_utils.py`. Confirm focused merge coverage selects the newest valid timestamp and preserves the old value when all version dates are missing or invalid.
2. Run `GITHUB_TOKEN=test-token uv run pytest -q tests/test_generate_json.py::GenerateJsonTests::test_main_annotates_merged_entries_with_the_official_version`. Confirm the temporary generated `public/plugins.json` uses the extended release timestamp for `Merged Plugin` and preserves the original timestamp for `Unconfigured Plugin`.
3. With authenticated GitHub CLI access, run `GITHUB_TOKEN="$(gh auth token)" uv run generate_json.py`.
4. Run `uv run python -c 'import json; from plugin_release_utils import timestamp_order_key; plugins=json.load(open("public/plugins.json", encoding="utf-8")); plugin=next(item for item in plugins if item["name"] == "ProtonDB Badges"); dates=[version.get("created") for version in plugin["versions"] if timestamp_order_key(version.get("created"))[0]]; expected=max(dates, key=timestamp_order_key); assert plugin["updated"] == expected, (plugin["updated"], expected); print(f"ProtonDB Badges: {expected}")'`. Require a zero exit status and printed selected date.
5. Run `scripts/orchestration/run-quality-gates`. Require actionlint, Ruff, formatting, storefront logic, Playwright surface tests, and the complete Python suite to pass.

No verification is deferred.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished merged-plugin-updated-date
```

This writes:

```text
/tmp/decky-plugins-extended/merged-plugin-updated-date_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer merged-plugin-updated-date`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/merged-plugin-updated-date-review-*.md
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
   scripts/orchestration/clear-finished merged-plugin-updated-date
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
   git add docs/review/merged-plugin-updated-date-review-*.md
   git commit -m "docs(review): record merged-plugin-updated-date review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished merged-plugin-updated-date
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer merged-plugin-updated-date` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed merged-plugin-updated-date
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize merged-plugin-updated-date
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/merged-plugin-updated-date_finalized
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
scripts/orchestration/finalize merged-plugin-updated-date
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/merged-plugin-updated-date_finished
/tmp/decky-plugins-extended/merged-plugin-updated-date_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
