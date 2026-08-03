# Plan: Cut the auditor's false-positive rate on generated artifacts and build-stamped metadata (scanner-precision)

## Context

The auditor's false-positive rate was unmeasured until now. Running it against
`beallio/SDH-Ludusavi` — a known-good plugin written by this repo's owner — produced
**14 findings, all of them false positives**, scoring 100 and classifying `MANUAL_REVIEW`.
Confirmed both in CI (run `30851405678`) and locally.

Breakdown:

| Rule | Count | Severity | Why it is wrong |
|---|---|---|---|
| `PRIVILEGE_SYSTEMCTL` | 5 | medium | A save-sync plugin managing a systemd **user** service is its function |
| `SENSITIVE_ENV_HARVEST` | 3 | medium | `os.environ.get("SYNCTHING_API_KEY")` is the plugin reading its own documented config |
| `EXEC_SUBPROCESS_RUN/POPEN` | 3 | medium | Ordinary subprocess use, already only `PASS_WITH_WARNINGS` |
| `MODIFIED_SOURCE_FILE` | 2 | high | `plugin.json` / `package.json` differ because Decky's build stamps the version |
| `PRIVILEGE_MOUNT` | 1 | high | Matched a build path **inside `dist/index.js.map`**, a sourcemap |

Nothing is currently broken by this: every finding classifies `MANUAL_REVIEW` or
`PASS_WITH_WARNINGS`, and `catalog-gate` excludes only `BLOCK`. The cost is to
decision-making, and `plugin-additions` is exactly a decision — it requires reading 13
repositories' reports and dropping anything that comes back `BLOCK` or `AUDIT_ERROR`. Doing
that against a scanner with this signal-to-noise ratio means either rubber-stamping
unreadable reports or rejecting legitimate plugins. Hence this sub-plan runs first.

### Insertion points (verified on `dev`)

- Static rules are applied at `audit_plugins.py:3306`, `scan_text_content(content, rel_path, ext)`,
  inside the extracted-file walk. There is **no** extension filter before this call — every
  decodable file is regex-scanned, which is how a `.map` blob reached `PRIVILEGE_MOUNT`.
- `_NON_SCRIPT_GENERATED_EXTENSIONS` already exists at `audit_plugins.py:2048-2061` and already
  contains `.map`, but it is only consulted by the source/artifact script heuristic, not by
  static scanning. Reuse it rather than defining a second list.
- The source/artifact content comparison lives at `audit_plugins.py:2327-2333` and emits
  `MODIFIED_SOURCE_FILE`. It was added and reviewed in `audit-scanners`; it is behaving as
  designed. The defect is scope, not logic.

### Scope discipline for this sub-plan

Do **not** weaken the `MODIFIED_SOURCE_FILE` detection generally. `audit-scanners` exists
because the fork compared path names and never contents; regressing that would undo it. The
allowance must be narrow and justified per file.

---

**Slug used throughout this plan:** `scanner-precision`

---

## Orchestration Contract

**Slug:** `scanner-precision`

**Plan file:**

```text
docs/plans/2026-08-03_scanner-precision.md
```

**Implementation branch:**

```text
feat/scanner-precision
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/scanner-precision_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/scanner-precision_finalized
```

**Review notes:**

```text
docs/review/scanner-precision-review-*.md
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
git checkout -b feat/scanner-precision
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_scanner-precision.md
git commit -m "docs(plan): add scanner-precision implementation plan"
```

---

## Implementation Tasks

### Task 1 — Stop scanning generated, non-source artifacts with source rules

Add an extension guard before `scan_text_content()` at `audit_plugins.py:3306` so files whose
extension is in `_NON_SCRIPT_GENERATED_EXTENSIONS` (2048-2061) are not subjected to the static
source rules.

Constraints:

- **Secret scanning must still run** on these files. `scan_for_secrets()` at 3310 is a separate
  concern — a leaked token in a `.map` or a `.json` is a real finding, and a sourcemap embeds
  original source text. Only the source-behaviour rules are being suppressed.
- `.json` is in that set and `plugin.json`/`package.json` are parsed for metadata elsewhere.
  Confirm that metadata parsing is unaffected; it does not go through `scan_text_content`.
- Record which extensions you suppressed in the report, so a reader can tell scanning was
  skipped rather than clean. Add the count to `archive_stats` or an equivalent existing field —
  do not invent a new top-level report key.

### Task 2 — Allow build-stamped metadata in the source/artifact diff

`plugin.json` and `package.json` legitimately differ between the repo source and the release
ZIP because the build stamps the version. Stop emitting `MODIFIED_SOURCE_FILE` for that case at
`audit_plugins.py:2327-2333`.

Make the allowance narrow, and in this order of preference:

1. Parse both sides as JSON and diff the keys. Suppress **only** when every differing key is a
   version-ish field (`version`, and Decky's stamped fields — inspect a real release ZIP to
   determine the exact set rather than guessing).
2. If the JSON on either side does not parse, do **not** suppress — fall through to the existing
   finding.

Do not suppress by filename alone. A `plugin.json` whose `flags` array gained `root` between
source and artifact is exactly the tampering this rule is for, and a filename-only allowance
would hide it.

### Task 3 — Reduce `SENSITIVE_ENV_HARVEST` noise on a plugin's own config

`os.environ.get("SYNCTHING_API_KEY")` in a Syncthing plugin is a plugin reading its own
documented configuration, not credential harvesting.

This is the lowest-confidence of the three fixes. Implement the narrow version: when the
environment variable name shares a stem with the plugin's own name (from `plugin.json`'s
`name`, normalised), downgrade the finding from `MANUAL_REVIEW` to `PASS_WITH_WARNINGS` rather
than dropping it. Keep `MANUAL_REVIEW` for the genuinely sensitive names the rule targets
(`AWS_*`, `GITHUB_TOKEN`, `STEAM_*`, SSH-related, and anything in the existing pattern list).

If you conclude during implementation that the stem-matching heuristic is unreliable, say so in
the session log and leave the rule unchanged rather than shipping something arbitrary. A noisy
rule is better than a wrong suppression.

### Task 4 — Make the measurement repeatable

Add a regression fixture reproducing the SDH-Ludusavi shape **offline** — no network, no new
GitHub repository, no pushing. Build a ZIP and a mocked source tree in the test that carry:

- a `dist/index.js.map` containing a build path that trips `PRIVILEGE_MOUNT`;
- `plugin.json` and `package.json` differing from source only in a version field;
- a plugin-namespaced env read;
- at least one finding that must **still** fire, so the fixture cannot pass by suppressing
  everything.

Assert the total finding count drops to only the intended survivors.

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
Failure cases run before the negative control. Run with `set -o pipefail`. Report actual
output and tallies, not conclusions. Do not push, and do not create GitHub repositories.

1. **The sourcemap false positive is gone, and provably was there.** Run the Task 4 fixture
   against `dev`'s auditor first and record `PRIVILEGE_MOUNT` firing on the `.map` file. Then
   run it against this branch and assert it does not. A test that only ever ran green proves
   nothing here.

2. **Secret scanning still reaches suppressed extensions.** Put a `ghp_` token inside the
   `dist/index.js.map` fixture and assert a secret finding is still raised. This is the step
   that catches an over-broad Task 1 — suppressing the file wholesale would make this fail.

3. **Version-only metadata drift is allowed; anything else is not.** Two cases, both required:
   - `plugin.json` differing only in `version` -> no `MODIFIED_SOURCE_FILE`;
   - `plugin.json` differing in `flags` (e.g. gaining `root`) -> `MODIFIED_SOURCE_FILE` still
     fires.
   The second is the negative control for Task 2. If it does not fail against a filename-only
   implementation, the test is not doing its job.

4. **Malformed JSON does not silently suppress.** Corrupt the ZIP's `plugin.json` so it does
   not parse, and assert the finding still fires.

5. **`audit-scanners` detection is intact.** Re-run
   `test_modified_same_path_file_detected` and confirm it still passes — a normal source file
   modified in the ZIP must still be caught. Then mutation-test: force the Task 2 suppression
   to apply unconditionally and confirm that test goes red.

6. **Env-read downgrade is scoped.** Assert a plugin-namespaced variable downgrades to
   `PASS_WITH_WARNINGS`, and that `GITHUB_TOKEN` / `AWS_SECRET_ACCESS_KEY` still classify
   `MANUAL_REVIEW`. Skip this step if Task 3 was intentionally left unimplemented, and say so.

7. **Negative control — measured improvement on the real plugin (runs last).** Re-run the
   auditor against `beallio/SDH-Ludusavi` and record the new finding count and classification
   next to the baseline of 14 findings / score 100 / `MANUAL_REVIEW`. State the number that
   remain and why each is legitimate.

   Note: locally this repository's audit returns `AUDIT_ERROR` because `trivy` and `clamav` are
   not installed and `security-policy.yml` marks them required. Record the per-scanner statuses
   and the findings list rather than the top-level classification, or run with a policy override
   that marks those scanners optional. Do not change the committed policy to make this easier.

8. **Full suite.** `uv run pytest`, plus `scripts/orchestration/run-quality-gates`. Record the
   tally. Baseline entering this sub-plan is 210 passed / 17 subtests.

### Explicitly not verified

- **This measures one plugin.** A single known-good plugin is a data point, not a
  false-positive rate. The remaining rules are unmeasured against the wider catalog.
- **The gate stays `BLOCK`-only regardless of the outcome here.** Do not propose tightening it;
  that decision needs a much larger sample.
- `PRIVILEGE_SYSTEMCTL` is deliberately left noisy. A plugin managing systemd units is worth a
  human glance even when legitimate, and it does not block anything.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished scanner-precision
```

This writes:

```text
/tmp/decky-plugins-extended/scanner-precision_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer scanner-precision`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/scanner-precision-review-*.md
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
   scripts/orchestration/clear-finished scanner-precision
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
   git add docs/review/scanner-precision-review-*.md
   git commit -m "docs(review): record scanner-precision review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished scanner-precision
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer scanner-precision` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed scanner-precision
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize scanner-precision
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/scanner-precision_finalized
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
scripts/orchestration/finalize scanner-precision
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/scanner-precision_finished
/tmp/decky-plugins-extended/scanner-precision_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
