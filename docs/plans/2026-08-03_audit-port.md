# Plan: Port the plugin security auditor with correct cache invalidation (audit-port)

## Context

This lands `audit_plugins.py` (~2773 lines), `security-policy.yml`, and
`security-allowlist.yml` from the fork, plus the dependency and ignore-file changes they need.

The auditor stays **advisory** in this sub-plan. It writes reports and nothing consults them;
`security-policy.yml` stays at `mode: report-only`. Gating arrives in `catalog-gate`, and it
is deliberately not wired here so a broken scanner cannot empty the store.

Two of the fork's cache defects are fixed here rather than later, because shipping the cache
wrong once means every later sub-plan debugs against stale verdicts.

The auditor never executes plugin code: two `subprocess.run` sites total, both for git and
external scanners, no `eval`, no `npm install`/`pip install` inside plugin trees. Preserve
that property — it is the whole reason this is safe to run in CI.

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

**This sub-plan is #2: `audit-port`.**  Depends on `release-utils` being merged into `dev`.

**Slug used throughout this plan:** `audit-port`

---

## Orchestration Contract

**Slug:** `audit-port`

**Plan file:**

```text
docs/plans/2026-08-03_audit-port.md
```

**Implementation branch:**

```text
feat/audit-port
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/audit-port_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/audit-port_finalized
```

**Review notes:**

```text
docs/review/audit-port-review-*.md
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
git checkout -b feat/audit-port
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_audit-port.md
git commit -m "docs(plan): add audit-port implementation plan"
```

---

## Implementation Tasks

- Add `security-reports/` and `.audit-cache/` to `.gitignore`.
- Add `PyYAML` to `[project].dependencies` in `pyproject.toml`.
- Run `uv lock` **in this repo**. Do not copy the fork's `uv.lock`: the fork's regeneration
  dropped the `[options]` block (`exclude-newer`, `exclude-newer-span`, and the
  `[options.exclude-newer-package] pyludusavi = false` pin). Confirm those three keys are
  still present in the regenerated lock before committing.

- Copy `audit_plugins.py`, `security-policy.yml`, `security-allowlist.yml`.
- `audit_plugins.py:2298-2302` is a no-op `pass`; the real cache lookup happens at 2320-2324,
  *after* `download_zip()` at 2312. Restructure so the release ID and the cached report are
  checked before the download, and the ZIP is fetched only on a cache miss.
- The cache key needs `artifact_sha256`, which is not known before download. Key the
  pre-download index on `(repository, release_id, audit_context_hash,
  resolved_tag_commit_sha)` where `release_id = f"{tag_name}@{asset['id']}"` (the form
  already built at line 2299). Store those fields plus the observed `artifact_sha256` in the
  record, reject entries whose context or resolved source commit differs, and re-validate the
  SHA after any download that does occur.
- Asset ID alone is **not** sufficient. A replaced asset does get a new ID, but the audit also
  reads the tag's source tree and diffs it against the ZIP
  (`audit_plugins.py:1778-1786, 2288-2302`). Tags are mutable, so an unchanged asset ID can
  otherwise return a report produced before the tag moved — hence `resolved_tag_commit_sha`
  in the key.
- Keep `security-policy.yml` at `mode: report-only` for now. Task 7 introduces gating through
  the generator, not through the workflow exit code.

There are two independent caches and both are broken. Fixing only the workflow one leaves
local and PR runs returning stale verdicts.

- **Workflow layer.** `.github/workflows/scheduled-security-audit.yml:58` computes
  `POLICY_HASH` over `security-policy.yml audit_plugins.py plugin_release_utils.py
  pyproject.toml`. The comment two lines above claims the allowlist is included. It is not.
  Add `security-allowlist.yml` to the `sha256sum` argument list.
- **Local layer.** `_cache_key()` (`audit_plugins.py:1885-1902`) mixes in only the constant
  `POLICY_VERSION` (`audit_plugins.py:60-64`) — neither policy nor allowlist *content*. Edit
  either file locally and the on-disk `.audit-cache/` still returns the old verdict. Compute
  an `audit_context_hash` over the effective policy, the allowlist, and the audit
  implementation; include it in `_cache_key()` and in every cached record. This is the same
  hash Task 3 puts in the pre-download index.

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

1. **Lock integrity and the dependency actually landed.** The three `[options]` keys already
   exist, so asserting only on them passes against an implementation that did nothing. Assert
   the new dependency first:
   ```bash
   set -o pipefail
   grep -qE '^[[:space:]]*"PyYAML",' pyproject.toml || { echo "FAIL: PyYAML not added"; exit 1; }
   grep -qE '^name = "pyyaml"$' uv.lock || { echo "FAIL: pyyaml absent from lock"; exit 1; }
   for k in 'exclude-newer' 'exclude-newer-span' 'pyludusavi'; do
     grep -q "$k" uv.lock || { echo "FAIL: uv.lock lost $k"; exit 1; }
   done
   echo "PASS: dependency added, lock options intact"
   ```

2. **The cache actually prevents the download.** Run the same audit twice against one fixture
   repo with a populated `.audit-cache/`, instrumenting or logging `download_zip()` entry.
   Assert the second run logs zero download-start lines. Then delete `.audit-cache/` and
   assert the third run logs exactly one. An implementation that always downloads passes
   neither half.

3. **Allowlist edits bust the workflow cache.** Compute `POLICY_HASH` using the workflow's own
   command, record it, append a comment line to `security-allowlist.yml`, recompute, assert
   the two differ. **Run this before the fix and record the failure** — against the fork's
   code the hash is unchanged.

4. **Allowlist edits bust the local cache.** Same shape, one layer down: audit a fixture,
   confirm a second run hits the cache, then edit `security-allowlist.yml` and confirm the
   third run does *not*. This fails against the fork, where `_cache_key()` mixes in only the
   constant `POLICY_VERSION`.

5. **A moved tag busts the cache.** Cache a verdict for a release, repoint the fixture tag at
   a different commit without touching the asset, re-audit, and assert a fresh audit runs.
   This is what `resolved_tag_commit_sha` in the key is for; without it the stale report is
   returned.

6. **The auditor still executes nothing (negative control, runs last).** Audit a fixture
   plugin whose `setup.py`/`package.json` install hook writes a sentinel file. Assert the
   sentinel does not exist after the audit.

7. **Full suite.** `uv run pytest`. Record the pass/fail tally, not a conclusion.
   `scripts/orchestration/run-quality-gates` additionally enforces `ruff check` and
   `ruff format --check`; the tree was linted and formatted clean on `main` in `70ca22b`,
   so any violation is from this branch.

### Explicitly not verified

- **False-positive rate is unmeasured.** This is why the auditor stays advisory here.
- **ClamAV, Trivy, and Semgrep paths** only execute when those binaries are on the runner.
  Local runs take the "unavailable" branch, leaving the scanner-output parsing untested.
- No gating behaviour whatsoever — that is `catalog-gate`.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished audit-port
```

This writes:

```text
/tmp/decky-plugins-extended/audit-port_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer audit-port`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/audit-port-review-*.md
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
   scripts/orchestration/clear-finished audit-port
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
   git add docs/review/audit-port-review-*.md
   git commit -m "docs(review): record audit-port review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished audit-port
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer audit-port` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed audit-port
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize audit-port
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/audit-port_finalized
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
scripts/orchestration/finalize audit-port
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/audit-port_finished
/tmp/decky-plugins-extended/audit-port_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
