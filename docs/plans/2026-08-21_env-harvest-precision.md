# Plan: Detect Environment Harvesting Instead Of Named Reads (env-harvest-precision)

## Context

`SENSITIVE_ENV_HARVEST` classifies reading one named environment variable as
harvesting the environment. It is the single largest cause of the audit's
undiscriminating review rate.

In the latest scheduled run, `32434670802`, 575 of 621 releases (92.6%) were
`MANUAL_REVIEW`. An independent rule review of that run's evidence found this
rule produced 486 findings with **no** true positives, and that correcting it
changes 84 of the 143 releases it touches, lowering the corpus review rate from
92.59% to 79.07%. No other rule comes close: the next largest lever changes 12
releases.

The rule is at `audit_plugins.py:1647`:

```python
re.compile(r"\bos\.environ\b.*(?:password|token|secret|key|api)", re.IGNORECASE)
```

It matches any line mentioning `os.environ` that also contains one of five
words anywhere. The observed evidence is entirely targeted reads: 97
`SYNCTHING_API_KEY` reads, 97 `SYNCTHING_API_URL` reads, 94 combined checks, 53
generic `os.environ.get(key)` helpers, and `SSLKEYLOGFILE` reads. Not one
finding copies or enumerates the environment, which is what the rule's own name
and message — "environment variable harvesting" — describe.

Note `os.environ.get(key)` matches because the *parameter is named* `key`. The
rule cannot distinguish a variable's name from a word in the surrounding line.

The two behaviors it conflates need different verdicts. Copying or iterating the
whole environment is the exfiltration-shaped act worth manual review. Reading
one named credential is ordinary plugin behavior — a Syncthing plugin reading
`SYNCTHING_API_KEY` is doing its job — but it is still worth recording. This
plan retargets the rule at harvesting and keeps targeted sensitive reads visible
at warning level, so precision improves without discarding the observation.

An existing mechanism already partially compensates.
`_downgrade_plugin_namespaced_env_findings()` demotes reads whose variable name
is namespaced to the plugin, guarded by `_PROTECTED_ENV_PREFIXES` and a
`PRIVATE_KEY` suffix check. It did not catch these findings. Whatever this plan
does must leave that protection coherent rather than duplicated or bypassed.

This change reduces detection, which is the direction that requires the most
care. A narrowed pattern that no longer fires on a real harvesting construct
would be a worse outcome than the current noise. The corpus contains no true
positive to preserve, so correctness must be established against constructed
fixtures rather than against existing findings.

Expected implementation scope is the rule table and env-finding handling in
`audit_plugins.py`, focused tests, and current documentation. Changing other
rules, the policy or allowlist files, the scanner bootstrap, the worklist
producer, the shard data plane, aggregation, or `security-verdicts.json` is
outside this plan. Do not regenerate or rewrite audit evidence.

**Slug used throughout this plan:** `env-harvest-precision`

---

## Orchestration Contract

**Slug:** `env-harvest-precision`

**Plan file:**

```text
docs/plans/2026-08-21_env-harvest-precision.md
```

**Implementation branch:**

```text
feat/env-harvest-precision
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/env-harvest-precision_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/env-harvest-precision_finalized
```

**Review notes:**

```text
docs/review/env-harvest-precision-review-*.md
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
git checkout -b feat/env-harvest-precision
```

Commit this plan first:

```bash
git add docs/plans/2026-08-21_env-harvest-precision.md
git commit -m "docs(plan): add env-harvest-precision implementation plan"
```

---

## Implementation Tasks

### Task 1 — Write the detection fixtures before changing the rule

The corpus contains no true positive for this rule, so the safety of narrowing
it can only be established against constructed cases. Build those first.

- Add a fixture set of genuine harvesting constructs that must be classified
  `MANUAL_REVIEW`. Cover at least, in Python: `dict(os.environ)`,
  `os.environ.copy()`, `{**os.environ}`, iteration such as
  `for k, v in os.environ.items()`, `list(os.environ)`, `json.dumps(dict(os.environ))`,
  and passing the whole mapping onward as in `requests.post(url, json=dict(os.environ))`.
  In JavaScript/TypeScript: `{...process.env}`, `Object.keys(process.env)`,
  `Object.entries(process.env)`, and `JSON.stringify(process.env)`.
- Add a fixture set of targeted reads that must **not** be `MANUAL_REVIEW`:
  `os.environ.get("SYNCTHING_API_KEY")`, `os.environ["SSLKEYLOGFILE"]`,
  a helper whose parameter is literally named `key`, and `process.env.SOME_TOKEN`.
- Assert the current rule fails both ways: it misses the harvesting constructs
  that contain none of the five trigger words, and it fires on the targeted
  reads. Record both directions in the red log; a red phase that only shows one
  is incomplete.
- Add a case pinning the protections that must survive: a read of a
  `_PROTECTED_ENV_PREFIXES` variable and one ending in `PRIVATE_KEY` must not be
  silently demoted by plugin-name namespacing.

### Task 2 — Retarget the rule at harvesting

- Replace the pattern so it matches whole-environment access rather than a
  co-occurring keyword. Detect copying, expansion, iteration, serialization, and
  enumeration of `os.environ` and `process.env`. Do not key on variable-name
  words at all; the name of the variable is not what makes an access harvesting.
- Keep the rule ID, severity, and `MANUAL_REVIEW` classification. The rule's
  meaning is being corrected, not its verdict.
- Cover both language families. The extension dispatcher already combines rule
  tables; follow the existing convention for a JS counterpart rather than
  inventing a new mechanism, and if a separate JS rule ID is the established
  pattern, say so in the commit message.
- State in a comment what the pattern deliberately does not catch — indirect
  access through an alias, `os.getenv` in a loop over a name list, dynamically
  built mappings — so the next reader knows the boundary is chosen rather than
  accidental.

### Task 3 — Keep targeted sensitive reads visible at warning level

Narrowing must not simply delete the observation.

- Emit a distinct finding for a read of a *named* environment variable that
  looks credential-bearing, classified `PASS_WITH_WARNINGS`. Match on the
  variable name captured from the access — as `_ENV_ACCESS_PATTERN` already
  does — not on words elsewhere in the line, so a parameter named `key` cannot
  trigger it.
- Give it its own rule ID and message so reports distinguish "read one named
  credential" from "copied the environment". Do not reuse
  `SENSITIVE_ENV_HARVEST` for this.
- Reconcile with `_downgrade_plugin_namespaced_env_findings()`. If that
  demotion becomes redundant now that targeted reads start at warning level,
  remove it and say why in the commit message; if it still does work, keep it
  and make clear which findings it applies to. Do not leave two overlapping
  mechanisms whose interaction has to be traced to predict a verdict.
  `_PROTECTED_ENV_PREFIXES` and the `PRIVATE_KEY` suffix must keep their
  protective effect either way.

### Task 4 — Update current documentation

Update `README.md` and `docs/audit-gating-overview.md` only where they describe
environment-related findings, so the rule descriptions match what now triggers
`MANUAL_REVIEW` versus a warning.

Do not restate corpus statistics as guarantees, do not rewrite historical
capacity evidence or prior review notes, and do not characterize the audit as
more precise overall on the strength of one rule.

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

Every check must report its real exit status and tallies. A missing fixture or
command is a failure, not an implicit pass.

### 1. Record the red phase

After adding the Task 1 fixtures and before changing the rule:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_audit_plugins.py \
  tests/test_secret_rule_precision.py \
  tests/test_audit_documentation.py \
  2>&1 | tee /tmp/decky-plugins-extended/env-harvest-precision-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

The log must show failures in **both** directions: harvesting constructs not
detected, and targeted reads wrongly classified `MANUAL_REVIEW`. A red phase
showing only one direction does not establish this one.

### 2. Prove detection is not lost

This is the check that decides whether the change is safe to keep, because the
corpus contains no true positive to fall back on.

Run every harvesting fixture from Task 1 through the real classification path
and require each to be `MANUAL_REVIEW`. Record each construct and its resulting
classification in a table under
`/tmp/decky-plugins-extended/env-harvest-precision-detection.log`. Any construct
that a reasonable reader would call harvesting and that the new pattern does not
catch must be listed explicitly in that log as a known gap, not quietly omitted.

### 3. Measure the effect against real evidence, without changing it

Using the preserved aggregate report from run `32434670802` at
`/tmp/claude-1000/-home-beallio-Dropbox-Scripts-decky-plugins-extended/57f86a73-119a-4167-a06a-55f1718016ab/scratchpad/lastaudit/security-report.json`,
re-evaluate the new pattern against the `evidence` strings of the existing
`SENSITIVE_ENV_HARVEST` findings and report:

- how many of the 486 findings the new pattern still matches;
- how many distinct releases would remain `MANUAL_REVIEW` on this rule alone;
- whether the independently reported figure of 84 of 143 releases changing is
  reproduced, and if not, why.

This is a read-only measurement. Do not modify that file, do not re-run the
audit, and do not treat a mismatch with the reported figure as a reason to
adjust the pattern — investigate and report the discrepancy instead.

### 4. Exercise the failure controls, then the valid controls

- a read of an `_PROTECTED_ENV_PREFIXES` variable is not demoted by plugin-name
  namespacing;
- a variable name ending in `PRIVATE_KEY` is not demoted;
- a helper whose parameter is named `key` produces no `MANUAL_REVIEW`;
- a targeted credential read still produces a recorded finding at
  `PASS_WITH_WARNINGS` — it must not disappear from the report entirely;
- the existing secret-rule precision tests still pass unchanged.

Then the valid controls: every harvesting fixture is `MANUAL_REVIEW`, every
targeted-read fixture is not, and a report containing both carries two
distinguishable rule IDs.

### 5. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation that widens
the new pattern back toward keyword co-occurrence, and require a targeted-read
test to fail because of it. Then make a second temporary mutation that removes
one harvesting alternative, and require the corresponding detection test to
fail. Save both diffs under
`/tmp/decky-plugins-extended/env-harvest-precision-mutation-*.patch`, reverse
each with `git apply -R`, rerun to exit 0, and verify `git diff --exit-code`.
Do not restore with a destructive checkout or reset.

Two mutations are required here because this change can fail in two opposite
directions, and a single mutation proves only one of them.

### 6. Run the complete repository gate

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git diff --check
base_commit=$(git merge-base dev HEAD)
git diff --exit-code "$base_commit..HEAD" -- security-verdicts.json
worktree_status=$(git status --porcelain)
if [[ -n "$worktree_status" ]]; then
  printf '%s\n' "$worktree_status" >&2
  exit 1
fi
```

Require Ruff check, Ruff format, all pytest tests and subtests, verified
actionlint, and all actionlint negative controls to pass. Record actual
test/subtest tallies.

`uv`'s experimental OSV malware check has been failing intermittently with
`Request failed after N retries`, failing a different
`tests/test_workflow_selection.py` parametrization each time. If the gate fails
only that way, re-run and record both outcomes; do not report a network flake as
a passing gate, and do not change any test to accommodate it.

### Deferred verification

Local fixtures can prove the pattern's behavior. They cannot prove the corpus
effect. Defer until the user authorizes a run on the default branch:

1. a scheduled or dispatched run whose aggregate report shows the corpus
   `MANUAL_REVIEW` rate falling from 92.6% toward the projected 79%;
2. confirmation that no release moved from `MANUAL_REVIEW` to a lower
   classification for any reason other than this rule;
3. confirmation that targeted credential reads still appear in the report at
   warning level rather than vanishing.

A lower review rate is the intended outcome but is not by itself evidence of
correctness: the same number would result from the rule failing to fire at all.
Item 3 is what distinguishes those two outcomes and must be checked explicitly.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished env-harvest-precision
```

This writes:

```text
/tmp/decky-plugins-extended/env-harvest-precision_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer env-harvest-precision`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/env-harvest-precision-review-*.md
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
   scripts/orchestration/clear-finished env-harvest-precision
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
   git add docs/review/env-harvest-precision-review-*.md
   git commit -m "docs(review): record env-harvest-precision review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished env-harvest-precision
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer env-harvest-precision` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed env-harvest-precision
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize env-harvest-precision
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/env-harvest-precision_finalized
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
scripts/orchestration/finalize env-harvest-precision
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/env-harvest-precision_finished
/tmp/decky-plugins-extended/env-harvest-precision_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
