# Plan: Make Trivy actually scan dependencies and enable Semgrep with pinned rules (dependency-and-static-analysis)

## Context

Two of the three scanner tiers are not doing anything. The pattern rules — the weakest tier —
are the only thing that has been running, and they produced eight false-positive `BLOCK`
verdicts on the first real audit.

### Trivy has never scanned anything

`run_trivy()` (`audit_plugins.py:1947-1970`) runs `trivy fs` against the **extracted release
ZIP**. Decky release ZIPs contain a bundled frontend and no lockfile. Verified against a real
release, `Teppichseite/RetroDECKY`:

```
manifests in the ZIP:  RetroDECKY/package.json
lockfiles in the ZIP:  none
node_modules:          none
```

`trivy fs` needs a lockfile to resolve concrete dependency versions; a bare `package.json` with
version ranges gives it nothing to report. The result across the 41-repository run:

```
trivy   passed   41       (zero findings)
```

A scanner that always passes is indistinguishable from one that is not running. `trivy` is
`enabled: true, required: true` in `security-policy.yml`, and the README advertises
"Dependency vulnerabilities: Trivy filesystem scan" — so this is currently false assurance.

The lockfiles exist, just not in the artifact. Confirmed in the source repositories:

```
Teppichseite/RetroDECKY   pnpm-lock.yaml, requirements.txt, scripts/requirements.txt
lopesleo/DeckTools        pnpm-lock.yaml
snoein/decky-insignia     pnpm-lock.yaml, requirements.txt
```

### Semgrep has never run

`security-policy.yml` has `semgrep: enabled: false`, and semgrep is not installed by
`scheduled-security-audit.yml` (which installs clamav and trivy only). Status was `skipped` on
all 41 repositories.

`run_semgrep()` (`audit_plugins.py:2104-2132`) invokes `--config auto`. That resolves rules from
the Semgrep registry at scan time, which means a network dependency inside the audit and
telemetry to a third party. Both are decisions worth making deliberately rather than inheriting.

### Why this matters more than tuning the pattern rules

Semgrep parses code into a syntax tree. It knows a comment is a comment, a string literal is not
code, and a README is not a program — which is the root cause of three of the four
false-positive classes found so far. It is a categorically better tool for this job than
regexes over raw text.

### Gate state

`catalog-gate` is currently report-only (`8325f95`), so nothing here can remove a plugin from
the live store. That is deliberate and must not change in this sub-plan.

---

**Slug used throughout this plan:** `dependency-and-static-analysis`

---

## Orchestration Contract

**Slug:** `dependency-and-static-analysis`

**Plan file:**

```text
docs/plans/2026-08-03_dependency-and-static-analysis.md
```

**Implementation branch:**

```text
feat/dependency-and-static-analysis
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/dependency-and-static-analysis_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/dependency-and-static-analysis_finalized
```

**Review notes:**

```text
docs/review/dependency-and-static-analysis-review-*.md
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
git checkout -b feat/dependency-and-static-analysis
```

Commit this plan first:

```bash
git add docs/plans/2026-08-03_dependency-and-static-analysis.md
git commit -m "docs(plan): add dependency-and-static-analysis implementation plan"
```

---

## Implementation Tasks

### Task 1 — Give Trivy something to scan

Scan the plugin's **source tree at the audited tag** for dependency vulnerabilities, in addition
to the release ZIP. The tag is already resolved — `resolved_tag_commit_sha` exists for the cache
key — so the exact source state is known.

Constraints:

- Fetch source **without executing anything**. Download the tag's tarball or use the git tree
  API; do not clone-and-build, do not run `npm install`, `pnpm install` or `pip install`. The
  auditor's never-execute property is the reason it is safe to run in CI and must survive.
- Keep scanning the ZIP too. A vulnerable dependency bundled into the artifact but absent from
  the lockfile is exactly the discrepancy worth catching.
- Attribute findings so a reader can tell whether a vulnerability came from the source lockfile
  or the shipped artifact.
- If the source cannot be fetched, that is a scanner error, not a pass. Do not report `passed`
  when nothing was scanned — that is the defect being fixed.

### Task 2 — Prove Trivy is not a no-op

Add a regression test that fails if Trivy silently scans nothing: assert that scanning a fixture
containing a lockfile with a **known-vulnerable pinned dependency** produces at least one
finding.

Use a fixture with a pinned old version and a well-known CVE. If the test cannot be made
deterministic — vulnerability databases change — assert instead that Trivy was invoked against a
path that actually contains a lockfile, and say in the session log why the stronger assertion
was not possible.

### Task 3 — Enable Semgrep with pinned rules

- Install semgrep in `scheduled-security-audit.yml` alongside clamav and trivy.
- Set `semgrep: enabled: true` in `security-policy.yml`, and leave `required: false`.
- **Replace `--config auto`.** Pin explicit rulesets — `p/security-audit` and `p/secrets` are
  reasonable starting points — or vendor a small local ruleset. Record which you chose and why.
  Do not leave rule content resolved from the network at scan time if a pinned alternative works.
- Semgrep findings must classify no higher than `MANUAL_REVIEW` on this first pass, whatever
  severity semgrep assigns. This is a new, unmeasured signal source and the evidence from
  tonight is that unmeasured rules should not reach `BLOCK`.

### Task 4 — Keep the runtime honest

`_run_scanner` gives semgrep a 180s timeout. Across 41 repositories that is up to two hours per
scheduled run, on top of the existing ~13 minutes.

Measure the actual wall-clock cost of a semgrep pass over a handful of real plugins and record
it. If the projected full-run cost is more than roughly double the current runtime, say so and
propose a mitigation — a shorter timeout, a narrower ruleset, or a slower cadence for semgrep
than for the rest of the audit. Do not silently ship a job that takes hours.

### Task 5 — Correct the documentation

The README advertises Trivy dependency scanning that has never produced a finding. Once Task 1
lands, verify the claim is true and reword it if it is not. State plainly that semgrep findings
are advisory.

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

1. **Reproduce the no-op first.** Run the current `run_trivy()` against an extracted real Decky
   release ZIP and record: zero findings, status `passed`, and that no lockfile exists in the
   scanned tree. That is the bug. A fix whose failure case was never observed is not evidence.

2. **Trivy now scans a tree containing a lockfile.** Assert the path handed to trivy for the
   source scan contains at least one of `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock` or
   `requirements.txt` for a real plugin that has one. This is the minimum bar; step 3 is
   stronger.

3. **Trivy reports a known vulnerability — the negative control.** Fixture with a pinned
   dependency carrying a known CVE; assert at least one finding is produced. If made
   non-deterministic by database drift, say so explicitly and keep step 2 as the bar.

4. **A failed source fetch is not a pass.** Force the source fetch to fail and assert the trivy
   status is an error state, not `passed`. Reporting success when nothing was scanned is the
   exact defect this sub-plan exists to fix, so it must be impossible to reintroduce silently.

5. **Nothing is executed.** Fixture whose source tree and ZIP both carry a `package.json` with a
   `postinstall` hook and a `setup.py` that writes a sentinel file. Audit it, assert the sentinel
   does not exist. This mirrors `audit-port`'s control and must still hold with source fetching
   added.

6. **Semgrep runs and is advisory.** Assert semgrep status is no longer `skipped` for a fixture,
   that its findings classify at most `MANUAL_REVIEW`, and that a semgrep finding alone never
   produces a `BLOCK` verdict.

7. **Rules are not fetched from the network at scan time**, if Task 3 pinned them. Assert the
   invocation does not use `--config auto`.

8. **Runtime is recorded, not estimated.** Report the measured wall-clock time of a semgrep pass
   over at least three real plugins, and the projected cost for 41. State the number.

9. **The gate is untouched.** `catalog-gate` tests must pass unchanged, and the enforcement mode
   must still be `report-only`. Nothing in this sub-plan may make a plugin disappear.

10. **Full suite.** `uv run pytest` plus `scripts/orchestration/run-quality-gates`. Baseline
    entering this sub-plan is 250 passed / 21 subtests.

### Explicitly not verified

- **This does not make the store safe.** It replaces a scanner that was doing nothing with one
  that does something, and adds a second opinion that understands syntax. Neither proves a
  plugin is benign.
- Semgrep's false-positive rate on Decky plugins is unmeasured, which is why its findings are
  capped at `MANUAL_REVIEW` here. Do not raise that cap in this sub-plan.
- Trivy reports known CVEs in declared dependencies. It says nothing about vendored code copied
  into a repository without a manifest entry, which is common in bundled plugin frontends.
- No judgement is made here about whether to re-enable catalog gating. That decision needs the
  pattern-rule false-positive rate brought down first, and is out of scope.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished dependency-and-static-analysis
```

This writes:

```text
/tmp/decky-plugins-extended/dependency-and-static-analysis_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer dependency-and-static-analysis`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/dependency-and-static-analysis-review-*.md
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
   scripts/orchestration/clear-finished dependency-and-static-analysis
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
   git add docs/review/dependency-and-static-analysis-review-*.md
   git commit -m "docs(review): record dependency-and-static-analysis review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished dependency-and-static-analysis
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer dependency-and-static-analysis` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed dependency-and-static-analysis
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize dependency-and-static-analysis
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/dependency-and-static-analysis_finalized
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
scripts/orchestration/finalize dependency-and-static-analysis
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/dependency-and-static-analysis_finished
/tmp/decky-plugins-extended/dependency-and-static-analysis_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
