# Plan: Make Security Audit CI Quota-Safe and Resilient (quota-safe-security-audit)

## Context

The scheduled security audit is failing even though the repository's audit and workflow tests are
green. Read-only diagnosis on 2026-08-18 found two distinct failure modes:

- runs `32107414958` and `32137507797` exhausted the GitHub REST allowance, waited roughly
  39–40 minutes for reset, and then hit the audit step's 45-minute timeout;
- run `32086261218` separately stalled in `Install required security scanners` on shard 11,
  reached that step's 12-minute timeout, and left aggregation with only thirteen shard artifacts.

The quota failure is structural. Each of fourteen workers currently calls
`build_audit_worklist()` and repeats the complete repository/release enumeration. The preserved
579-release capacity snapshot records 83 baseline enumeration requests per worker, or 1,162 per
run. After sharding, `audit_plugins.py` also resolves every assigned release tag through REST
before consulting progress/cache state; across the full corpus this adds roughly another 1,158
requests on a warm run. Fresh work then uses the REST tarball endpoint and the Git tree/raw-file
APIs for source scanning and source/artifact comparison. `_gh_get()` responds to a rate limit by
sleeping until reset without regard for the surrounding Actions deadline.

Implement a single immutable run-global audit worklist and an API-free shard data plane. One
preparation job must select the corpus, enumerate each repository once, resolve immutable source
commits through Git transport, validate a canonical worklist, and publish it for this workflow run
only. The fourteen workers must retain the current release-identity SHA-256 assignment but consume
that artifact without repository, release, ref, tree, or raw-file REST requests. Aggregation must
prove that all shard evidence has the same worklist fingerprint and exactly covers the prepared
identities; counting fourteen artifacts is not sufficient.

Materialize each required source archive once from codeload at its resolved commit and reuse the
same safely extracted source snapshot for metadata, Trivy, and source/artifact comparison. Move
cache eligibility ahead of source acquisition so a valid cache hit does not fetch source. Preserve
the current digest-backed and digestless artifact validation rules, scanner classifications,
release-local `AUDIT_ERROR` behavior, run-global exit 1 behavior, and atomic progress/verdict
checkpointing.

Harden scanner installation as a separate implementation track within this plan. Replace the three
duplicated workflow bodies with one checked-in, fail-closed Bash script that provides named phase
logging, command-level time limits, and bounded retries while retaining the 12-minute outer step
limit and all required scanners. This improves the separate bootstrap failure without presenting
external package availability as guaranteed.

Keep fourteen release-level shards. Do not change to repository-level sharding: one current
repository contains 107 releases and would project beyond the PR audit's 22-minute step budget at
the observed p95 rate. Do not increase the PR/scheduled audit timeouts, scanner-install timeout,
six-hour cadence, download/archive limits, scanner requirements, enforcement mode, public catalog
schemas, or verdict publication semantics. Do not rewrite the historical capacity JSON; update
current documentation around it.

Expected implementation scope is `audit_plugins.py`, a focused worklist module if needed,
`plugin_release_utils.py`, both audit workflows, a new scanner-bootstrap script, focused tests,
the quality-gate workflow mutation anchors, `README.md`, and `docs/audit-gating-overview.md`.
Generating or deploying catalogs, changing `security-verdicts.json`, starting hosted workflows,
or modifying security findings is outside this plan.

**Slug used throughout this plan:** `quota-safe-security-audit`

---

## Orchestration Contract

**Slug:** `quota-safe-security-audit`

**Plan file:**

```text
docs/plans/2026-08-18_quota-safe-security-audit.md
```

**Implementation branch:**

```text
feat/quota-safe-security-audit
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/quota-safe-security-audit_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/quota-safe-security-audit_finalized
```

**Review notes:**

```text
docs/review/quota-safe-security-audit-review-*.md
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
git checkout -b feat/quota-safe-security-audit
```

Commit this plan first:

```bash
git add docs/plans/2026-08-18_quota-safe-security-audit.md
git commit -m "docs(plan): add quota-safe-security-audit implementation plan"
```

---

## Implementation Tasks

### Task 1 — Add failing contracts before changing runtime behavior

Write the red tests that distinguish the required design from the current fourteen independent
enumerators. Extend existing modules where they already own the contract; add a dedicated test
module only where the scanner-bootstrap shell fixture needs it.

- In `tests/test_audit_worklist.py`, add canonical worklist round-trip, schema validation,
  fingerprint, producer, worker-isolation, resume, and exact-coverage tests. The initial focused run
  must fail because no materialized-worklist CLI/schema exists and workers still enumerate.
- In `tests/test_audit_plugins.py` and `tests/test_bounded_download_callers.py`, add tests proving a
  real uncached audit uses one codeload source download, gives the same source snapshot to metadata,
  Trivy, and source/artifact comparison, and makes no ref/tree/raw/tarball REST calls.
- In `tests/test_enforcement_workflow.py`, add executable aggregation cases for a missing worklist,
  failed producer, missing shard manifest, mismatched fingerprint, missing identity, unexpected
  identity, duplicate/wrong shard, a manifest/report disagreement in either direction, and the
  valid empty-worklist case.
- In `tests/test_workflow_selection.py` and `tests/test_workflow_security.py`, add the desired
  producer-to-workers-to-aggregator dependency/artifact contract for both workflows.
- In `tests/test_plugin_release_utils.py`, add bounded API deadline and scanner-script path-selection
  cases.
- Add `tests/test_scanner_bootstrap.py` with fake `sudo`, package tools, network commands,
  `timeout`, and `GITHUB_PATH`; these tests must never contact a package service or require root.

Before implementation, run the new focused tests, record their node IDs and failing assertions,
and verify that the failures are the missing behavior rather than fixture/setup errors. Do not lock
the plan to a fixed failing-test count.

### Task 2 — Define and validate the immutable worklist

Create a focused `audit_worklist.py` module unless repository evidence demonstrates a cleaner
acyclic boundary. Keep transport/audit execution in their existing modules; do not further enlarge
`audit_plugins.py` with an unrelated serialization subsystem.

- Define a versioned canonical JSON document with a root `schema_version`, declared `fingerprint`,
  and `payload`. Compute the fingerprint as lowercase SHA-256 over the UTF-8 canonical JSON bytes of
  `payload` (`sort_keys=True`, compact separators, one documented newline policy), avoiding a
  self-referential hash.
- The payload must bind the checked-out source revision, selection mode, resolved base commit when
  applicable, canonical selected repository list, shard count, and deterministically ordered items.
  It must not contain a run timestamp or other value that breaks reproducibility.
- Normalize each item to only the data the audit consumes: canonical repository URL and archived
  state; release ID, tag, prerelease/draft state, published/created timestamps; the single eligible
  ZIP asset's ID, name, browser-download URL, and normalized GitHub digest; plus either one validated
  resolved commit SHA or a redacted source-resolution error. Derive the authoritative work identity
  from canonical repository, release ID, and asset ID.
- Strictly validate types, required and unexpected fields, canonical ordering, repository/asset URL
  ownership, eligibility, unique identities, digest shape, commit shape, selection consistency, and
  the declared fingerprint before returning any item. Reject malformed JSON, unknown schema
  versions, duplicate/extra identities, noncanonical aliases, and tampering as run-global errors.
- Preserve a valid zero-item payload for `none` selection. Write the finished document atomically;
  on repository metadata/release pagination/serialization failure, exit 1 and leave no usable
  worklist or partial file.
- Add a producer CLI to `audit_plugins.py`, using the exact interface
  `--prepare-worklist PATH --source-revision SHA --api-deadline-seconds N` together with exactly one
  existing selector: `--all`, `--changed --base-ref REF`, `--repository URL`, or
  `--repository URL --latest-only`. After the atomic write succeeds, it must print exactly one
  machine-readable stdout line, `worklist_fingerprint=<64-lowercase-hex>`; all diagnostic/progress
  output must go to stderr. The workflow must reject absent, duplicate, or malformed output before
  writing the value to `$GITHUB_OUTPUT`. It must not begin scanning releases.

Resolve all release tags with one argv-based `git ls-remote --tags` subprocess per selected
repository. Do not invoke a shell or interpolate tag text into a command. Parse exact
`refs/tags/<tag>` and `refs/tags/<tag>^{}` records, prefer the peeled commit for annotated tags,
validate hexadecimal object IDs, and cover lightweight tags, annotated tags, slashes/unicode in tag
names, duplicate/malformed output, missing tags, command timeout, and nonzero exit. A repository-wide
Git transport failure makes preparation run-global and produces no worklist. A successfully
enumerated individual release whose tag is missing or unusable remains an item with a
source-resolution error so its assigned worker emits the current release-local `AUDIT_ERROR` and
safe siblings still publish.

### Task 3 — Make shard workers consume only the prepared snapshot

- Add `--worklist PATH` as a mutually exclusive CLI mode alongside `--all`, `--changed`,
  `--repository`, `--aggregate-reports`, and `--merge-verdict-delta`; add
  `--expected-worklist-fingerprint SHA256` as its required companion. Reject `--latest-only` and
  every selection argument in worklist mode. Validate the complete file and expected fingerprint
  before creating report, progress, or verdict-delta outputs.
- Select the worker's items with the unchanged
  `sha256(canonical_owner_repo + "\0" + release_id) % shard_count` formula. Do not use repository
  sharding or alter the release order within a shard.
- When `--worklist` is present, prohibit calls to `read_repo_urls()`, `get_changed_repos()`,
  `build_audit_worklist()`, `get_repo_metadata()`, `get_releases()`, `_gh_get()`,
  `get_repo_file_raw()`, the legacy REST source-tarball helper, or REST-based tag resolution. In the
  real-worker isolation test, use an uncached eligible release, force `--skip-cache`, enable Trivy
  and source-artifact-diff, provide fake scanner executables/download bytes, and install raising
  sentinels on every prohibited path. Assert one codeload download and no sentinel call; a cache hit
  or disabled source scanner does not prove this boundary.
- Pass the normalized repository state and resolved commit/error into `audit_release()` rather than
  resolving them again. A prepared source-resolution error must create an identity-complete,
  checkpointed release-local report and participate in exit 4 precedence.
- Bind progress/resume entries to the worklist fingerprint in addition to the existing repository,
  release, asset, artifact hash, source commit, audit-context, and completion fields. A progress
  file from another snapshot must not skip work. The prepared commit or prepared resolution error
  is the sole source-identity input during resume; add a matching-progress test with all legacy
  resolvers set to raise.
- Emit an atomic `shard-manifest.json` beside each report/delta. It must contain the worklist
  fingerprint and source revision, shard count/index, deterministically assigned identity set, and
  identity-complete attempted/report set. Emit a manifest for an empty assigned shard as well.
- Preserve publishable exits 0/2/3/4, non-publishable run-global exit 1, safe sibling checkpointing,
  isolated cache/progress paths, and existing report/verdict-delta artifact names.

Retain the existing local and smoke CLI behavior by building and validating an in-memory or
temporary snapshot once, then using the same execution path. Local/smoke selection may perform its
one necessary repository/release enumeration, but no audit path may return to REST for ref, tree,
raw metadata, or source-tarball data.

### Task 4 — Materialize and reuse one immutable source snapshot

Refactor the uncached audit path so source acquisition is an explicit per-release resource rather
than hidden inside individual scanners.

- Replace the REST tarball URL with the immutable
  `https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>` URL for the validated commit SHA. Use
  `plugin_release_utils.bounded_stream_download()` with the existing source-size,
  connect/read-timeout, and cleanup policy. Add an explicit bounded redirect policy that permits
  HTTPS only and codeload's expected host(s), and rejects any other redirect before streaming. Use
  a source-download session whose authentication headers are scoped only to validated GitHub
  download hosts; tests must prove credentials are never sent to an unapproved redirect host.
- Safely extract the source archive once. Build a canonical source inventory containing path,
  bytes/Git-blob hash, and safe metadata needed by source/artifact comparison. Never materialize an
  escaping symlink or special node; retain enough non-executed metadata to compare Git symlinks
  without weakening archive safety.
- Read tagged `plugin.json` and `package.json` from that local snapshot. Change `run_trivy()` to
  accept an already materialized source directory, and change `compare_source_and_artifact()` to
  consume the same source root/inventory rather than resolving a Git tree or fetching raw files.
  Preserve its normalized-version build-stamp allowances and current finding/report shape.
- Move digest-backed pre-download cache lookup, and digestless bounded artifact-hash/cache lookup,
  ahead of source materialization. A valid cache hit must perform neither codeload nor source
  extraction. Digestless releases must still stream current asset bytes once before reuse; retain
  GitHub asset digest and downloaded SHA-256 validation exactly.
- If shared source download/extraction fails, continue artifact archive inspection, artifact
  scanners, and artifact-metadata fallback. Record failures for every source-dependent consumer.
  Required Trivy or source-artifact-diff failure yields release-local `AUDIT_ERROR` and exit 4 when
  no stronger structural classification applies; a source consumer made optional by a test policy
  contributes the existing warning behavior instead. Add report-level tests for both required and
  optional policies. Never execute repository hooks, package managers, or plugin code.

Instrument tests so a fresh successful release observes exactly one source download/extraction and
both consumers receive the same object/path. Assert the exact immutable codeload URL and reject any
`api.github.com/.../tarball/...` call. Patch `_gh_get`, REST ref/tree helpers, and raw-file fetches
to raise during the real worker test. Add cache-hit, source failure, annotated/lightweight tag,
metadata, symlink, redirect/credential, and source/artifact behavioral-equivalence cases.

### Task 5 — Prove aggregate coverage against the worklist

- Add `--expected-worklist PATH` and `--aggregate-shard-manifests PATH...` to aggregate mode. Require
  the worklist, fourteen reports, fourteen deltas, and fourteen manifests together; validate all of
  them before writing aggregate evidence or a merged verdict delta.
- Require unique shard indices `0..13`, the expected shard count, one common fingerprint/source
  revision, and exact per-index assignments calculated from the worklist. Reject missing,
  unexpected, overlapping, duplicated, wrong-shard, identity-incomplete, and unattempted work.
- Validate correspondence in every direction: worklist assignment to shard manifest, manifest
  identity set to report identity set, each completed report to its verdict-delta identity, and the
  union of reports to the complete worklist. A manifest cannot claim an identity absent from its
  report, and a report cannot introduce an identity absent from its manifest.
- Require the union of identity-complete reports—including release-local incomplete reports—to
  equal the worklist identity set exactly. Continue validating each report/delta pair and rejecting
  conflicting verdict keys.
- A valid empty worklist still requires fourteen empty, fingerprint-matching shard manifests and
  report/delta pairs. A failed/missing producer or any coverage mismatch is exit 1 and publishes no
  aggregate report, delta, or verdict-store update.
- Preserve deterministic aggregate ordering, current classification precedence, PR enforcement
  after safe publication, and scheduled atomic verdict publication.

Exercise the CLI and the real workflow shell bodies, not only helper functions. Include a negative
where all fourteen artifacts exist but one expected identity is absent; this is the gap the current
artifact-count check does not detect.

### Task 6 — Bound GitHub API waits to the producer deadline

Make a shared monotonic API budget govern every producer REST request, pagination step, retry, and
rate-limit wait in `audit_plugins.py` and `plugin_release_utils.py`.

- Configure the producer with an eight-minute internal API budget inside a ten-minute Actions job.
  Clip connect/read attempts and retry/backoff sleeps to the remaining monotonic budget.
- Handle 403/429 rate limits, `X-RateLimit-Reset`, and `Retry-After` explicitly. Retry only when the
  required wait fits the remaining budget; otherwise raise a clear bounded run-global error without
  sleeping. Treat malformed/missing headers with a documented bounded fallback.
- Ensure the HTTP adapter cannot independently honor a retry delay beyond the same budget. Close
  every response on success, retry, parse failure, and exception, including release pagination.
- Do not add a higher-quota token, GitHub App, longer timeout, serial `max-parallel`, or hidden
  best-effort partial enumeration as the remedy.

Use a fake monotonic clock/sleeper and fake responses to prove: a reset within budget retries; a
reset beyond budget fails without oversleep; exhausted normal retries fail; pagination shares one
budget; malformed headers stay bounded; and response cleanup always occurs.

### Task 7 — Wire one producer into both workflows

Update `.github/workflows/plugin-security-audit.yml` and
`.github/workflows/scheduled-security-audit.yml` in lockstep.

- Add one `prepare-audit-worklist` job per workflow. PR preparation performs the existing mode/base-ref
  selection once, records the selection summary once, and invokes `--prepare-worklist`; scheduled
  preparation uses `--all`. Give preparation a ten-minute job timeout and the eight-minute CLI API
  budget.
- Upload exactly one current-run worklist artifact only after successful validation. The preparation
  shell must capture and validate the producer's exact
  `worklist_fingerprint=<64-lowercase-hex>` stdout line, write that value to `$GITHUB_OUTPUT`, and
  declare it as the job output consumed by workers and aggregation. Do not put the worklist in
  Actions cache and do not fall back to a prior run's artifact.
- Make every matrix worker depend on preparation, download that exact artifact, verify the job's
  fingerprint, and invoke `--worklist` with its existing count/index. Remove per-worker selection
  and all `--all`/`--changed` enumeration arguments. Preserve fourteen shards, fail-fast false,
  per-shard cache isolation, existing audit timeouts, and evidence names. Workers must have
  `needs: prepare-audit-worklist`, no bypassing `if: always()`, and no `GITHUB_TOKEN`, `GH_TOKEN`,
  or equivalent GitHub credential in their job/step environment; only preparation receives the API
  token. Set `persist-credentials: false` on every worker `actions/checkout` invocation. Add workflow
  contract tests that reject either an exposed worker credential or a worker checkout without
  credential persistence disabled.
- Make aggregation depend on preparation and the matrix workers, download the same worklist plus all
  shard manifests/reports/deltas, and pass them to exact-coverage aggregation. It must fail closed
  if preparation failed or the artifact is missing/tampered. PR aggregation must declare
  `needs: [prepare-audit-worklist, audit-shards]`; scheduled aggregation must declare
  `needs: [prepare-audit-worklist, scheduled-audit]`. Retain `if: always()` only with an explicit
  guard that rejects any non-successful preparation result before downloading or publishing.
- Preserve pinned action SHAs, least-privilege permissions, concurrency behavior, PR path
  selection, smoke behavior, scheduled verdict publication/rebase safety, and result precedence.
- Update `scripts/orchestration-hooks/quality-gates` where its actionlint mutation control assumes
  the old `needs: scheduled-audit` shape. The mutated invalid dependency must still fail actionlint;
  do not weaken or delete the negative control.

Extend executable workflow tests to prove the selector runs only in preparation; enumeration is
invoked once; each worker downloads the same artifact, has the exact dependency, lacks an
always-run bypass and GitHub credential; and aggregate receives the original artifact. Structurally
assert the dependency lists and execute the explicit aggregate preparation-result guard. A failed
producer must prevent workers and make aggregation fail closed; missing/mismatched coverage cannot
publish. String presence alone is insufficient where the existing test harness can execute the
shell body.

### Task 8 — Harden and deduplicate scanner bootstrap

Add executable `scripts/install-security-scanners` rather than a local composite action. Follow the
repository's operational-script convention.

- Use `#!/usr/bin/env bash` and `set -Eeuo pipefail`. Implement a named phase runner that logs UTC
  start/end/duration, wraps each network/install phase in `timeout --foreground`, reports the phase
  and exit status on failure, and exits nonzero. Define phase timeout and retry constants in one
  place; the worst-case sum of every allowed attempt, backoff, and local verification must be at
  most ten minutes, leaving two minutes for process termination and cleanup before the unchanged
  12-minute workflow-step cap.
- Retain policy-required ClamAV and Trivy, and retain the current fail-closed bootstrap requirement
  for exact Semgrep `1.132.0` with setuptools `70.3.0`; this bootstrap requirement is intentionally
  stricter than Semgrep's optional runtime policy status. Keep the current Trivy repository/key
  source and pin its expected OpenPGP fingerprint as
  `825AD9036F7C850E6A6FED4935B8ACA44FD9CA9F`. Download the key to a temporary file with bounded
  retry, inspect it with `gpg --show-keys --with-colons`, require that fingerprint before dearmoring
  it, and do not use a download-to-`gpg` pipeline. Configure bounded APT acquisition
  timeouts/retries and visible output rather than an unexplained quiet stall. Retry only idempotent
  APT/index/key-fetch work; never retry local version/database verification.
- Treat package installation, Trivy availability/version output, exact Semgrep verification,
  `freshclam`, `clamscan --version`, and ClamAV database presence as hard requirements. Keep stopping
  the pre-existing `clamav-freshclam` service as the sole soft failure and emit a warning when it
  cannot be stopped. Use noninteractive `sudo -n`, fail clearly if `GITHUB_PATH` is absent, and
  clean temporary files with a trap.
- Replace all three inline `Install required security scanners` bodies—scheduled worker, PR matrix
  worker, and PR smoke job—with `scripts/install-security-scanners`; keep their step names and
  `timeout-minutes: 12`.
- Add `scripts/install-security-scanners` to the scheduled audit cache-key input hash and update
  `tests/test_workflow_security.py` accordingly, so a bootstrap change cannot reuse a cache created
  under different scanner-install behavior.
- Add the script to the PR workflow `paths:` filter and to `_FULL_AUDIT_PATHS` in
  `plugin_release_utils.py`, so changing bootstrap selects the full corpus. Extend both
  `tests/test_workflow_selection.py` and `tests/test_plugin_release_utils.py` with
  `scripts/install-security-scanners` selecting `all`, and make the workflow-security test assert
  the exact `paths:` entry. Name and add these exact node IDs to the workflow's collection gate:
  `tests/test_scanner_bootstrap.py::test_scanner_bootstrap_happy_path`,
  `tests/test_scanner_bootstrap.py::test_scanner_bootstrap_timeout_fails_named_phase`, and
  `tests/test_scanner_bootstrap.py::test_scanner_bootstrap_key_failure_is_not_masked`.

Fake-command tests must cover the happy path; each phase failing before later phases; timeout status
124; failed key download not being masked by downstream commands; wrong Semgrep version; missing
ClamAV database; one bounded retry that recovers; and retry exhaustion that exits with the named
phase. Workflow-contract tests must prove that each of the three named scanner-install steps has
exactly `run: scripts/install-security-scanners`, retains `timeout-minutes: 12`, contains no inline
package/scanner commands, and that this invocation occurs exactly three times across the two
workflows. The script test must also assert that the tracked file is executable. Do not run the real
installer as a local verification step.

### Task 9 — Update current documentation without rewriting historical evidence

Update `README.md`, `docs/audit-gating-overview.md`, and
`tests/test_audit_documentation.py` to describe the producer/worklist/worker/aggregate lifecycle,
API-free shard behavior, one-source reuse, exact coverage validation, bounded rate-limit failure,
and shared scanner bootstrap.

- Replace the statement that fourteen shards repeat the 83-request enumeration baseline with the
  new one-enumeration contract, while retaining the preserved snapshot's release distribution and
  wall-time measurements as historical capacity inputs.
- State clearly that a worklist alone is insufficient unless ref/tree/raw/source REST calls are also
  absent from workers.
- Do not edit `docs/agent_conversations/2026-08-08_audit-fourteen-shard-capacity-projection.json` or
  retroactively claim it measured the new design.
- Document that local tests prove request topology, integrity, and bounded failure; hosted runner
  quota behavior and resilience to an external scanner mirror outage remain deferred until an
  authorized post-merge workflow run.
- Keep user-facing security limitations, enforcement mode, catalog behavior, archive/download
  limits, and verdict semantics unchanged.

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

Follow
`/home/beallio/Dropbox/Scripts/agent-orchestration/skills/orchestration-plan-author/references/verification-standards.md`.
Every check below must report its real exit status/tallies, and a missing fixture or command is a
failure rather than an implicit pass.

### 1. Record the red phase

After adding the tests from Task 1 and before implementing their behavior, run:

```bash
set -o pipefail
set +e
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_audit_worklist.py \
  tests/test_audit_plugins.py \
  tests/test_bounded_download_callers.py \
  tests/test_plugin_release_utils.py \
  tests/test_enforcement_workflow.py \
  tests/test_workflow_selection.py \
  tests/test_workflow_security.py \
  tests/test_scanner_bootstrap.py \
  2>&1 | tee /tmp/decky-plugins-extended/quota-safe-security-audit-red.log
red_status=${PIPESTATUS[0]}
set -e
if [[ "$red_status" -ne 1 ]]; then
  echo "expected pytest assertion failures (exit 1), got exit $red_status" >&2
  exit 1
fi
```

Record the specific expected failures from the saved log. Exit 0, no collected new nodes,
command-not-found, collection/setup failure, or unrelated fixture failure does not establish the
red phase.

### 2. Run focused positive coverage

After implementation, rerun the command above and require exit 0. Also run:

```bash
bash -n scripts/install-security-scanners
GITHUB_TOKEN=test-token PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider \
  tests/test_audit_cache_invalidation.py \
  tests/test_audit_documentation.py \
  tests/test_audit_transparency.py
```

Record pass/fail tallies. The fake scanner-bootstrap harness must be the only local execution of the
installer; do not invoke real APT, ClamAV refresh, Trivy installation, or Semgrep installation.

### 3. Exercise failure controls, then the valid controls

Run the executable tests/CLI fixtures that prove all of these fail closed with their specific
diagnostic and no unsafe aggregate output:

- a worklist payload whose release ID changes without updating the producer fingerprint;
- a recomputed but unexpected fingerprint that differs from the preparation job output;
- fourteen structurally valid shard artifacts whose union omits one expected work identity;
- a shard manifest with the wrong index and one with an identity assigned to another shard;
- a worker with sentinels that raise on every GitHub REST/enumeration entry point;
- a 403/429 reset beyond the monotonic API deadline;
- scanner-bootstrap phase timeout 124, key-download failure, wrong Semgrep version, and absent
  ClamAV database.

After those failure cases, run the valid empty-worklist aggregation and a multi-repository 14-shard
fixture. Require fourteen unique indices, a common fingerprint, pairwise-disjoint assignments,
union equality with the worklist, normal 0/2/3/4 exit semantics, and zero GitHub REST calls from
workers.

### 4. Mutation-test the implementation

From a clean committed implementation, make one temporary mutation to the implementation—not the
tests—that bypasses the worklist fingerprint comparison. Run the tampered-worklist test and require
it to fail because the mutation was detected by the test. Save the mutation diff under
`/tmp/decky-plugins-extended/quota-safe-security-audit-mutation.patch`, reverse that exact patch with
`git apply -R`, rerun the test to exit 0, and verify `git diff --exit-code`. Do not use a destructive
checkout/reset to restore it.

The existing quality gate's invalid YAML, expression, and job-dependency mutations must also still
be rejected after the workflow dependency changes.

### 5. Run the complete repository gate

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

Require Ruff check, Ruff format, all pytest tests/subtests, verified actionlint, and all actionlint
negative controls to pass. Record actual test/subtest tallies. Confirm the worktree is clean and
`security-verdicts.json` has not changed before marking the round complete.

### Deferred verification

Do not claim that local tests empirically prove hosted GitHub quota or package-mirror availability.
Because this plan does not push or start external workflows, defer these checks until the user
authorizes a post-merge/default-branch run:

1. record a full-corpus workflow run ID and show one successful preparation artifact, fourteen
   workers consuming its fingerprint, exact aggregate coverage, and no worker GitHub REST calls or
   rate-limit sleep;
2. record both a cold and a warm scheduled run completing inside existing timeouts;
3. verify scanner phase timestamps identify any external stall and that a transient bounded retry
   either recovers or fails with the named phase before the 12-minute outer timeout.

External scanner/package availability can never be guaranteed; the implemented contract is bounded,
observable, retried where safe, and fail-closed.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished quota-safe-security-audit
```

This writes:

```text
/tmp/decky-plugins-extended/quota-safe-security-audit_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer quota-safe-security-audit`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/quota-safe-security-audit-review-*.md
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
   scripts/orchestration/clear-finished quota-safe-security-audit
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
   git add docs/review/quota-safe-security-audit-review-*.md
   git commit -m "docs(review): record quota-safe-security-audit review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished quota-safe-security-audit
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer quota-safe-security-audit` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed quota-safe-security-audit
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize quota-safe-security-audit
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/quota-safe-security-audit_finalized
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
scripts/orchestration/finalize quota-safe-security-audit
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/quota-safe-security-audit_finished
/tmp/decky-plugins-extended/quota-safe-security-audit_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
