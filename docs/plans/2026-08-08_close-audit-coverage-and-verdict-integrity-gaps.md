# Plan: Close Audit Coverage and Verdict Integrity Gaps (close-audit-coverage-and-verdict-integrity-gaps)

## Context

The read-only audit review found that the security decision made by the audit pipeline is not
always the decision applied to the artifact users can install.

The current path in `audit_plugins.py` selects one newest eligible release per repository, while
`generate_json.py` publishes every eligible stable and prerelease release. Older catalog entries
can therefore have no durable verdict. The catalog gate also looks up verdicts by
`tag@asset_id` without comparing the stored `artifact_sha256` to the current catalog hash; a
stale `PASS` can be reused for a changed artifact, and stale blocked identities are reconciled
against the wrong hash.

The review also reproduced three outcome-integrity problems:

- a traversal finding is classified as `AUDIT_ERROR` when required scanners are unavailable,
  even though the structural finding is deterministic and blockable;
- Trivy and Semgrep return parsed results without honoring a nonzero scanner exit status;
- a real-looking secret on a line containing `# test` is downgraded to a warning by the broad
  fixture heuristic.

The workflow and cache do not fully protect those decisions. PR audit mode can run zero real
repository audits when only audit implementation or policy changes, `semgrep-rules.yml` is
missing from the PR path filter, and cached reports do not include all rule/scanner inputs. The
allowlist, metadata version comparison, verdict-store loading, URL parsing, release pagination,
and download limits have related integrity or availability gaps.

Implement the fixes in `audit_plugins.py`, `generate_json.py`, `check_for_updates.py`,
`plugin_release_utils.py`, `security-policy.yml`, `security-allowlist.yml`,
`.github/workflows/plugin-security-audit.yml`, `.github/workflows/scheduled-security-audit.yml`,
the project quality-gate hook, `README.md`, and the focused test modules under `tests/`.

The checked-in `security-policy.yml` is authoritative and currently sets
`enforcement.mode: enforce`; this plan must not change that mode. Catalog generation excludes only
a `CURRENT` effective `BLOCK`. Unknown releases, stale-hash verdicts, and release-local
`AUDIT_ERROR` attempts remain fail-open for catalog eligibility, while malformed policy/verdict
state and other run-global catalog-generation integrity failures remain fail-closed. Remove
documentation and workflow comments that incorrectly describe report-only as the current default;
report-only remains a supported configuration, not the active one.

This plan covers the verified high and medium findings from the audit review. It does not add
runtime plugin execution, change `plugins.json` or `testing_plugins.json`, deploy catalogs, or push
branches/remotes. Machine- and human-readable audit outputs may gain explicit identity-status
fields without changing the public plugin catalog schema.

**Slug used throughout this plan:** `close-audit-coverage-and-verdict-integrity-gaps`

---

## Orchestration Contract

**Slug:** `close-audit-coverage-and-verdict-integrity-gaps`

**Plan file:**

```text
docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md
```

**Implementation branch:**

```text
feat/close-audit-coverage-and-verdict-integrity-gaps
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finalized
```

**Review notes:**

```text
docs/review/close-audit-coverage-and-verdict-integrity-gaps-review-*.md
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
git checkout -b feat/close-audit-coverage-and-verdict-integrity-gaps
```

Commit this plan first:

```bash
git add docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md
git commit -m "docs(plan): add close-audit-coverage-and-verdict-integrity-gaps implementation plan"
```

---

## Implementation Tasks

### Task 1 — Audit every catalog-eligible release

Replace the repository-level newest-release-only path with an explicit, resumable multi-release
audit path.

- Centralize release eligibility in `plugin_release_utils.py` and use it from auditing, catalog
  generation, and update detection. A release is catalog-eligible only when `draft` is false and
  it has exactly one case-insensitive `.zip` asset. Stable consumers exclude prereleases;
  testing-catalog and audit consumers include them. Releases with zero or multiple ZIP assets are
  ineligible everywhere.
- Update `get_releases()` to consume every GitHub pagination link. A failed later page or a
  repeated/cyclic `next` link is a repository error; never silently treat a partial page set as a
  complete repository.
- Define ordering instead of inheriting API page order: canonical `owner/repo` ascending, then
  eligible releases by `published_at` (falling back to `created_at`) descending, numeric GitHub
  release ID descending, and ZIP asset ID descending. Missing timestamps sort last.
- Make `--all`, `--changed`, and an unqualified `--repository` audit every eligible release in each
  selected repository. Add `--latest-only`, valid only with `--repository`, as the explicit
  one-release smoke/debug mode; the real-plugin smoke workflow must use it.
- Add deterministic `--shard-count N` and `--shard-index I` selection over the SHA-256 of canonical
  `owner/repo + "\0" + release_id`. Validate `N > 0` and `0 <= I < N`. Configure full-corpus PR
  and scheduled audits as fourteen isolated shards whose union is identical to an unsharded worklist
  and contains no duplicate release IDs.
- Atomically checkpoint a progress manifest and report after every release. Resume may skip only
  an exact completed identity comprising canonical repository, release ID, asset ID, current
  artifact hash, resolved source commit, and audit-context hash; interrupted or mismatched work
  reruns. Each shard emits an isolated verdict delta and report. Add an aggregation mode that
  rejects duplicate/conflicting keys and produces the same deterministic verdict/report content as
  an unsharded run.
- Preserve one durable verdict per release key. A release-local `AUDIT_ERROR` must not stop later
  releases, overwrite that release's prior completed verdict, or suppress successful sibling
  updates. Define exit 4 as publishable release-local incompleteness and reserve exit 1 for a
  run-global policy/store/output integrity failure whose outputs are unsafe to publish. Preserve
  exit 2 for `BLOCK`, exit 3 for `MANUAL_REVIEW`, and exit 0 for remaining completed results; for
  mixed outcomes use precedence 1, 4, 2, 3, 0. Workflows must publish/merge safe shard deltas for
  exits 2, 3, and 4 before applying their existing PR/scheduled enforcement result, while exit 1
  publishes nothing.
- Keep JSON/Markdown reports unambiguous about repository, tag, release ID, asset ID,
  classification, identity status, audited artifact hash, completion status, and error scope.
- Replace newest-release-only tests with coverage for stable, prerelease, draft, zero-ZIP,
  multi-ZIP, pagination, deterministic order, sharding, resume, aggregation conflicts,
  single-release smoke, and mixed successful/error releases.

### Task 2 — Bind catalog gating to the current artifact hash

Make the catalog gate require a verdict for bytes proven current, not merely the same tag, asset
ID, version, or URL.

- Introduce one authoritative artifact-identity path shared by the auditor, generator, and update
  checker. Accept a GitHub digest only when it is exactly `sha256:` plus 64 hexadecimal characters
  and normalize it to lowercase. When no valid digest exists, stream the current asset once
  through the bounded downloader and compute SHA-256. Never reuse an existing catalog hash merely
  because normalized version and artifact URL are unchanged.
- Pass the current SHA-256 explicitly into `classification_for()`, configured-repository gating,
  upstream reconciliation, and `check_for_updates.py`. Update detection must compare normalized
  version plus current hash, so a same-version asset replacement requests regeneration.
- Give verdict lookup a structured identity status: `CURRENT` for an exact release-key/hash match,
  `STALE_HASH` for a matching release key with an absent or different stored hash, and `UNKNOWN`
  when no verdict exists. Only `CURRENT` may yield an effective `PASS` or `BLOCK`; only a `CURRENT`
  effective `BLOCK` may exclude under enforce mode.
- `STALE_HASH` and `UNKNOWN` remain fail-open but must emit explicit logs and public
  `audit.json`/`audit.html` records containing repository, tag, release ID, current hash, stored
  hash when present, identity status, and fail-open outcome. Do not add these fields to
  `plugins.json` or `testing_plugins.json`.
- Remove or route around duplicate identity logic so configured, upstream, generation, and update
  paths cannot apply different hash rules.
- Add tests for matching `PASS`, matching `BLOCK`, stale `PASS`, stale `BLOCK`, current hashes
  already present upstream, and changed bytes behind the same tag and URL without a GitHub digest.
  Assert the new bytes are hashed, update detection notices the replacement, and only a matching
  current block removes the current `(name, hash)` identity.

### Task 3 — Preserve deterministic structural blocks and scanner failures

Correct classification precedence in `classify_findings()` and the audit-release path.

- An unallowlisted finding in the policy's `blockable_rules` set must remain `BLOCK` even when a
  required behavioral scanner is unavailable or failed. This covers archive traversal, escaping
  symlinks, archive limits, setuid/device/named-pipe members, and malware signatures.
- A corrupt or unreadable archive with no deterministic structural finding remains `AUDIT_ERROR`,
  matching the policy comment that corruption means the audit could not complete. Do not turn all
  scanner failures into `BLOCK`.
- Keep scanner statuses and findings visible in reports. Required scanner failures still produce
  `AUDIT_ERROR` when no structural block justifies a `BLOCK` result.
- Make Trivy and Semgrep honor `_run_scanner()`'s boolean result. A nonzero exit must produce a
  failed scanner status even if parseable JSON was emitted; preserve any parsed findings in the
  report. Add tests for valid JSON plus nonzero exit, empty output plus nonzero exit, and the
  clean zero exit path.
- Add regression tests using the default policy: archive traversal plus unavailable required
  scanners must be `BLOCK`; corrupt ZIP plus unavailable scanners must be `AUDIT_ERROR`.
- Keep corruption independent from scanner availability. With ClamAV, Trivy, Semgrep, and source
  comparison disabled or healthy, a corrupt/unreadable ZIP must be `AUDIT_ERROR`, produce no
  fabricated structural block, and preserve a prior completed verdict. Retain a separate
  traversal-plus-unavailable-scanners regression proving that deterministic traversal remains
  `BLOCK`.

### Task 4 — Make cache identity include every security input

Prevent a cached report from being reused after its scanner inputs change.

- Extend `compute_audit_context_hash()` to include the vendored `semgrep-rules.yml`, the scanner
  executable/version identity, and the malware/vulnerability database freshness identity used by
  ClamAV and Trivy. If a database identity cannot be obtained reliably, make scheduled audits
  bypass report-cache hits for those scanners rather than claiming freshness.
- Keep scheduled-workflow cache keys aligned with the runtime context and document the chosen
  freshness behavior in the workflow comments. Do not make a six-hour scheduled scan appear
  fresh solely because the artifact and source commit are unchanged.
- Validate `release_id` again when loading an index-selected cached report, just as the fallback
  file scan already does. A corrupted index must not redirect a request to another release's
  report.
- Add tests proving that changing Semgrep rules, scanner identity/freshness, or release ID causes
  a cache miss, while identical inputs still hit. Include a cache-index mismatch fixture.
- Do not claim a zero-download warm run for digestless assets: the current artifact bytes still
  require bounded hash validation. An unchanged digest or a newly verified identical byte hash may
  reuse extraction, source, and scanner results only when every other cache identity also matches.

### Task 5 — Ensure CI runs the relevant corpus

Make PR CI execute the same security gates and scanner contract as the authoritative local gate.

- Add `generate_json.py`, `check_for_updates.py`, `plugin_release_utils.py`,
  `security-verdicts.json`, `semgrep-rules.yml`, the audit-mode selector, and the project
  quality-gate hook to the workflow path filter alongside existing audit, policy, allowlist,
  lockfile, test, and workflow paths.
- Add side-effect-free `select_audit_mode(changed_paths)` behavior to `plugin_release_utils.py` and
  expose it through `python -m plugin_release_utils --select-audit-mode`; test the executable path,
  not only the function. A diff containing only `additional_plugins.txt` selects changed
  repositories. Any audit, generator, update-check, release-utility, policy, allowlist,
  verdict-store, Semgrep-rule, dependency, selector, quality-gate, or audit-workflow change selects
  the fourteen-shard full corpus. A mixed plugin-list plus security-pipeline diff also selects the full
  corpus.
- Replace `unittest discover` in the workflow and README with the same Ruff, format, and
  `uv run pytest -q` gates used locally. Zero collection is a failure, and collection assertions
  must prove pytest-style catalog, enforcement-workflow, cache, and workflow-selection modules ran.
- Install the existing pinned Semgrep `1.132.0` in PR, smoke, and scheduled jobs; assert the exact
  `semgrep --version` before scanning and feed that identity into the cache context.
- Add `actionlint` `v1.7.12` to the project quality-gate hook and CI. Fetch/cache the official
  platform archive under the orchestration `/tmp` root with `gh release download`, verify it against
  the release checksum, and fail closed on download, checksum, extraction, or execution failure. An
  invalid workflow syntax/expression/dependency or mutated invalid workflow must fail the gate.
- Keep the smoke audit as a fast `--repository ... --latest-only` end-to-end check and do not treat
  it as the corpus audit. The summary must distinguish no configured repository changes, changed
  repositories, full corpus selected, and shard/aggregation status.
- Test path-trigger and selection behavior by executing the helper against representative diffs;
  string-presence assertions are insufficient.

### Task 6 — Tighten secret and metadata precision

Remove downgrade paths that can hide a real finding while preserving legitimate fixture
coverage.

- Change `_looks_like_test_fixture()`/`scan_for_secrets()` so a warning downgrade requires both an
  explicitly recognized fixture path and an anchored placeholder value for that detector.
  Recognized path evidence is an exact segment in `test`, `tests`, `fixture`, `fixtures`,
  `example`, `examples`, `mock`, or `mocks`, or a filename containing `.example.`. Arbitrary line
  text, comments, whitespace, and substring matches do not qualify.
- Placeholder recognition must match the entire extracted value and be limited to enumerated
  forms such as `changeme`, `placeholder`, `your_<name>`, bracket/template tokens, or a
  provider-shaped prefix followed only by repeated placeholder characters. A high-entropy token
  followed by `# test` remains critical. Use a recognized placeholder under an explicit fixture
  path as the positive control; keep all evidence redacted.
- Pass the normalized release version into `_metadata_diff_is_build_stamped()`. Accept only a
  `package.json.version` or `plugin.json.version` change exactly to that version; removal of exactly
  one `debug` flag without any other flag change or reorder; and `publish.image` changing only
  `/main/` to `/v{normalized_version}/`. All other version, flag, image, key, or value changes are
  source/artifact drift.
- Add one positive test for each allowed build-stamp transformation plus arbitrary `999.0.0`,
  combined unrelated drift, reordered flags, and near-match image-path negatives.

### Task 7 — Bind all blockable allowlists to exact artifacts

For every rule currently present in `security-policy.yml`'s `blockable_rules`, require
`artifact_sha256` to match canonical lowercase `^[0-9a-f]{64}$` and equal the current artifact
hash. Missing values, `any`, malformed or uppercase hashes, and mismatches are rejected.
Non-blockable rules may retain `any` only with exact repository, release, rule, approval, reason,
and unexpired date scope. Update allowlist comments accordingly. Parameterize over the policy's
live blockable-rule set rather than a hand-maintained structural subset, and mutation-test that a
newly blockable rule immediately gains the exact-hash requirement.

### Task 8 — Fail clearly on integrity and resource hazards

Close the remaining low-level gaps that can make the audit silently inspect the wrong source or
consume unbounded runner resources.

- Centralize GitHub repository parsing/canonicalization in `plugin_release_utils.py` and use it
  from audit, generation, update detection, verdict lookup, and allowlist normalization. Accept
  only `https://github.com/<owner>/<repo>` with one optional trailing slash, a case-insensitive
  host, exactly two non-empty decoded path segments, and no credentials, port, query, fragment,
  `.git` suffix, encoded separator, or extra path. Both accepted trailing-slash forms canonicalize
  to the same key; retain the two currently configured trailing-slash URLs through normalization.
- Add a policy-driven bounded streaming helper in `plugin_release_utils.py` and use it for release
  auditing, source archives, generator hashing, upstream reconciliation, and update detection.
  Add validated policy defaults of 67,108,864 bytes (64 MiB) for release ZIPs and 268,435,456 bytes
  (256 MiB) for source archives, a 10-second connect timeout, a 60-second read timeout, and a
  1,048,576-byte (1 MiB) chunk size. Source extraction must consume the loaded policy rather than
  `_default_policy()`.
- Reject declared `Content-Length` above the applicable limit before reading. When the header is
  absent, malformed, negative, or understated, enforce the streamed count and fail on byte
  `limit + 1`; exactly `limit` succeeds. Hash during the single stream, delete partial files on
  every failure, skip extraction/scanners/cache writes, and preserve prior verdicts. Release-audit
  download failures are release-local `AUDIT_ERROR`; generator/update downloads are run-global.
- Remove implicit legacy verdict fallback. A missing tracked `security-verdicts.json` is a valid
  empty snapshot whose releases are `UNKNOWN`; a present unreadable or invalid file is an integrity
  error. Validate the root, every canonical repository mapping, every release-record mapping,
  release keys, classification enum, rule-ID lists, and SHA fields before use. An absent stored SHA
  in an otherwise valid legacy record is `STALE_HASH`, not `CURRENT` and not schema corruption.
- Add focused tests for valid trailing slashes and hostile URL variants; malformed JSON and every
  nested schema failure; missing-store unknown behavior; all three download call paths; header and
  streamed overflow; exact-limit success; partial cleanup; non-default policy values; and no cache
  or verdict mutation after failure.

### Task 9 — Update documentation and test fixtures

Update `README.md` and any audit-gating documentation affected by the final behavior:

- state that current policy mode is `enforce`, a current effective `BLOCK` is excluded, and
  report-only remains a supported but inactive configuration;
- document all-release sharding/checkpointing, deterministic order, and the single-release smoke
  mode;
- explain current-byte hashing and `CURRENT`, `STALE_HASH`, and `UNKNOWN` outcomes without changing
  the plugin catalog schema;
- distinguish deterministic structural `BLOCK`, release-local `AUDIT_ERROR`, and run-global
  integrity failure, including safe partial publication and final exit handling;
- document scanner freshness/cache behavior, CI path selection, pytest/Semgrep/actionlint parity,
  exact-hash allowlists, URL normalization, nested verdict validation, and the concrete download
  limits;
- replace the stale README `unittest discover` command with `uv run pytest -q`.

Update focused fixtures and assertions without deleting existing review-note artifacts or
broadening this plan into runtime plugin execution.

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
Failure cases run before negative controls. Every behavioral gate must name the exact pytest node
IDs executed, record actual output and pass/fail totals, and include a pre-fix failure or mutation
check. Workflow tests must execute shared Python/shell behavior; string-presence assertions are not
sufficient. Missing required tools fail rather than skip. Use `set -o pipefail` for pipelines and
never infer a producer's result from the pipeline's final command.

1. **Red regression tests first.** Before implementing each behavior, add focused tests and run
   them against `dev`, recording the expected failure: only one release is audited; draft parity
   differs; later-page failure returns partial success; shards overlap or omit work; resume accepts
   a mismatched identity; one error suppresses sibling verdicts; a same-URL old hash is reused;
   traversal loses to scanner failure; valid nonzero Trivy/Semgrep output passes; inline `# test`
   downgrades a token; arbitrary metadata drift passes; a new blockable rule accepts `any`; nested
   corrupt verdict state or a legacy fallback is accepted; and a streamed download is unbounded.
   Each failure must name the violated behavior rather than merely return nonzero.

2. **Release coverage, sharding, resume, and error isolation.** Use paginated fixtures containing
   stable, prerelease, draft, zero-ZIP, and multi-ZIP releases. Assert auditor/generator eligibility
   parity, exact deterministic order, one verdict key per eligible release, and that `--changed`
   versus `--all` differs only in repository selection. Prove fourteen shards are pairwise disjoint and
   union-identical to the unsharded worklist, aggregation rejects conflicts, and reordered API
   pages produce byte-equivalent output. Prove resume skips only an exact completed identity and
   `--latest-only` emits exactly one release.

   Simulate later-page failure and a repeated pagination link; neither may report the repository
   complete, delete prior verdicts, or publish partial page results as a complete corpus. In a
   mixed run, release A completes as `PASS` while release B produces `AUDIT_ERROR` with an existing
   durable verdict. Assert A's new verdict/report is checkpointed and publishable, B's prior verdict
   is byte-for-byte unchanged, B's error report is retained, remaining releases run, and workflow
   publication occurs before the final release-error result. A run-global integrity failure must
   instead leave all publishable outputs untouched.

3. **Authoritative artifact identity.** Seed an existing catalog and stored `PASS` with hash A.
   Return the same tag and asset URL without a GitHub digest but make the streamed bytes hash to B.
   Assert generation and update detection compute B rather than reusing A, classify the stored
   verdict as `STALE_HASH`, and never treat it as current. Repeat with a stored `BLOCK`; the stale
   block must not remove B. Assert a valid digest and a streamed hash agree, while malformed digest
   forms force bounded byte hashing. Verify `CURRENT`, `STALE_HASH`, and `UNKNOWN` plus their hashes
   and fail-open outcome appear in console output, `audit.json`, and `audit.html` without changing
   the plugin catalog schema.

4. **Classification, corruption, and scanner status.** Assert default-policy traversal remains
   `BLOCK` with required scanners unavailable. With ClamAV, Trivy, Semgrep, and source comparison
   disabled or healthy, a corrupt ZIP alone must be `AUDIT_ERROR`, produce no structural `BLOCK`,
   and preserve the prior verdict. Trivy/Semgrep valid JSON plus nonzero exit and empty output plus
   nonzero exit must be failed statuses; valid zero-exit output is the negative control.

5. **Cache, CI, scanner, and workflow parity.** Assert independent cache misses for Semgrep rules,
   Semgrep executable/version, Trivy executable/database, ClamAV database, policy, allowlist,
   release ID, artifact hash, and source commit. Reject a cache index pointing to a different
   release. An identical fully verified context must hit.

   Execute audit-mode selection for audit-only, generator-only, update-checker-only,
   release-utility-only, policy-only, allowlist-only, verdict-store-only, Semgrep-rule-only,
   lockfile-only, workflow-only, selector-only, quality-gate-only, plugin-list-only, and mixed
   plugin-list/security diffs. Every security-pipeline or mixed diff selects the fourteen-shard full
   corpus; only plugin-list-only selects changed repositories. Run the exact CI test command and
   assert `pytest --collect-only -q` includes catalog-gate, enforcement-workflow,
   workflow-selection, cache, and new regression node IDs. Both audit workflows must install the
   same pinned Semgrep and record the expected version. Run pinned `actionlint` over every workflow
   and mutation-test invalid YAML/expression/step dependency handling.

6. **Precision, metadata, allowlist, and URL controls.** Assert a credential-shaped token with
   `# test`, arbitrary whitespace, or a test word in a non-fixture path remains critical. A fully
   recognized placeholder in an explicit fixture path is downgraded and all evidence is redacted.
   Test every enumerated accepted build-stamp transformation and reject arbitrary version drift,
   combined drift, reordered flags, and near-match image paths. Parameterize exact-hash behavior
   over every live blockable rule, then add one rule temporarily and prove the constraint follows
   policy automatically. Assert both configured trailing-slash URLs canonicalize and hostile host,
   port, credential, query, fragment, suffix, encoded-separator, and extra-segment variants fail
   before any request.

7. **Complete verdict-store integrity.** Test malformed JSON and non-object roots plus repository
   values that are not objects, release records that are not objects, invalid release keys,
   unsupported/non-string classifications, non-list rule fields, non-string rule IDs, and
   present-but-invalid SHA-256 values. Each must abort catalog generation before new public output
   is written and must never consult legacy cache state. A valid legacy record with no artifact SHA
   is `STALE_HASH`. A genuinely missing tracked store returns an empty snapshot and exposes valid
   releases as explicit `UNKNOWN` without implicit `.audit-cache` fallback.

8. **Bounded downloads.** Exercise release audit, source archive, generator hashing, upstream
   reconciliation, and update detection at `limit - 1`, exactly `limit`, and `limit + 1`; exact
   limit succeeds. Test oversized, absent, understated, malformed, and negative `Content-Length`,
   plus a chunk crossing the limit. Failures delete partial files, skip extraction/scanners, create
   no cache entry, and leave verdicts unchanged. Override both policy limits with non-default
   values and prove all call paths consume the effective policy rather than built-in defaults.

9. **Capacity and live-corpus compatibility.** In a temporary worktree with reports, cache, and
   verdict output isolated under `/tmp`, instrument GitHub API calls, artifact/source downloads,
   and scanner subprocesses. Enumerate the complete configured corpus and deterministically assign
   it to fourteen shards. Production cold capacity succeeds when the maximum fourteen-shard wall-time estimate,
   derived from the actual largest-shard release count, observed per-release
   mean and p95 timings, and observed enumeration overhead, fits the unchanged audit-step timeout
   with explicit headroom. Do not require the sequential unsharded cold scan to complete as a
   production success condition; it may be stopped after a representative timing sample. Preserve
   semantic equality between unsharded and aggregated sharded results through deterministic tests
   and the existing mutation evidence. Unchanged digest-backed releases perform zero artifact
   downloads; digestless releases may perform one bounded artifact stream solely to validate the
   current hash. Unchanged releases perform zero source downloads, extractions, or scanner
   subprocesses after identity validation.

   Record repository count, eligible-release count, pages fetched, wall time, API requests,
   release/source bytes, downloads, scanner invocations, report count, verdict count, and shard
   balance. Record the repeated enumeration request count for all fourteen production shards and
   explicitly defer hosted-runner concurrency/API behavior when no hosted run is authorized.
   Assert every existing eligible release ZIP fits 64 MiB and every source archive fits 256 MiB.
   Any legitimate current item exceeding a limit or the projected maximum-shard runtime budget
   blocks finalization and requires an explicit reviewed plan change; do not silently raise limits.

10. **Mutation checks.** One at a time: restore newest-release-only selection; remove draft
    filtering; force overlapping shards; loosen resume identity; suppress sibling publication on
    release error; restore URL-only hash reuse; remove current-hash comparison; move scanner-error
    precedence ahead of structural blocks; restore implicit legacy fallback; bypass streamed size
    enforcement; and remove the workflow full-audit branch. The matching regression must go red;
    restore the implementation after every mutation.

11. **Negative controls last.** Run clean matching-hash releases, clean archives, valid scanner
    zero-exit output, legitimate Decky build-stamped metadata, explicit fixture placeholders,
    exact-hash allowlist entries, accepted canonical/trailing-slash URLs, valid verdict stores, and
    bounded downloads at the exact limits. Record their actual classifications/statuses so the
    hardening does not reject normal plugins.

12. Run `scripts/orchestration/run-quality-gates`,
    `scripts/orchestration/check-review-notes-not-deleted`, and `git status --short`. Record Ruff,
    format, full pytest, pytest collection, pinned Semgrep, pinned `actionlint`, review-note, and
    corpus-budget tallies. The implementer must commit the plan first, keep the worktree clean, and
    leave review notes to the orchestrator.

### Explicitly deferred or not verified

- No remote push, pull request, Cloudflare deployment, or hosted GitHub Actions run is created.
  Hosted-runner variance and package-mirror latency remain unmeasured; workflow syntax, shared
  shell/Python behavior, pytest collection, scanner parity, and cold/warm corpus budgets are
  verified locally.
- Hosted ClamAV/Trivy database publication timing is not measured. Fingerprint extraction, cache
  invalidation, and fail-safe scheduled cache bypass are verified with controlled local identities.
- No runtime or on-device plugin execution is added; static-analysis blind spots remain documented.
- The public plugin catalog schema remains unchanged. Audit JSON/HTML identity-status additions are
  verified separately.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished close-audit-coverage-and-verdict-integrity-gaps
```

This writes:

```text
/tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer close-audit-coverage-and-verdict-integrity-gaps`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/close-audit-coverage-and-verdict-integrity-gaps-review-*.md
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
   scripts/orchestration/clear-finished close-audit-coverage-and-verdict-integrity-gaps
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
   git add docs/review/close-audit-coverage-and-verdict-integrity-gaps-review-*.md
   git commit -m "docs(review): record close-audit-coverage-and-verdict-integrity-gaps review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished close-audit-coverage-and-verdict-integrity-gaps
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer close-audit-coverage-and-verdict-integrity-gaps` after the next review note is created.

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
   scripts/orchestration/check-review-notes-committed close-audit-coverage-and-verdict-integrity-gaps
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize close-audit-coverage-and-verdict-integrity-gaps
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finalized
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
scripts/orchestration/finalize close-audit-coverage-and-verdict-integrity-gaps
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finished
/tmp/decky-plugins-extended/close-audit-coverage-and-verdict-integrity-gaps_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
