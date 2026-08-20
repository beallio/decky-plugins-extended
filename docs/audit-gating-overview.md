# Audit gating — design overview

> **This is not an executable plan.** It is the shared rationale behind seven sub-plans in
> `docs/plans/`. Each sub-plan carries its own orchestration contract, branch, and markers.
> Nothing here is run directly.

## Current implementation state (2026-08-18)

The historical design and appendix below describe the incremental rollout at
the time those sub-plans landed. The current authoritative behavior is:

- `security-policy.yml` uses `enforcement.mode: enforce`; report-only is
  supported but inactive.
- The auditor processes every stable and prerelease catalog-eligible release in
  canonical repository and deterministic newest-first release order. Full PR
  and scheduled runs first prepare one immutable run-global worklist, then use
  fourteen disjoint API-free shard workers with atomic per-release checkpoints,
  isolated verdict deltas, and manifests that prove exact coverage before
  duplicate-rejecting aggregation. Only explicit `--repository ... --latest-only`
  uses one release.
- If upstream metadata no longer proves that a configured repository URL has
  the same identity, or that repository's tags or releases cannot be resolved,
  or it has no catalog-eligible release, preparation records a visible
  per-repository `AUDIT_ERROR` and continues with the rest of the corpus. If
  every selected repository has such an error, preparation is run-global and
  writes no worklist. The audit never follows a rename redirect: adopting a
  renamed upstream requires an explicit reviewed edit to
  `additional_plugins.txt`, so a re-registered former name cannot be audited
  under the configured identity.
- Catalog decisions bind the exact release key to the current artifact hash.
  Only a `CURRENT` effective `BLOCK` is excluded. `STALE_HASH` and `UNKNOWN`
  are explicit fail-open outcomes; neither can reuse an old pass or block.
- A deterministic blockable structural finding remains `BLOCK` even when a
  required scanner fails. A corrupt archive without such proof remains a
  release-local `AUDIT_ERROR`. Safe sibling outputs publish before exit 4;
  run-global integrity failures use exit 1 and publish nothing.
- Digestless assets are bounded-streamed to validate current bytes even on a
  warm run. Cache identity includes Semgrep rules and scanner/database
  identities; scheduled runs bypass report-cache hits when ClamAV or Trivy
  database freshness cannot be established.
- Repository URLs and the complete tracked verdict schema are validated
  strictly. Release/source streams use the policy's 64 MiB/256 MiB limits,
  10/60-second connect/read timeouts, and 1 MiB chunks.
- Preparation has an eight-minute shared monotonic API deadline inside a
  ten-minute job. It bounds every producer REST request, pagination step,
  retry, and rate-limit wait; workers use the prepared commit/source snapshot
  and make no GitHub REST calls. Each uncached release obtains one immutable
  `codeload` archive and reuses its safely extracted source snapshot for all
  source consumers.
- The shared scanner bootstrap replaces three inline workflow bodies. It logs
  named bounded phases, tears down a timed-out phase's whole process group with
  a short grace period before force-killing residue, and bounds the complete
bootstrap to a fixed 600 seconds. Each phase allocates from time remaining
after reserves for later mandatory phases instead of using a fixed
per-phase cap, and retryable phases split their allocation across the attempts
still available so a full-length first attempt leaves useful time for a retry.
Before each retryable APT attempt it separately logs a bounded wait for the
dpkg frontend lock, then uses a longer APT retry backoff. It refreshes the
configured package indexes even when local package state allows the
base-package install to be skipped, and restricts the post-configuration Trivy
index refresh to the Trivy source list. Base-package archives are cached at
`.scanner-package-cache/apt-archives` (or the `BASE_APT_ARCHIVE_DIR` override).
The cache key binds the hosted runner image identifier, the exact base-package
set, and the bootstrap script SHA-256. On a cold install, APT retains the
downloaded archives there for the workflow cache save; the first run after any
key change is still cold. A restored archive is untrusted input: APT still
verifies it against the signed package index before installation, so cache reuse
never bypasses signed-index verification, and the bootstrap never uses `dpkg -i`
for cached archives. A valid warm cache logs that no package was downloaded; a
checksum mismatch discards the restored archives and triggers a cold install
that obtains and verifies replacements. This removes repeated package downloads
on the common path, but does not make scanner setup guaranteed: a cold or
unusable cache still relies on the mirror. A sufficiently slow mirror on a cold
run fails the shard closed and blocks publication. It verifies Trivy's
signing-key fingerprint, retries only safe APT/key-fetch work, and fails closed
for ClamAV, Trivy, or exact Semgrep `1.132.0` setup failures.
- CI selects changed repositories only for a plugin-list-only diff. Security
  pipeline, policy, verdict, dependency, quality-gate, test, or audit-workflow
  changes select the fourteen-shard corpus. Local and CI gates use Ruff, pytest,
  Semgrep 1.132.0, and checksummed actionlint 1.7.12.
- Production capacity is measured against the largest fourteen-shard wall-time
  projection rather than sequential unsharded completion. The preserved
  579-release snapshot projects the largest shard to 16.58 minutes at the
  observed p95 rate, within the unchanged 22-minute PR audit-step limit. Its
  repeated-enumeration count is historical evidence, not a new-design result;
  hosted-runner quota behavior, concurrency, and external scanner-mirror
  resilience remain deferred.

## Sub-plans, in execution order

Each finalizes into `dev` before the next begins, so later sub-plans branch from a base that
already contains the earlier ones.

| # | Slug | What it lands | Depends on |
|---|------|---------------|-----------|
| 1 | `release-utils` | Shared release-selection helpers; testing-channel semver fix | — |
| 2 | `audit-port` | `audit_plugins.py`, policy/allowlist, deps, cache correctness | 1 |
| 3 | `audit-scanners` | Redaction leak + source/artifact content comparison | 2 |
| 4 | `audit-verdicts` | Per-release audit entry point; durable verdict store | 2 |
| 5 | `catalog-gate` | The gate itself **and** the rebuild-loop fix | 4 |
| 6 | `audit-ci` | Audit workflows; hardening for the existing `generate.yml`; docs | 5 |
| 7 | `scanner-precision` | Cut the false-positive rate on generated artifacts and build-stamped metadata | 6 |
| 8 | `plugin-additions` | 9 of the 13 new plugin entries, vetted | 7 |
| 9 | `secret-rule-precision` | Require quoted literals in the loose secret patterns; re-evaluate 3 wrongly excluded plugins | 8 |
| 10 | `verdict-publication` | Make verdicts a tracked file so the Cloudflare build can see them; the gate is inert without this | 9 |

**The gate does not fire in production until sub-plan 10.** The live catalog is built by
Cloudflare Pages from a fresh clone, not by GitHub Actions; the verdict store lived in the
gitignored `.audit-cache/`, so `load_verdicts()` found nothing there and every release read as
unknown. Every `catalog-gate` test seeds verdicts directly, so the suite passed while
production excluded nothing. Sub-plan 10 moves the store to a tracked file.

The auditor is **advisory** until sub-plan 5. Sub-plans 2-4 deliberately land no gating, so a
half-built scanner cannot empty the store.

Sub-plans 7 and 9 were both added after the fact, each because a review measured a
false-positive problem the original plan had listed only as an unverified risk.

Sub-plan 9 is the more serious of the two. Three secret patterns make the quote optional and
so match an unquoted identifier: `token = get_steam_authentication_token()` produces
`SECRET_BEARER_TOKEN`. Unlike #7's findings, `SECRET_*` classifies `BLOCK`, which
`catalog-gate` silently excludes — so this removes plugins from the store rather than merely
flagging them. It surfaced in #8, where it wrongly excluded three legitimate plugins.

Sub-plan 7 was added after the fact. Auditing `beallio/SDH-Ludusavi`, a known-good plugin,
produced 14 findings and a `MANUAL_REVIEW` classification, all false positives — the first real
measurement of a rate the original plan explicitly listed as unverified. Nothing was broken by
it (the gate excludes only `BLOCK`), but `plugin-additions` requires reading 13 repositories'
reports and acting on them, so the scanner is corrected before decisions are made against it.

---

## Context

Ported code comes from the fork `zany130/decky-plugins-extended` @ `77cc3ca`, which is 13
commits ahead of this repo's `1f444b2` with no divergence. Re-clone it and
`git remote add upstream https://github.com/beallio/decky-plugins-extended` to reproduce
`git diff upstream/main..HEAD`. All fork line citations below refer to that tree.

`generate_json.py` builds two catalogs from GitHub releases. `main()` loops releases at
`generate_json.py:385`, builds a version dict via `build_version_object()`
(`generate_json.py:210`), and appends it to `testing_versions` at line 391 and — for
non-prereleases — `stable_versions` at line 394. That loop body is the only place a release
becomes catalog content, so it is the sole gate insertion point. The version dict
(`generate_json.py:238-245`) has keys `name`, `hash`, `artifact`, `created`, `downloads`,
`updates`; `artifact` is the ZIP `browser_download_url` from line 218. Nothing in this repo
currently persists a GitHub release ID or asset ID.

The fork's `audit_plugins.py` already caches audit results keyed on
`(repository, release_id, artifact_sha256, policy_version)` — `_cache_key()` at
`audit_plugins.py:1885`, `load_cached_report()` at 1895, `save_cached_report()` at 1924.
The requested "don't re-audit when the SHA hasn't changed" behaviour therefore exists in
design; three defects stop it working as advertised, and they are Tasks 3–5 below.

Three structural obstacles matter more than the port itself, and drive the task order:

1. **`audit_repository()` audits exactly one release, not all of them.**
   `audit_repository()` (`audit_plugins.py:2210`) internally calls `find_best_release()`
   (line 2266) and returns a single `AuditReport`. The catalog carries *every* eligible
   release per plugin. Per-release gating and last-clean fallback are impossible without a
   per-release entry point. This is a refactor, not wiring.
2. **`AUDIT_ERROR` results are never cached** (`audit_plugins.py:2502-2503`). "Keep the last
   known verdict" therefore needs a verdict store that survives an error, separate from the
   report cache.
3. **`check_for_updates.py` will spin the deploy loop forever once gating lands.**
   `check_custom_repos()` (`check_for_updates.py:53-75`) independently picks the highest
   semver non-prerelease release straight from GitHub and reports it "missing" when it is
   absent from the live catalog; `changed = bool(upstream or custom)` at line 88. A release
   held back by the gate is permanently absent, so `changed=true` fires on every scheduled
   run and triggers a Cloudflare rebuild every 6 hours forever. Task 8 fixes this and is
   **not optional**.

Reference material: the fork clone used for the review is disposable. Re-clone with
`git clone https://github.com/zany130/decky-plugins-extended` and
`git remote add upstream https://github.com/beallio/decky-plugins-extended` to reproduce
`git diff upstream/main..HEAD`.

### Decisions already made

These were settled by the repo owner. Do not revisit them mid-implementation.

| Decision | Choice |
|---|---|
| Which classifications exclude a release | `BLOCK` only. `MANUAL_REVIEW` ships but is reported. |
| Behaviour on `AUDIT_ERROR` | Fail open, and keep the release's last known non-error verdict. |
| When the newest release is excluded | Fall back to the newest release that passed. |

**Slug used throughout this plan:** `audit-gating`

---


---

## Appendix — the original single-plan task and verification text

Retained for traceability. The authoritative, per-sub-plan versions live in `docs/plans/`;
where they differ, the sub-plan wins.

## Implementation Tasks

Work in order. Tasks 1–2 are independently shippable; do not start Task 6 before Task 5 is
green.

### Task 1 — Port the mechanical prerequisites

- Add `security-reports/` and `.audit-cache/` to `.gitignore`.
- Add `PyYAML` to `[project].dependencies` in `pyproject.toml`.
- Run `uv lock` **in this repo**. Do not copy the fork's `uv.lock`: the fork's regeneration
  dropped the `[options]` block (`exclude-newer`, `exclude-newer-span`, and the
  `[options.exclude-newer-package] pyludusavi = false` pin). Confirm those three keys are
  still present in the regenerated lock before committing.

### Task 2 — Port `plugin_release_utils.py` and rewire `generate_json.py`

- Copy the fork's `plugin_release_utils.py`. Exports: `normalize_version` (line 29),
  `parse_semver` (44), `version_sort_key` (61), `has_exactly_one_zip` (81), `get_zip_asset`
  (88), `select_best_release` (95).
- Replace the equivalent inline logic in `generate_json.py` with calls to them, matching the
  fork's call sites.
- **Fix before porting:** `select_best_release(releases, allow_prerelease=True)` returns a
  stable release even when a higher prerelease exists. That is wrong for the testing
  catalog and is baked into a fork test at `tests/test_audit_plugins.py:1941-1947`. With
  `allow_prerelease=True` it must return the highest semver release, prerelease or not.
  Do not port that test as written.
- Note the one intentional behaviour change: `has_exactly_one_zip` matches `.zip`
  case-insensitively, so a release shipping `Plugin.ZIP` becomes eligible where it was not
  before.

### Task 3 — Port the audit, with the download/cache ordering fixed

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

### Task 4 — Fix cache invalidation at both layers

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

### Task 5 — Fix the two scanner correctness defects

- **Redaction leak.** Static-rule findings at `audit_plugins.py:1176-1188` store the entire
  matched source line, so a secret sharing a line with a matched pattern reaches the JSON
  report, the Markdown report, and the GitHub job summary — even though the secret scanner
  redacts its own findings inline at `audit_plugins.py:1272-1293`. There is **no** reusable
  redaction helper today; write one based on `_SECRET_PATTERNS` and apply it wherever
  `Finding.evidence` is constructed, not at render time.
- **Dead entropy detector.** `_shannon_entropy()` (`audit_plugins.py:1256-1263`) is defined
  and never called. Either wire it into the secret scanner or delete it — do not leave it
  as decoration implying coverage that does not exist.
- **Source/artifact diff compares names only.** `audit_plugins.py:1799-1825` compares path
  membership, treating both the full extracted path and a one-component-stripped path as
  candidates. It never compares contents, so a plugin that modifies a file already present in
  the repo source is invisible to it. Add content-hash comparison for paths present on both
  sides. Specify how you hash before writing code: Git blob hashing vs raw bytes, how
  generated/built files are excluded, symlink handling, archives with no single common root,
  and case-colliding paths. Getting this wrong produces noisy false positives on every
  plugin that ships a build step.

### Task 6 — Add a per-release audit entry point

Add to `audit_plugins.py`:

```python
def audit_release(repo_url, release, policy, exceptions,
                  cache_dir=CACHE_DIR, skip_cache=False) -> AuditReport
```

It audits the exact release passed in, rather than one chosen by `find_best_release()`.
Refactor `audit_repository()` (line 2210) to select a release and delegate to it, so there is
one audit path and no duplicated logic.

Add a verdict store — `.audit-cache/verdicts.json` — mapping
`repository -> release_id -> {classification, blocking_rule_ids, artifact_sha256,
audit_context_hash, audited_at}`. Write to it on every audit that reaches a real
classification. Never overwrite an existing entry with `AUDIT_ERROR`; that is what makes
fail-open-with-last-verdict work, since error results are not cached today
(`audit_plugins.py:2502-2503`). Write atomically (temp file + `os.replace`) — the generator,
the scheduled audit, and the PR audit can all touch this file, and a torn write loses every
verdict at once.

Add the adapter the generator will call:

```python
def classification_for(repository, release, verdicts) -> VerdictResult
```

Return a struct, not a bare string: `effective_classification` (what the gate acts on),
`audit_classification` (what this attempt actually produced), and `blocking_rule_ids`.
Task 7 needs the rule IDs to log *why* a release was dropped, and a bare string cannot carry
them.

When the current attempt yields `AUDIT_ERROR` and a previous non-error verdict exists, set
`effective_classification` to that previous verdict. When nothing is known **and** the audit
could not run, set both fields to `AUDIT_ERROR` — do **not** synthesise `PASS`. Task 7 already
admits `AUDIT_ERROR` into the catalog, so this fails open exactly as decided while keeping
"never audited" distinguishable from "audited clean" in the reports.

### Task 7 — Gate the catalog

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

### Task 8 — Stop the gate from spinning the rebuild loop

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

### Task 9 — Port the workflows and the docs

- Port `plugin-security-audit.yml` and `scheduled-security-audit.yml` (with Task 4's fix).
- Apply the fork's workflow hardening to the **existing** `.github/workflows/generate.yml`:
  SHA-pin every action rather than tag-pin, keep `permissions: contents: read`, add a
  `concurrency` group, and route `${{ }}` values through `env:` instead of interpolating them
  into `run:` blocks.
- Do **not** port anything from fork commit `58435fc`. It rewrites `static/index.html`, the
  README, `check_for_updates.py`'s `DEFAULT_LIVE_CATALOG_URL`, and `generate.yml`'s
  `LIVE_CATALOG_URL` from `decky-extended-plugins.beallio.com` to
  `zany130-decky-plugins-extended.pages.dev`. Skip `tests/test_deployment_urls.py` entirely —
  it asserts the fork's URLs.
- Port the README's security section, but correct two false claims it makes: that plugins are
  inspected *before acceptance* (they are not, until Task 7 lands) and that cache hits avoid
  downloads (untrue until Task 3 lands). Rewrite both to describe what the code does after
  this plan, and strip the fork branding.
- Cost note to record in the README: the 6-hourly scheduled audit clones and scans every
  configured repo. Consider widening the cron if Actions minutes become a problem.

### Task 10 — Vet and add the fork's new plugin entries

The fork adds 13 entries to `additional_plugins.txt`. All 13 are public, unarchived repos
with a root `plugin.json`/`package.json` and at least one single-ZIP release, so they are
catalog-compatible. That is compatibility, not safety, and none has been through the audit.
Add them only after Tasks 3–7 are green, then read the resulting audit report for each before
committing. Four are from a single author (`Rayekkk`) and two belong to the fork owner.

---

---

## Verification

Follow `~/.claude/skills/orchestration-plan-author/references/verification-standards.md`.
Failure cases run before the negative control. Record actual command output and pass/fail
tallies — not "confirmed working".

Run everything with `set -o pipefail`. Several steps below grep command output; without it a
failing producer is masked by a succeeding `grep` (VS-07).

1. **Lock integrity and the dependency actually landed (Task 1).** The three `[options]` keys
   already exist today, so asserting only on them passes against an implementation that did
   nothing. Assert the new dependency first:
   ```bash
   set -o pipefail
   grep -qE '^[[:space:]]*"PyYAML",' pyproject.toml || { echo "FAIL: PyYAML not added"; exit 1; }
   grep -qE '^name = "pyyaml"$' uv.lock || { echo "FAIL: pyyaml absent from lock"; exit 1; }
   for k in 'exclude-newer' 'exclude-newer-span' 'pyludusavi'; do
     grep -q "$k" uv.lock || { echo "FAIL: uv.lock lost $k"; exit 1; }
   done
   echo "PASS: dependency added, lock options intact"
   ```
   The first two lines fail before the work is done; the loop fails if `uv lock` strips
   `[options]`, which is exactly what happened in the fork.

2. **Cache actually prevents the download (Task 3).** Run the same audit twice against one
   fixture repo with a populated `.audit-cache/`. Instrument or log `download_zip()` entry.
   Assert the second run logs zero download-start lines. Then delete `.audit-cache/` and
   assert the third run logs exactly one. A run that always downloads passes neither.

3. **Allowlist busts the cache (Task 4).** Compute `POLICY_HASH` from the workflow's command,
   record it, append a comment line to `security-allowlist.yml`, recompute, and assert the
   two values differ. Against today's code this step **fails** — run it before Task 4's fix
   and record the failure, then again after. This is the "prove the gate before trusting it"
   obligation.

4. **Redaction (Task 5).** Build a fixture ZIP containing a line that trips a non-secret
   static rule *and* carries a plausible token on the same line, e.g.
   `subprocess.run(cmd)  # token ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`. Audit it with
   `GITHUB_STEP_SUMMARY` pointed at a real file so the summary is captured too.

   Assert the reports exist and are non-empty *before* searching them — a `grep -r` over a
   missing directory finds nothing and would otherwise read as success (VS-14):
   ```bash
   set -o pipefail
   token='ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
   reports=(security-reports/security-report.json security-reports/security-report.md "$GITHUB_STEP_SUMMARY")
   for f in "${reports[@]}"; do
     [ -s "$f" ] || { echo "FAIL: $f missing or empty — audit did not run"; exit 1; }
   done
   if grep -l --fixed-strings "$token" "${reports[@]}"; then
     echo "FAIL: token leaked into the files listed above"; exit 1
   fi
   echo "PASS: token redacted in all three outputs"
   ```
   Run this against the unfixed code first and confirm it reports a leak. If it does not, the
   fixture is not tripping a rule — fix the fixture before trusting the fix.

5. **The rebuild loop is closed (Task 8).** Fixture: a plugin whose newest release audits
   `BLOCK` and whose previous release passes. Run `generate_json.py`, publish the output as
   the live catalog fixture, then run `check_for_updates.py` twice. Assert `changed=false`
   both times. Against un-fixed `check_for_updates.py` this reports `changed=true`
   indefinitely; record that failure before the fix.

6. **Fail-open on error preserves the verdict (Task 6).** Seed `verdicts.json` with a `PASS`
   for a release. Do **not** force the error with an unreachable asset URL —
   `build_version_object()` (`generate_json.py:210-236`) downloads the artifact to compute the
   catalog hash, so the run dies before the audit is reached. Instead supply a valid catalog
   digest and mock `audit_release()` to return `AUDIT_ERROR`. Then assert:
   - `audit_release()` was called exactly once — otherwise an adapter that never audits at all
     passes this step;
   - the release still appears in the generated catalog;
   - `verdicts.json` still holds `PASS`, not `AUDIT_ERROR`.

7. **Negative control — the gate actually excludes (Task 7).** Runs last. Fixture plugin with
   three releases where the newest audits `BLOCK`. Assert on **normalized** version names and
   artifact hashes, not raw tags: `normalize_version()` strips the leading `v`, so a blocked
   tag `v2.0.0` is trivially "absent" from a catalog that stores `2.0.0` even with no gate at
   all (`generate_json.py:198-211, 238-245`).
   - assert the blocked release's normalized version *and* its artifact hash are absent from
     both `plugins.json` and `testing_plugins.json`;
   - assert the fallback release's normalized version and hash are at `versions[0]`;
   - assert the plugin itself is still present (fallback worked, plugin did not vanish).
   - Run this fixture twice, the second time with the blocked version pre-seeded into the
     fetched catalog, to cover the `merge_plugin_versions()` removal path from Task 7.

8. **Mutation test.** Delete the `BLOCK` branch added in Task 7 and re-run step 7. It must go
   red. If it stays green the gate is not wired into the code path that builds the catalog.

9. **Full suite.** `uv run pytest`. Record the pass/fail tally. The fork's suite is 188 tests;
   expect the count to differ after Task 2 removes the bad prerelease test.

### Explicitly not verified by this plan

- **False-positive rate of the ruleset is unmeasured.** This is the reason the gate is
  `BLOCK`-only. Before tightening to `MANUAL_REVIEW`, run the audit across the full
  `additional_plugins.txt` and read every finding by hand.
- **Fail-open ships unaudited artifacts during an outage.** A first-seen release whose audit
  cannot run is admitted with no verdict at all. That is the settled policy, but the catalog
  gives users no signal that it happened. Consider surfacing a degraded-state marker on such
  entries; not designed here.
- **Verdict-store concurrency is untested.** Task 6 specifies atomic writes, but no test
  exercises the generator, the scheduled audit, and the PR audit writing at once.
- **ClamAV, Trivy, and Semgrep integration paths** are exercised only when those binaries are
  present on the runner. Local runs without them take the "unavailable" branch, so the
  scanner-parsing code is untested here.
- **The 13 new plugin entries are checked for catalog compatibility only** — public,
  unarchived, one ZIP per release. No safety claim is made about them.
- **Audit coverage of the testing channel.** The auditor prefers stable releases; after
  Task 6 it audits whatever release is passed, but confirm the testing catalog's head is
  actually among the releases audited rather than assuming Task 2's fix covers it.
- No load or cost testing of the 6-hourly scheduled audit against the full plugin list.

---
