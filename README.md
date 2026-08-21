# Decky Plugins Extended

A custom Decky Loader plugin repository that merges community and custom
plugins into a single compatible store.

## How to use on your Steam Deck

To install plugins from this extended repository, point Decky Loader to its
custom store URL.

1. **Set the Custom Store URL.**
   - Open the Quick Access Menu and select the Decky Loader plug icon.
   - Open **Settings** using the gear icon.
   - Open the **General** tab in Decky settings.
   - Find **Store Channel** and set it to `Custom`
   - Set **Custom Store** to:

  ```text
  https://decky-extended-plugins.beallio.com/plugins.json
  ```

2. **Browse plugins.**
   - Return to the Decky Store using the shopping bag icon. It will populate
     with the extended plugin catalog.

## View the catalogs

The generated JSON files are hosted directly on Cloudflare Pages and can be viewed in your browser:

- **Stable plugins:** [https://decky-extended-plugins.beallio.com/plugins.json](https://decky-extended-plugins.beallio.com/plugins.json)
- **Testing plugins:** [https://decky-extended-plugins.beallio.com/testing_plugins.json](https://decky-extended-plugins.beallio.com/testing_plugins.json)

The `decky-plugins-extended.pages.dev` URLs serve the same content and keep
working.

## Developer guide

The generator fetches, hashes, and merges custom GitHub releases into the
upstream Deckbrew stable and testing catalogs. This is a minimal repository;
do not create or store planning artifacts in a `docs/` directory.

### Add a plugin

Add the plugin repository URL to `additional_plugins.txt`, one URL per line:

```text
https://github.com/beallio/SDH-Ludusavi
```

Each repository must have:

- A `plugin.json` file on its default branch with a `name` field. Decky
  identifies an installed plugin by that name, so the catalog entry has to use
  it or the store will never match the plugin you have installed and will never
  offer updates. A repository without `plugin.json` falls back to the
  `package.json` name, which usually differs (`sdh-ludusavi` vs
  `SDH-Ludusavi`) and has that consequence.
- A `package.json` file on its default branch, used for the author and as the
  fallback source for the description and tags.
- At least one GitHub release.
- Exactly one `.zip` asset on every release that should appear in the catalogs.

Tags and the description come from `plugin.json`'s `publish` block, matching
the official store; `package.json` `keywords` and `description` are only the
fallback. A plugin that declares `"flags": ["root"]` also gets a `root` tag,
because that is how the store card decides to show its "runs as root" warning.

Store card images come from `plugin.json`'s `publish.image`, the same field the
official store ingests. Cards are 320x200 and cropped with `object-fit: cover`,
so a wide banner works better than a tall icon. A repository that has no image,
still carries the template's placeholder (which points at the loader's own
repo), or whose image URL is gone falls back to the GitHub repository card at
`https://opengraph.githubassets.com/1/<owner>/<repo>`. To give a plugin a proper
image, get its author to set `publish.image` upstream.

Release tags are reduced to the version they contain, so `Release-0.7.1` and
`decky-romm-sync-v0.30.1` become `0.7.1` and `0.30.1`. Decky validates store
versions as semver before offering an update and silently ignores anything
else. Tags with no version in them at all (`nightly`, `dev-build`) are passed
through unchanged; keep those as GitHub prereleases so they stay out of the
stable catalog.

Stable releases are included in both catalogs. GitHub prereleases are included
only in the testing catalog. Releases with zero or multiple `.zip` assets are
skipped.

### Landing page

`static/index.html` is copied into `public/` on every build and served at the
site root. `public/` is build output and gitignored, so anything that should be
published has to live in `static/`, not `public/`.

### Store sorting

Decky Loader sorts the store server-side: the frontend appends
`?sort_by=<name|date|downloads>&sort_direction=<asc|desc>` to the store URL and
renders the returned array in order. Static files ignore query strings, so the
Cloudflare Pages Function in `functions/_middleware.js` reorders
`plugins.json` and `testing_plugins.json` per request, matching what
`plugins.deckbrew.xyz` returns for the same query (code-point name comparison,
`created` for date, `downloads` for downloads). Requests without a recognized
`sort_by` are passed through untouched.

Versions within a plugin are ordered by semver, highest first, not by release
date. Decky only ever reads `versions[0]`, so a late hotfix to an old branch or
a rolling tag would otherwise sit on top and suppress update detection. Versions
with no parseable number (`nightly`, `dev-build`) sort last.

### Install counts

Counts live in a D1 database rather than in the catalogs, which are rebuilt from
scratch on every deploy. The Pages Function folds them into the response before
sorting, so `sort_by=downloads` sees real numbers, and records a row when Decky
POSTs its increment after an install. Counts are *added* to whatever the entry
already carries, so plugins merged with an upstream entry keep Deckbrew's totals
and gain the installs made through this store. Without the binding everything
still works; custom entries just stay at zero.

Setup:

```sh
npx wrangler d1 create decky-plugin-counts
npx wrangler d1 execute decky-plugin-counts --remote --file=schema.sql
```

Then bind it in the Cloudflare Pages project under Settings -> Bindings as a D1
database with the variable name `DB`, for both Production and Preview.

The endpoint is unauthenticated, so anyone can POST to inflate a number. That is
acceptable for a personal store; do not read these as trustworthy statistics.

### Local development

This project uses [uv](https://docs.astral.sh/uv/) for Python dependency
management. Install `uv`, provide a GitHub token, and run the generator:

```sh
export GITHUB_TOKEN="your_personal_access_token"
uv run generate_json.py
```

`uv` installs the dependencies from `pyproject.toml` into an isolated virtual
environment. The generated catalogs are written to `public/plugins.json` and
`public/testing_plugins.json`.

Run the same local gates as CI with:

```sh
uv run ruff check .
uv run ruff format --check .
GITHUB_TOKEN=test-token uv run pytest -q
scripts/orchestration/run-quality-gates
```

The project quality gate also downloads the official actionlint v1.7.12
archive through `gh`, verifies the release checksum, and validates every GitHub
Actions workflow. Pytest exit 5 (no tests collected) is a failure. PR and
scheduled audit jobs install Semgrep 1.132.0 and assert that exact version.

The token must be able to read the configured repositories; the GitHub Actions
workflow uses its built-in `GITHUB_TOKEN`.

## Automation

Cloudflare Pages is connected to this repository and deploys on every push to
`main`. It runs `generate_json.py` as its build step, so the catalogs are
regenerated from upstream Deckbrew and GitHub at deploy time rather than being
committed — `public/` is gitignored and holds only local build output. The
build reads a `GITHUB_TOKEN` configured as an environment variable in the
Cloudflare Pages dashboard, and the same deploy publishes `functions/`.

The GitHub Actions workflow has two jobs, neither of which publishes anything.

`build` runs when generator inputs change and on manual dispatch. It generates
both catalogs with `uv` and validates their plugin IDs, names, version lists and
SHA-256 hashes, so a bad `additional_plugins.txt` entry surfaces as a failed
check instead of a failed Cloudflare build.

`refresh` runs every 6 hours and on manual dispatch. Because Cloudflare only
rebuilds on push, the catalog would otherwise stay frozen at whatever upstream
looked like at the last deploy. `check_for_updates.py` compares the live catalog
against the upstream catalog and the latest release of every configured
repository, and only when something is missing does the job POST the Cloudflare
deploy hook. The check asks whether a version is *absent* from the live entry
rather than whether the newest versions match, because merging GitHub releases
into upstream entries regularly leaves this catalog ahead of Deckbrew's.

To enable it, create a deploy hook under Pages -> Settings -> Builds &
deployments -> Deploy hooks, and store the URL as the repository secret
`CLOUDFLARE_DEPLOY_HOOK`. Without the secret the job fails loudly rather than silently
skipping the rebuild.

## Security auditing

The pull-request and scheduled audit workflows statically inspect configured
plugin repositories and every catalog-eligible release ZIP. The checked-in
policy currently uses `enforcement.mode: enforce`. Catalog generation excludes
only a `CURRENT` effective `BLOCK`: the exact release key and the current
artifact SHA-256 must match the durable verdict. `MANUAL_REVIEW`, release-local
`AUDIT_ERROR`, `STALE_HASH`, and `UNKNOWN` remain eligible under the fail-open
catalog policy. The audit never imports, executes, installs, or sources plugin
code.

### What is scanned

- **Archive safety**: path traversal, zip bombs, setuid files, device files,
  symlink escapes, duplicate paths, and oversized members.
- **Source vs artifact comparison**: unexpected files and differing file
  contents between the tagged repository source and the release ZIP, with
  generated build output excluded from comparison.
- **Plugin metadata**: `plugin.json` and `package.json` validity, declared
  permissions and flags, and version consistency.
- **Privilege and system access**: `sudo`, `pkexec`, kernel-module loading,
  `systemctl`, `iptables`, filesystem mounting, and other privileged operations.
- **Dangerous patterns**: `os.system`, `subprocess` with `shell=True`,
  `eval`/`exec`, `curl | sh`, and similar execution primitives.
- **Persistence**: systemd services, cron jobs, `LD_PRELOAD`, shell-profile
  modification, and udev rule installation.
- **Sensitive data access**: SSH private keys, Steam authentication files,
  `/etc/shadow`, and credential-file paths.
- **Environment access**: direct copying, expansion, iteration, enumeration, or
  serialization of the whole environment requires `MANUAL_REVIEW`; a targeted
  read of a credential-bearing environment-variable name is recorded as
  `PASS_WITH_WARNINGS`.
- **Network behaviour**: extracted URLs, domains, telemetry endpoints, disabled
  TLS verification, and hard-coded authorization headers.
- **Obfuscation**: large base64 payloads, `marshal.loads`, `pickle.loads`,
  packed scripts, and dynamic remote code loading.
- **Native binaries**: ELF, PE, AppImage, and shared-library detection by magic
  bytes.
- **Secrets**: private keys, GitHub tokens, and cloud-provider credentials,
  redacted in every report surface.
- **Malware**: ClamAV signature scanning of safely extracted contents.
- **Dependency vulnerabilities**: Trivy scans both the shipped release ZIP and
  the repository source at the release's exact commit, so source lockfiles are
  checked even when they are omitted from the bundle. Findings identify whether
  they came from the artifact or source tree.
- **Syntax-aware static analysis**: Semgrep runs a small vendored ruleset with
  registry access, telemetry, and version checks disabled at scan time. Semgrep
  findings are advisory and can classify no higher than `MANUAL_REVIEW` while
  their Decky-plugin false-positive rate is being measured.

### What is not guaranteed

A passing audit does **not** prove a plugin is safe. Static analysis cannot
detect all threats, evaluate runtime behaviour, or inspect obfuscation that
perfectly mimics benign code. The audit identifies suspicious behaviour; it
does not certify a plugin.

### Classifications

| Classification | Meaning |
|---|---|
| `PASS` | No blocking or review-required findings. Archive safe. No unexplained binaries. |
| `PASS_WITH_WARNINGS` | Minor issues such as low/medium vulnerabilities, ordinary network usage, a named credential environment-variable read, or an unavailable optional scanner. |
| `MANUAL_REVIEW` | Root flag, sudo, native binaries, systemd changes, obfuscated code, direct whole-environment harvesting, or a high-severity dependency vulnerability. |
| `BLOCK` | A structural artifact fact: a malware signature; archive traversal or an escaping symlink; a compression-ratio, total-size, file-count, or single-file-size archive bomb limit; a setuid/setgid member; a device file; or a named pipe. |
| `AUDIT_ERROR` | This release attempt or repository worklist-preparation outcome could not reach a conclusion because of a bounded-download failure, corrupt ZIP, required-scanner failure, repository-local upstream failure, or other local error. |

`BLOCK` is restricted by `security-policy.yml` to the structural facts listed
above. Behavioural findings such as privileged commands, shell downloads,
destructive-looking text, or secret-shaped literals remain visible and inform
the rarity-ranked review queue, but they classify no higher than
`MANUAL_REVIEW` and never remove a plugin from the catalog.

### Enforcement and catalog gating

The current policy is **enforce**. A completed `BLOCK` exits 2 and
`MANUAL_REVIEW` exits 3. A release-local incomplete audit uses exit 4 only after
safe sibling reports and verdict deltas have been checkpointed; its prior
completed verdict is preserved. Exit 1 is reserved for run-global policy,
verdict-store, aggregation, or output-integrity failures, whose outputs are not
safe to publish. Mixed release outcomes use precedence 1, 4, 2, 3, 0.

Report-only remains supported but inactive. To use it explicitly, change
`security-policy.yml`:

```yaml
enforcement:
  mode: report-only
```

In report-only mode findings remain visible, but completed `BLOCK` and
`MANUAL_REVIEW` results do not make the command fail. Release-local and
run-global integrity failures remain distinct.

### Running an audit locally

```sh
export GITHUB_TOKEN="your_personal_access_token"

# Audit all configured plugins:
uv run python audit_plugins.py --all --output-dir security-reports

# Audit plugins changed in the current branch relative to main:
uv run python audit_plugins.py --changed --base-ref origin/main

# Audit a single repository:
uv run python audit_plugins.py --repository https://github.com/owner/repo

# Fast one-release smoke/debug audit (the only newest-release-only mode):
uv run python audit_plugins.py --repository https://github.com/owner/repo --latest-only

# Run one deterministic shard of the full worklist:
uv run python audit_plugins.py --all --shard-count 14 --shard-index 0
```

Reports are written to `security-reports/security-report.json` and
`security-reports/security-report.md`. A progress manifest, isolated verdict
delta, and report are written atomically after every release. Resume skips only
an exact completed identity: canonical repository, GitHub release ID, asset ID,
current artifact hash, resolved source commit, and audit-context hash. Work is
ordered by canonical `owner/repo`, then release timestamp, release ID, and asset
ID; releases are newest-first within each repository. Generated reports are
gitignored.

### Reviewing reports

Open `security-reports/security-report.md` for the human-readable summary.
Each finding includes a `rule_id`, severity, classification, file path, line
number, and redacted evidence. Start with `BLOCK` findings, then
`MANUAL_REVIEW`, and follow the recommended-actions section.

### Adding a narrow allowlist exception

Exceptions must be scoped to a specific artifact by its exact SHA-256 hash.
Add an entry to `security-allowlist.yml` and open a pull request for review:

```yaml
exceptions:
  - repository: owner/plugin-name
    release: "1.2.3"
    artifact_sha256: "exact-64-character-hex-sha256-of-the-release-zip"
    rule: ROOT_ACCESS
    reason: >
      Hardware-control plugin requires a documented privileged helper to
      access GPU registers. Binary audited separately.
    approved_by: security-reviewer
    expires: "2027-01-01"
```

- Every rule in the policy's live `blockable_rules` set requires a canonical
  lowercase 64-character `artifact_sha256` matching the current artifact; it
  cannot use `"any"`. Non-blockable exceptions may use `"any"` only with an
  exact repository, release, rule, approval, reason, and unexpired date scope.
- Entries expire automatically; expired entries produce a warning but do not
  silently apply.
- There is no global "ignore all findings" switch.

### Why artifact SHA-256 is used

Mutable release tags can be force-pushed to point at a different commit, and
GitHub release assets can be replaced without changing the tag name. Allowlist
entries therefore use the downloaded ZIP's SHA-256, while audit cache entries
also bind the release/asset identity, audit context, and resolved tag commit.

GitHub's digest is trusted only when it is exactly `sha256:` followed by 64 hex
characters. Digest-backed releases can use a compatible pre-download cache hit.
Digestless releases always perform one bounded artifact stream to prove the
current bytes before reusing extraction/scanner results; a catalog's old hash is
never reused merely because its version and URL match. Cache identity includes
the artifact, release/asset, resolved source commit, policy, allowlist, vendored
Semgrep rules, scanner executables/versions, and available ClamAV/Trivy database
freshness. Scheduled runs bypass report-cache hits when database freshness
cannot be established.

Verdict lookup reports `CURRENT` for an exact release-key/hash match,
`STALE_HASH` for an absent or different stored hash, and `UNKNOWN` for no
verdict. The latter two are explicit fail-open audit records in `audit.json` and
`audit.html`; the public `plugins.json` and `testing_plugins.json` schemas do not
change.

Repository identities accept only
`https://github.com/<owner>/<repo>` with an optional trailing slash and are
canonicalized to lowercase owner/repository keys. Credentials, ports, query or
fragment data, `.git`, encoded separators, and extra path segments are rejected.
The tracked verdict store is validated through every nested record and never
falls back to `.audit-cache`.

Downloads are streamed once with policy limits: release ZIPs are capped at
67,108,864 bytes, source archives at 268,435,456 bytes, connect/read timeouts are
10/60 seconds, and chunks are 1,048,576 bytes. Declared and observed overflows
fail closed and partial files are removed.

### Why untrusted plugin code is never executed

Every external plugin repository is treated as hostile input. The audit reads
file bytes, parses metadata and lock files, and performs static pattern
matching. It never imports Python modules from the plugin, runs shell scripts,
executes installers, or runs `npm install` or `pip install` inside plugin source
trees. This avoids an entire class of supply-chain attacks in which a plugin's
build or install step compromises the CI runner.

### How scheduled release audits work

`scheduled-security-audit.yml` runs every six hours and audits every eligible
stable or prerelease release of every configured repository in fourteen isolated,
deterministic shards. Each run starts with one immutable run-global worklist:
the preparation job alone enumerates repositories/releases and resolves source
commits, validates a fingerprinted canonical JSON snapshot, and uploads it only
for that run. The fourteen workers download that exact snapshot and are an
API-free shard data plane: they receive no GitHub credential and do not repeat
repository, release, ref, tree, raw-file, or source-tarball REST requests.

Each worker records its assigned identities and byte bindings for its report and
verdict delta in `shard-manifest.json`. Aggregation requires the prepared
worklist, fourteen report/delta/manifest triples, their common fingerprint, and
exact coverage of every assigned release identity before it writes aggregate
evidence or updates the verdict store. A valid empty selection still supplies
fourteen empty triples. This is deliberately stronger than counting uploaded
artifacts.

If upstream repository metadata no longer identifies the URL configured in
`additional_plugins.txt`, or that repository's tags or releases cannot be
resolved, or it has no catalog-eligible release, preparation records a
per-repository `AUDIT_ERROR` and continues auditing the rest of the corpus.
If every selected repository has such an error, preparation instead fails
run-globally and writes no worklist. The audit never follows a repository
rename redirect: adopting a renamed upstream is an explicit, reviewed edit to
`additional_plugins.txt`, which prevents a re-registered former name from being
audited under the old identity.

An uncached release materializes one immutable `codeload.github.com` source
archive at its resolved commit, safely extracts it once, and shares that
snapshot between metadata checks, Trivy, and source/artifact comparison. Cache
eligibility is checked before source acquisition. Its workflow cache covers
policy, allowlist, Semgrep rules, implementation, dependency inputs, and the
shared scanner bootstrap; runtime database freshness decides whether
report-cache reuse is safe. The workflows never modify the allowlist or
automatically approve a finding.

The producer has an eight-minute monotonic GitHub API budget inside its
ten-minute job. Connect/read attempts, pagination, retries, and rate-limit
waits are clipped to that deadline; an over-budget reset fails run-global
instead of sleeping into a worker timeout. Scanner setup is one shared scanner
bootstrap script with named, bounded phases. A timed-out phase terminates its
whole process group, allows a short grace period, then force-kills any residue.
APT retries first wait in a separately logged, bounded phase for the dpkg
frontend lock and use a longer APT-specific backoff; the full bootstrap has a
fixed 600-second budget below the unchanged twelve-minute setup-step cap. Each
phase derives its timeout from the budget still available after reserving
minimum time for later mandatory phases, rather than using a fixed per-phase
cap. A retryable phase splits that allocation across its attempts so a
full-length first try keeps useful time for its retry. The bootstrap refreshes
the configured package indexes even when its installed-package query lets it
skip the base-package install; after configuring Trivy, the second index
refresh is restricted to the Trivy source list. Base-package archives live in
the workspace-local `.scanner-package-cache/apt-archives` directory (or the
`BASE_APT_ARCHIVE_DIR` override). The three scanner jobs restore that directory
before setup and save it afterwards; its key includes the runner OS identity
(rather than an image build that can vary between shards), the exact
base-package set (`wget`, `apt-transport-https`, `gnupg`, `lsb-release`, and
`clamav`), and the bootstrap script's SHA-256.
During a cold base-package install, the bootstrap tells APT to retain the
downloaded archives in that directory, then removes APT's transient `lock`
file and `partial/` working directory before the cache save. The install phase
logs `cache=`, `downloaded=`, `archive-retained=`, and `archive-saveable=` so
a failed best-effort cache save is visible in one shard's log. The first run
after any key change is necessarily cold.

That cache is untrusted input. Before a cached archive is installed, APT checks
it against the signed package index with its normal checksum verification; the
bootstrap never installs a cached `.deb` with `dpkg -i`. A checksum mismatch
causes the bootstrap to discard the restored archives and perform a cold,
signed-index-verified install. That verification makes the OS-level cache key
granularity safe even when a restored archive no longer matches the current
index. Cache reuse therefore never bypasses signed-index verification. A valid
warm cache takes APT's no-download path and logs
`cache=warm downloaded=false`, which removes the repeated package download on
the common path. This does not guarantee scanner setup: a cache miss, unusable
cache, or changed key takes the cold APT path and still depends on the mirror.
A sufficiently slow mirror on that cold run fails the shard closed and blocks
publication. Retry remains limited to idempotent APT/key-fetch work, with a
verified Trivy signing-key fingerprint and hard ClamAV, Trivy, and exact
Semgrep `1.132.0` checks.

Production capacity is measured against the maximum fourteen-shard wall-time
estimate, not against a sequential unsharded scan. The preserved 579-release
snapshot assigns 30–52 releases per shard. A 161-release cold sample observed a
14.797-second mean and 18.541-second p95 per release; including enumeration, the
largest shard projects to 16.58 minutes at p95, leaving 5.42 minutes of headroom
inside the PR audit step's unchanged 22-minute limit. Its 83-request-per-worker,
1,162-request repetition is historical capacity evidence for the prior design,
not a measurement of the worklist data plane. Local tests prove topology,
integrity, and bounded failure; hosted-runner quota behavior and resilience to
an external scanner mirror outage remain deferred until a reviewed workflow run
is authorized.

The scheduled audit clones and scans every configured repository on each run.
That is the principal Actions-minutes cost; widen the cron interval if the
six-hour cadence becomes too expensive.

For pull requests, a change only to `additional_plugins.txt` selects changed
repositories. Any audit/generator/update/release-utility, policy, allowlist,
verdict, Semgrep-rule, dependency, selector, quality-gate, test, or audit-workflow
change selects the same fourteen-shard full corpus. The one-release smoke remains a
separate fast end-to-end check and is never treated as corpus coverage.
