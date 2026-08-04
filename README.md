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

Run the unit tests with:

```sh
GITHUB_TOKEN=test-token uv run python -m unittest discover -s tests -v
```

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
plugin repositories and their release ZIPs. Catalog generation consults the
durable verdict store before adding releases: an effective `BLOCK` verdict is
excluded, while `MANUAL_REVIEW`, `AUDIT_ERROR`, and releases without a verdict
remain eligible under the fail-open policy. The audit never imports, executes,
installs, or sources plugin code.

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
| `PASS_WITH_WARNINGS` | Minor issues such as low/medium vulnerabilities, ordinary network usage, or an unavailable optional scanner. |
| `MANUAL_REVIEW` | Root flag, sudo, native binaries, systemd changes, obfuscated code, or a high-severity dependency vulnerability. |
| `BLOCK` | Malware signature, archive traversal, zip bomb, credential in a release, undisclosed executable download, or explicitly destructive command. |
| `AUDIT_ERROR` | Audit could not reach a conclusion because of a download failure, corrupt ZIP, or internal error. |

### Report-only workflow mode and catalog gating

The audit workflows default to **report-only**: `BLOCK` and `MANUAL_REVIEW`
findings are prominent in the job summary but do not prevent a pull request
from merging. Internal audit failures still fail the audit job. Separately,
catalog generation excludes releases whose effective durable verdict is
`BLOCK`; `MANUAL_REVIEW` and `AUDIT_ERROR` continue to ship as decided by the
catalog policy.

To make the audit workflow itself return a blocking status after evaluating
false-positive rates, change `security-policy.yml`:

```yaml
enforcement:
  mode: enforce   # was: report-only
```

In enforcement mode the audit command exits 2 for `BLOCK` and 3 for
`MANUAL_REVIEW`.

### Running an audit locally

```sh
export GITHUB_TOKEN="your_personal_access_token"

# Audit all configured plugins:
uv run python audit_plugins.py --all --output-dir security-reports

# Audit plugins changed in the current branch relative to main:
uv run python audit_plugins.py --changed --base-ref origin/main

# Audit a single repository:
uv run python audit_plugins.py --repository https://github.com/owner/repo
```

Reports are written to `security-reports/security-report.json` and
`security-reports/security-report.md`. Generated reports are gitignored.

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

- `MALWARE`, `ARCHIVE_TRAVERSAL`, and `CREDENTIAL_THEFT` rules require an exact
  `artifact_sha256`; they cannot be excepted with `"any"`.
- Entries expire automatically; expired entries produce a warning but do not
  silently apply.
- There is no global "ignore all findings" switch.

### Why artifact SHA-256 is used

Mutable release tags can be force-pushed to point at a different commit, and
GitHub release assets can be replaced without changing the tag name. Allowlist
entries therefore use the downloaded ZIP's SHA-256, while audit cache entries
also bind the release/asset identity, audit context, and resolved tag commit.

A compatible cache hit is found before the ZIP download, so an unchanged
release is not downloaded again. A changed asset identity, audit context, or
source commit causes a cache miss; after that download, the observed SHA-256 is
revalidated before the result is reused or stored.

### Why untrusted plugin code is never executed

Every external plugin repository is treated as hostile input. The audit reads
file bytes, parses metadata and lock files, and performs static pattern
matching. It never imports Python modules from the plugin, runs shell scripts,
executes installers, or runs `npm install` or `pip install` inside plugin source
trees. This avoids an entire class of supply-chain attacks in which a plugin's
build or install step compromises the CI runner.

### How scheduled release audits work

`scheduled-security-audit.yml` runs every six hours and audits the newest
eligible release of every configured repository. Its workflow cache is keyed
by the policy, allowlist, and audit implementation, so changing any of them
invalidates prior results. It never modifies the allowlist or automatically
approves a finding.

The scheduled audit clones and scans every configured repository on each run.
That is the principal Actions-minutes cost; widen the cron interval if the
six-hour cadence becomes too expensive.
