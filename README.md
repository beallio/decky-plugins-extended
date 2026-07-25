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
  https://decky-plugins-extended.pages.dev/plugins.json
  ```

2. **Browse plugins.**
   - Return to the Decky Store using the shopping bag icon. It will populate
     with the extended plugin catalog.

## View the catalogs

The generated JSON files are hosted directly on Cloudflare Pages and can be viewed in your browser:

- **Stable plugins:** [https://decky-plugins-extended.pages.dev/plugins.json](https://decky-plugins-extended.pages.dev/plugins.json)
- **Testing plugins:** [https://decky-plugins-extended.pages.dev/testing_plugins.json](https://decky-plugins-extended.pages.dev/testing_plugins.json)

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
- A `package.json` file on its default branch, used for the author,
  description, and tags.
- At least one GitHub release.
- Exactly one `.zip` asset on every release that should appear in the catalogs.

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

### Store sorting

Decky Loader sorts the store server-side: the frontend appends
`?sort_by=<name|date|downloads>&sort_direction=<asc|desc>` to the store URL and
renders the returned array in order. Static files ignore query strings, so the
Cloudflare Pages Function in `functions/_middleware.js` reorders
`plugins.json` and `testing_plugins.json` per request, matching what
`plugins.deckbrew.xyz` returns for the same query (code-point name comparison,
`created` for date, `downloads` for downloads). Requests without a recognized
`sort_by` are passed through untouched.

Custom plugins have no download counts, so they sort as zero and land at the
bottom of a downloads-descending list; their date comes from the repository's
creation timestamp.

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

The GitHub Actions workflow does not publish anything. It runs when generator
inputs change and on manual dispatch, generating both catalogs with `uv` and
validating their plugin IDs, names, version lists, and SHA-256 hashes, so a bad
`additional_plugins.txt` entry surfaces as a failed check instead of a failed
Cloudflare build.
