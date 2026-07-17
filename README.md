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
  https://beallio.github.io/decky-plugins-extended/plugins.json
  ```

2. **Browse plugins.**
   - Return to the Decky Store using the shopping bag icon. It will populate
     with the extended plugin catalog.

## View the catalogs

The generated JSON files are hosted directly on GitHub Pages and can be viewed in your browser:

- **Stable plugins:** [https://beallio.github.io/decky-plugins-extended/plugins.json](https://beallio.github.io/decky-plugins-extended/plugins.json)
- **Testing plugins:** [https://beallio.github.io/decky-plugins-extended/testing_plugins.json](https://beallio.github.io/decky-plugins-extended/testing_plugins.json)

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

- A `package.json` file on its default branch with a `name` field.
- At least one GitHub release.
- Exactly one `.zip` asset on every release that should appear in the catalogs.

Stable releases are included in both catalogs. GitHub prereleases are included
only in the testing catalog. Releases with zero or multiple `.zip` assets are
skipped.

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

The GitHub Actions workflow runs when generator inputs change, on manual
dispatch, and every hour. It generates both catalogs with `uv`, validates
their plugin IDs, names, version lists, SHA-256 hashes, and artifact URLs, then
deploys the `public/` directory to GitHub Pages.
