"""Decide whether the published catalog is out of date.

Cloudflare rebuilds on push, so between pushes the catalog is frozen at whatever
upstream looked like at the last deploy. This compares what is live against the
current upstream catalog and the latest release of every configured repository.
It deliberately does not hash anything: names and version strings are enough to
know a rebuild is needed, and the rebuild does the expensive work.

The test is "is this version missing from the live entry", not "does the newest
version match". The catalogs merge GitHub releases into upstream entries, so ours
is often ahead of Deckbrew -- CheatDeck and PlayTime are both ahead today -- and
an equality check would report a change on every run forever.

Writes changed=true|false to $GITHUB_OUTPUT and stdout.
"""

import os
import sys

import generate_json as g

LIVE_URL = os.environ.get(
    "LIVE_CATALOG_URL", "https://decky-extended-plugins.beallio.com/plugins.json"
)


def version_index(plugins):
    return {
        p["name"]: {v.get("name") for v in p.get("versions") or []} for p in plugins
    }


def report(missing, label):
    if not missing:
        return
    print(f"{label} ({len(missing)}):")
    for name, version in missing[:10]:
        print(f"  {name} {version} is not in the live catalog")
    if len(missing) > 10:
        print(f"  ... and {len(missing) - 10} more")


def check_upstream(live):
    missing = []
    for plugin in g.fetch_json(g.PLUGINS_URL):
        versions = plugin.get("versions") or []
        if not versions:
            continue
        newest = versions[0].get("name")
        if newest not in live.get(plugin["name"], set()):
            missing.append((plugin["name"], newest))
    return missing


def check_custom_repos(live):
    missing = []
    for url in g.read_repo_urls():
        owner, repo = url.rstrip("/").split("/")[-2:]
        try:
            branch = g.get_repo_info(owner, repo).get("default_branch", "main")
            name = g.resolve_plugin_name(
                g.get_plugin_json(owner, repo, branch),
                g.get_package_json(owner, repo, branch),
            )
            versions = g.sort_versions(
                [
                    {
                        "name": g.normalize_version(r.get("tag_name", "")),
                        "created": r.get("published_at") or "",
                    }
                    for r in g.get_releases(owner, repo)
                    if not r.get("prerelease")
                ]
            )
        except Exception as e:
            # An unreachable repo is not evidence of a change, and the build
            # itself tolerates these, so never rebuild on one.
            print(f"  skipped {owner}/{repo}: {e}")
            continue

        if versions and versions[0]["name"] not in live.get(name, set()):
            missing.append((name, versions[0]["name"]))
    return missing


def main():
    live = version_index(g.fetch_json(LIVE_URL))

    upstream = check_upstream(live)
    report(upstream, "Upstream versions missing")

    custom = check_custom_repos(live)
    report(custom, "Custom repository releases missing")

    changed = bool(upstream or custom)
    if not changed:
        print("Live catalog already has every upstream and configured release.")

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")
    print(f"changed={'true' if changed else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
