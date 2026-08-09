"""Decide whether the published catalog is out of date.

Cloudflare rebuilds on push, so between pushes the catalog is frozen at whatever
upstream looked like at the last deploy. This compares what is live against the
current upstream catalog and the latest release of every configured repository.
The verdict store's audited hashes are used only to identify BLOCKed upstream
artifacts; the rebuild still performs any expensive hashing.

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


class UpstreamArtifactIdentityError(RuntimeError):
    """The current GitHub artifact behind an upstream version is unresolved."""

    def __init__(self, repository, normalized_version, reason):
        self.repository = repository
        self.normalized_version = normalized_version
        self.reason = reason
        super().__init__(
            f"repository={repository} version={normalized_version}: {reason}"
        )


def version_index(plugins):
    return {
        p["name"]: {(v.get("name"), v.get("hash")) for v in p.get("versions") or []}
        for p in plugins
    }


def report(missing, label):
    if not missing:
        return
    print(f"{label} ({len(missing)}):")
    for name, version in missing[:10]:
        print(f"  {name} {version} is not in the live catalog")
    if len(missing) > 10:
        print(f"  ... and {len(missing) - 10} more")


def _resolve_upstream_release(version, release_cache, download_policy=None):
    """Resolve and hash the exact current release behind an upstream version."""
    artifact = version.get("artifact", "")
    normalized_version = g.normalize_version(str(version.get("name") or ""))
    try:
        repository = g.canonicalize_github_release_asset_repository_url(artifact)
        owner, repo = g.parse_github_repository_url(repository)
    except ValueError as exc:
        raise UpstreamArtifactIdentityError(
            "<unresolved>",
            normalized_version,
            f"invalid upstream GitHub release asset URL {artifact!r}",
        ) from exc
    if repository not in release_cache:
        release_cache[repository] = g.get_releases(owner, repo)
    releases = release_cache[repository]
    version_candidates = []
    artifact_candidates = []
    for release in releases:
        if not g.is_release_eligible(release, allow_prerelease=True):
            continue
        if g.normalize_version(release.get("tag_name", "")) != normalized_version:
            continue
        version_candidates.append(release)
        asset = g.get_zip_asset(release) or {}
        if asset.get("browser_download_url") == artifact:
            artifact_candidates.append(release)
    if not version_candidates:
        raise UpstreamArtifactIdentityError(
            repository,
            normalized_version,
            "no eligible release matches the normalized version",
        )
    if not artifact_candidates:
        raise UpstreamArtifactIdentityError(
            repository,
            normalized_version,
            (
                f"{len(version_candidates)} eligible release(s) match the normalized "
                "version, but no ZIP asset matches the upstream artifact URL"
            ),
        )
    if len(artifact_candidates) != 1:
        raise UpstreamArtifactIdentityError(
            repository,
            normalized_version,
            (
                "ambiguous current artifact: "
                f"{len(artifact_candidates)} eligible releases match the normalized "
                "version and upstream artifact URL"
            ),
        )
    release = artifact_candidates[0]
    current = g.build_version_object(release, policy=download_policy)
    if current is None:
        raise UpstreamArtifactIdentityError(
            repository,
            normalized_version,
            "the uniquely matched release did not yield a current ZIP artifact",
        )
    return release, current


def check_upstream(
    live,
    verdicts,
    blockable_rules=None,
    *,
    download_policy=None,
    enforcement_mode="enforce",
):
    missing = []
    release_cache = {}
    for plugin in g.fetch_json(g.PLUGINS_URL):
        newest = None
        for version in plugin.get("versions") or []:
            release, current = _resolve_upstream_release(
                version, release_cache, download_policy=download_policy
            )
            current_hash = current.get("hash")
            is_blocked = g.catalog_version_is_blocked(
                version,
                verdicts,
                blockable_rules,
                release=release,
                current_artifact_sha256=current_hash,
            )
            if not is_blocked or enforcement_mode != "enforce":
                newest = current
                break
        if newest is None:
            continue
        identity = (newest.get("name"), newest.get("hash"))
        if identity not in live.get(plugin["name"], set()):
            missing.append((plugin["name"], newest.get("name")))
    return missing


def check_custom_repos(
    live,
    verdicts,
    blockable_rules=None,
    *,
    download_policy=None,
    enforcement_mode="enforce",
):
    missing = []
    for url in g.read_repo_urls():
        try:
            url = g.canonicalize_github_repository_url(url)
            owner, repo = g.parse_github_repository_url(url)
            branch = g.get_repo_info(owner, repo).get("default_branch", "main")
            name = g.resolve_plugin_name(
                g.get_plugin_json(owner, repo, branch),
                g.get_package_json(owner, repo, branch),
            )
            versions = []
            for release in g.get_releases(owner, repo):
                if not g.is_release_eligible(release, allow_prerelease=False):
                    continue
                version = g.build_version_object(release, policy=download_policy)
                if version is None:
                    continue
                verdict = g.classification_for(
                    url,
                    release,
                    verdicts,
                    blockable_rules,
                    current_artifact_sha256=version["hash"],
                )
                if (
                    verdict.effective_classification != "BLOCK"
                    or enforcement_mode != "enforce"
                ):
                    versions.append(version)
            g.sort_versions(versions)
        except g.ArtifactDownloadError:
            raise
        except Exception as e:
            # An unreachable repo is not evidence of a change, and the build
            # itself tolerates these, so never rebuild on one.
            print(f"  skipped {owner}/{repo}: {e}")
            continue

        if versions and (versions[0]["name"], versions[0]["hash"]) not in live.get(
            name, set()
        ):
            missing.append((name, versions[0]["name"]))
    return missing


def main():
    live = version_index(g.fetch_json(LIVE_URL))
    verdicts = g.load_verdicts()
    try:
        policy = g.load_policy()
        enforcement_mode = (policy.get("enforcement") or {}).get(
            "mode"
        ) or "report-only"
        blockable_rules = set(policy.get("blockable_rules") or [])
    except Exception as exc:
        raise RuntimeError(f"Could not load catalog security policy: {exc}") from exc

    try:
        upstream = check_upstream(
            live,
            verdicts,
            blockable_rules,
            download_policy=policy,
            enforcement_mode=enforcement_mode,
        )
    except (g.ArtifactDownloadError, UpstreamArtifactIdentityError) as exc:
        print(f"Fatal artifact identity failure: {exc}")
        return 1
    report(upstream, "Upstream versions missing")

    try:
        custom = check_custom_repos(
            live,
            verdicts,
            blockable_rules,
            download_policy=policy,
            enforcement_mode=enforcement_mode,
        )
    except g.ArtifactDownloadError as exc:
        print(f"Fatal artifact identity failure: {exc}")
        return 1
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
