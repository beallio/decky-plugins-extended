"""Derive the store-backed repository list from the official plugin database.

The official store's catalog API (`https://plugins.deckbrew.xyz/plugins`) carries
no repository field, so the only machine-readable link from a published plugin to
its source is the submodule map in `SteamDeckHomebrew/decky-plugin-database`:
every plugin enters the official store as a submodule pointing at its own
repository.

This module resolves that map and records every verified official plugin source.
It separately keeps only the entries this catalog can build newer versions from
in `store_plugins.txt`. Keeping the two repository sets separate is the point:
source links can cover the full official catalog without expanding the audit and
release corpus.

Regenerate with:

    uv run store_discovery.py

The result is committed. Resolving it at runtime instead would make the audit
worklist depend on a mutable external input, so two runs could legitimately
disagree about which repositories are in scope, and a pull request could not show
the corpus changing.
"""

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

import generate_json as g
import plugin_release_utils

DATABASE_REPOSITORY = "SteamDeckHomebrew/decky-plugin-database"

HEADER = """\
# store_plugins.txt -- GENERATED FILE, do not edit by hand.
#
# Source repositories for plugins the official Decky store already publishes,
# derived from the submodule map in {database}.
# Regenerate with: uv run store_discovery.py
#
# additional_plugins.txt stays hand-maintained and holds only the plugins the
# official store does not carry.
"""

_SUBMODULE_BLOCK = re.compile(r"^\[submodule\s+\"(?P<name>[^\"]*)\"\]", re.MULTILINE)
_SUBMODULE_URL = re.compile(r"^\s*url\s*=\s*(?P<url>\S+)\s*$", re.MULTILINE)
_SSH_PREFIX = re.compile(r"^git@([^:/]+):")


_SOURCE_NAME_OVERRIDES = {
    "https://gitlab.com/finewolf-projects/decky-plugin-bluetooth-wake-control": "BT Wake Control",
}


@dataclass(frozen=True)
class Submodule:
    """One `.gitmodules` entry: the declared name and its remote URL."""

    name: str
    url: str


@dataclass
class DiscoveryResult:
    """Repositories to track, the store versions to defer to, and every skip."""

    included: list[str] = field(default_factory=list)
    versions: dict[str, list[str]] = field(default_factory=dict)
    sources: dict[str, list[str]] = field(default_factory=dict)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def skip(self, subject: str, reason: str) -> None:
        self.skipped.append((subject, reason))


def parse_gitmodules(text: str) -> list[Submodule]:
    """Return every submodule that declares a URL, in file order.

    `.gitmodules` is INI-like but git does not require a specific key order, so
    split on section headers and take the first `url` inside each block rather
    than pairing lines positionally.
    """
    if not isinstance(text, str):
        raise TypeError("gitmodules content must be a string")
    submodules: list[Submodule] = []
    matches = list(_SUBMODULE_BLOCK.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.end() : end]
        url_match = _SUBMODULE_URL.search(block)
        if url_match is None:
            continue
        submodules.append(Submodule(match.group("name"), url_match.group("url")))
    return submodules


def canonical_github_url(url: str) -> Optional[str]:
    """Return the canonical HTTPS repository URL, or None when not GitHub.

    `.gitmodules` mixes forms the strict parser rejects outright: `git@` SSH
    remotes, a trailing `.git`, trailing slashes, and non-GitHub hosts such as
    the GitLab and self-hosted remotes a few plugins use. Normalize what can be
    normalized and reject the rest, because every downstream reader requires the
    exact HTTPS `github.com/<owner>/<repo>` form.
    """
    if not isinstance(url, str):
        return None
    candidate = _SSH_PREFIX.sub(r"https://\1/", url.strip())
    candidate = candidate.rstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[: -len(".git")]
    try:
        return plugin_release_utils.canonicalize_github_repository_url(candidate)
    except ValueError:
        return None


def canonical_source_url(url: str) -> Optional[str]:
    """Return a safe HTTPS source URL for any supported submodule remote."""
    if not isinstance(url, str):
        return None
    candidate = _SSH_PREFIX.sub(r"https://\1/", url.strip()).rstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[: -len(".git")]
    try:
        return plugin_release_utils.canonicalize_repository_source_url(candidate)
    except ValueError:
        return None


def match_store_plugin_names(
    candidate: str, store_versions: dict[str, set[str]]
) -> list[tuple[str, str]]:
    """Resolve every official name with the same punctuation-normalized identity."""
    key = candidate.casefold()
    normalized = re.sub(r"[^a-z0-9]+", "", key)
    matches = sorted(
        store_key
        for store_key in store_versions
        if re.sub(r"[^a-z0-9]+", "", store_key) == normalized
    )
    return [
        (store_key, candidate if store_key == key else store_key)
        for store_key in matches
    ]


def has_contributable_release(
    releases: Iterable[dict], deferred_versions: Iterable[str] = ()
) -> bool:
    """Whether any release would actually reach the stable catalog.

    Prerelease-only repositories are excluded on purpose: they can only ever
    contribute testing versions, and `check_for_updates.check_custom_repos`
    evaluates stable eligibility alone, so tracking them would grow the audit
    corpus without ever refreshing the published stable catalog.

    A repository whose every stable release is already published by the official
    store is excluded for the same reason. The catalog defers to the store's own
    artifact for those versions and the audit skips them, so tracking the
    repository would add corpus without adding a single catalog entry.
    """
    deferred = set(deferred_versions)
    for release in releases or []:
        if release.get("prerelease"):
            continue
        if not plugin_release_utils.is_release_eligible(
            release, allow_prerelease=False
        ):
            continue
        if (
            plugin_release_utils.normalize_version(release.get("tag_name", ""))
            in deferred
        ):
            continue
        return True
    return False


def fetch_gitmodules(repository: str = DATABASE_REPOSITORY) -> str:
    """Read `.gitmodules` from the official plugin database's default branch."""
    owner, _, repo = repository.partition("/")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/.gitmodules"
    response = g.session.get(url, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if payload.get("encoding") != "base64":
        raise ValueError(f"Unsupported encoding for .gitmodules in {repository}")
    return base64.b64decode(payload["content"]).decode("utf-8")


def fetch_store_versions() -> dict[str, set[str]]:
    """Versions the official store publishes, keyed by casefolded plugin name.

    Both channels count: a version the testing store already carries is one the
    official infrastructure built and vets, so this catalog has no reason to
    republish or re-scan its own artifact for it.
    """
    published: dict[str, set[str]] = {}
    for url in (g.PLUGINS_URL, g.TESTING_PLUGINS_URL):
        for plugin in g.fetch_json(url):
            name = plugin.get("name")
            if not isinstance(name, str) or not name:
                continue
            names = published.setdefault(name.casefold(), set())
            for version in plugin.get("versions") or []:
                if isinstance(version.get("name"), str) and version["name"]:
                    names.add(version["name"])
    return published


def read_tracked_urls(path: str = plugin_release_utils.PLUGIN_LIST_FILE) -> set[str]:
    """Canonical URLs already held by the hand-maintained list."""
    if not os.path.exists(path):
        return set()
    tracked = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            canonical = canonical_github_url(url)
            if canonical:
                tracked.add(canonical.lower())
    return tracked


def discover_store_repositories(
    *,
    gitmodules_text: str,
    store_versions: dict[str, set[str]],
    tracked_urls: set[str],
    repo_metadata: Callable[[str, str], Optional[dict]],
    plugin_name: Callable[[str, str, str], Optional[str]],
    releases: Callable[[str, str], list[dict]],
) -> DiscoveryResult:
    """Select the store-backed repositories this catalog can build from.

    Filters run cheapest-first so a submodule that is obviously out of scope
    never costs an API call. Every rejection is recorded with its reason: a
    silent corpus is impossible to review in a diff.
    """
    result = DiscoveryResult()
    seen: set[str] = set()
    claimed_names: dict[str, str] = {}

    for submodule in parse_gitmodules(gitmodules_text):
        subject = submodule.name or submodule.url
        source_url = canonical_source_url(submodule.url)
        if source_url is None:
            result.skip(subject, f"not a repository source: {submodule.url}")
            continue
        url = canonical_github_url(submodule.url)
        if url is None:
            candidate_name = _SOURCE_NAME_OVERRIDES.get(
                source_url, submodule.name.rsplit("/", 1)[-1]
            )
            matched_names = match_store_plugin_names(candidate_name, store_versions)
            if not matched_names:
                result.skip(
                    subject,
                    f"source name {candidate_name!r} matches no store plugin",
                )
                continue
            for _, display_name in matched_names:
                sources = result.sources.setdefault(display_name, [])
                if source_url not in sources:
                    sources.append(source_url)
            result.skip(source_url, "source recorded; not a GitHub audit repository")
            continue
        if url.lower() in tracked_urls:
            result.skip(url, "already in additional_plugins.txt")
            continue
        owner, repo = plugin_release_utils.parse_github_repository_url(url)
        metadata = repo_metadata(owner, repo)
        if not metadata:
            result.skip(url, "repository metadata unavailable")
            continue

        # GitHub answers a renamed repository's API through a redirect, so the
        # submodule URL can be stale while still resolving. Adopt the canonical
        # identity: audit worklist preparation compares metadata full_name to the
        # configured URL and reports an identity mismatch for the old one.
        full_name = metadata.get("full_name")
        if isinstance(full_name, str) and full_name:
            renamed = canonical_github_url(f"https://github.com/{full_name}")
            if renamed and renamed != url:
                result.skip(url, f"renamed upstream, tracking {renamed} instead")
                url = renamed
                if url.lower() in tracked_urls:
                    result.skip(url, "already in additional_plugins.txt")
                    continue
                owner, repo = plugin_release_utils.parse_github_repository_url(url)

        if url.lower() in seen:
            result.skip(url, "duplicate submodule target")
            continue

        name = plugin_name(owner, repo, metadata.get("default_branch") or "main")
        if not name:
            result.skip(url, "no plugin.json name on the default branch")
            continue
        matched_names = match_store_plugin_names(name, store_versions)
        if not matched_names:
            # The generator merges into an upstream entry by lowercased name, so
            # a mismatch would publish a second entry beside the store's own.
            result.skip(url, f"plugin.json name {name!r} matches no store plugin")
            continue
        for _, display_name in matched_names:
            sources = result.sources.setdefault(display_name, [])
            if url not in sources:
                sources.append(url)
        store_name = name.casefold()
        if store_name not in store_versions:
            result.skip(url, f"plugin.json name {name!r} matches no exact store plugin")
            continue
        if metadata.get("archived"):
            result.skip(url, "repository is archived")
            continue
        claimed = claimed_names.get(store_name)
        if claimed:
            # Two submodules resolve to one plugin name, usually an original and
            # a maintainer fork. The catalog can only merge one source into that
            # entry, so take the first and name the loser rather than letting
            # them overwrite each other's versions.
            result.skip(url, f"plugin name {name!r} already tracked via {claimed}")
            continue
        deferred = store_versions[store_name]
        repo_releases = releases(owner, repo)
        if not has_contributable_release(repo_releases, deferred):
            result.skip(
                url,
                "no stable single-zip release beyond what the official store "
                "already publishes",
            )
            continue

        seen.add(url.lower())
        result.included.append(url)
        result.versions[url] = sorted(deferred)
        claimed_names[store_name] = url

    result.included.sort(key=plugin_release_utils.canonical_repository_key)
    result.sources = {
        name: sorted(urls, key=str.casefold)
        for name, urls in sorted(
            result.sources.items(), key=lambda item: (item[0].casefold(), item[0])
        )
    }
    return result


def render_list(urls: Iterable[str], database: str = DATABASE_REPOSITORY) -> str:
    """Render the generated list, header included, with a trailing newline."""
    body = "".join(f"{url}\n" for url in urls)
    return HEADER.format(database=database) + body


def _repo_metadata(owner: str, repo: str) -> Optional[dict]:
    try:
        return g.get_repo_info(owner, repo)
    except Exception as exc:  # noqa: BLE001 - one bad repo must not end the run
        print(f"  metadata failed for {owner}/{repo}: {exc}")
        return None


def _plugin_name(owner: str, repo: str, branch: str) -> Optional[str]:
    try:
        return (g.get_plugin_json(owner, repo, branch) or {}).get("name")
    except Exception as exc:  # noqa: BLE001
        print(f"  plugin.json failed for {owner}/{repo}: {exc}")
        return None


def _releases(owner: str, repo: str) -> list[dict]:
    try:
        return g.get_releases(owner, repo)
    except Exception as exc:  # noqa: BLE001
        print(f"  releases failed for {owner}/{repo}: {exc}")
        return []


def render_versions(versions: dict[str, list[str]]) -> str:
    """Render the store-version map with a trailing newline for a clean diff."""
    ordered = {url: versions[url] for url in sorted(versions)}
    return json.dumps(ordered, indent=2, sort_keys=False) + "\n"


def render_sources(sources: dict[str, list[str]]) -> str:
    """Render the official plugin source map with deterministic ordering."""
    ordered = {
        name: sorted(sources[name], key=str.casefold)
        for name in sorted(sources, key=lambda value: (value.casefold(), value))
    }
    return json.dumps(ordered, indent=2, sort_keys=False) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        default=plugin_release_utils.DISCOVERED_PLUGIN_LIST_FILE,
        help="Where to write the generated repository list.",
    )
    parser.add_argument(
        "--versions-output",
        default=plugin_release_utils.STORE_VERSIONS_FILE,
        help="Where to write the per-repository store version map.",
    )
    parser.add_argument(
        "--sources-output",
        default=plugin_release_utils.STORE_SOURCES_FILE,
        help="Where to write the official plugin source map.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when any generated file is out of date instead of writing.",
    )
    args = parser.parse_args(argv)

    print(f"Reading submodules from {DATABASE_REPOSITORY}...")
    result = discover_store_repositories(
        gitmodules_text=fetch_gitmodules(),
        store_versions=fetch_store_versions(),
        tracked_urls=read_tracked_urls(),
        repo_metadata=_repo_metadata,
        plugin_name=_plugin_name,
        releases=_releases,
    )

    for subject, reason in result.skipped:
        print(f"  skip {subject}: {reason}")
    deferred = sum(len(names) for names in result.versions.values())
    print(
        f"\n{len(result.included)} repositories tracked, {len(result.skipped)} skipped; "
        f"{deferred} store-published versions deferred and "
        f"{len(result.sources)} official source mappings recorded."
    )

    outputs = {
        args.output: render_list(result.included),
        args.versions_output: render_versions(result.versions),
        args.sources_output: render_sources(result.sources),
    }
    if args.check:
        stale = []
        for path, rendered in outputs.items():
            current = ""
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    current = handle.read()
            if current != rendered:
                stale.append(path)
        if stale:
            print(f"out of date: {', '.join(stale)}; run: uv run store_discovery.py")
            return 1
        print("generated files are up to date.")
        return 0

    for path, rendered in outputs.items():
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"Wrote {path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
