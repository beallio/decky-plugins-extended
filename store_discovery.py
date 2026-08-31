"""Derive the store-backed repository list from the official plugin database.

The official store's catalog API (`https://plugins.deckbrew.xyz/plugins`) carries
no repository field, so the only machine-readable link from a published plugin to
its source is the submodule map in `SteamDeckHomebrew/decky-plugin-database`:
every plugin enters the official store as a submodule pointing at its own
repository.

This module resolves that map, keeps only the entries this catalog can actually
build newer versions from, and renders `store_plugins.txt` as the generated
companion to the hand-maintained `additional_plugins.txt`. Keeping the two lists
separate is the point: `additional_plugins.txt` stays a curated set of plugins
the official store does not carry, while every store-backed repository is
re-derived rather than tracked by hand.

Regenerate with:

    uv run store_discovery.py

The result is committed. Resolving it at runtime instead would make the audit
worklist depend on a mutable external input, so two runs could legitimately
disagree about which repositories are in scope, and a pull request could not show
the corpus changing.
"""

import argparse
import base64
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


@dataclass(frozen=True)
class Submodule:
    """One `.gitmodules` entry: the declared name and its remote URL."""

    name: str
    url: str


@dataclass
class DiscoveryResult:
    """Repositories to track, plus why every other submodule was left out."""

    included: list[str] = field(default_factory=list)
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


def has_stable_eligible_release(releases: Iterable[dict]) -> bool:
    """Whether any release can become a stable catalog version.

    Prerelease-only repositories are excluded on purpose. They can only ever
    contribute testing versions, and `check_for_updates.check_custom_repos`
    evaluates stable eligibility alone, so tracking them would grow the audit
    corpus without ever refreshing the published stable catalog.
    """
    for release in releases or []:
        if release.get("prerelease"):
            continue
        if plugin_release_utils.is_release_eligible(release, allow_prerelease=False):
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


def fetch_store_names() -> set[str]:
    """Casefolded names of every plugin the official stable store publishes."""
    return {
        plugin["name"].casefold()
        for plugin in g.fetch_json(g.PLUGINS_URL)
        if isinstance(plugin.get("name"), str) and plugin["name"]
    }


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
    store_names: set[str],
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

    for submodule in parse_gitmodules(gitmodules_text):
        subject = submodule.name or submodule.url
        url = canonical_github_url(submodule.url)
        if url is None:
            result.skip(subject, f"not a GitHub repository: {submodule.url}")
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
        if metadata.get("archived"):
            result.skip(url, "repository is archived")
            continue

        name = plugin_name(owner, repo, metadata.get("default_branch") or "main")
        if not name:
            result.skip(url, "no plugin.json name on the default branch")
            continue
        if name.casefold() not in store_names:
            # The generator merges into an upstream entry by lowercased name, so
            # a mismatch would publish a second entry beside the store's own.
            result.skip(url, f"plugin.json name {name!r} matches no store plugin")
            continue
        if not has_stable_eligible_release(releases(owner, repo)):
            result.skip(url, "no stable release with exactly one zip asset")
            continue

        seen.add(url.lower())
        result.included.append(url)

    result.included.sort(key=plugin_release_utils.canonical_repository_key)
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


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        default=plugin_release_utils.DISCOVERED_PLUGIN_LIST_FILE,
        help="Where to write the generated list.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when the generated list differs from --output instead of writing.",
    )
    args = parser.parse_args(argv)

    print(f"Reading submodules from {DATABASE_REPOSITORY}...")
    result = discover_store_repositories(
        gitmodules_text=fetch_gitmodules(),
        store_names=fetch_store_names(),
        tracked_urls=read_tracked_urls(),
        repo_metadata=_repo_metadata,
        plugin_name=_plugin_name,
        releases=_releases,
    )

    for subject, reason in result.skipped:
        print(f"  skip {subject}: {reason}")
    print(
        f"\n{len(result.included)} repositories tracked, {len(result.skipped)} skipped."
    )

    rendered = render_list(result.included)
    if args.check:
        current = ""
        if os.path.exists(args.output):
            with open(args.output, encoding="utf-8") as handle:
                current = handle.read()
        if current != rendered:
            print(f"{args.output} is out of date; run: uv run store_discovery.py")
            return 1
        print(f"{args.output} is up to date.")
        return 0

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    print(f"Wrote {args.output}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
