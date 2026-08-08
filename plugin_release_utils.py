"""plugin_release_utils.py - Shared release-selection logic for Decky Loader plugins.

Both generate_json.py and audit_plugins.py use these functions to ensure the
auditor inspects the exact release artifact that the catalog distributes.

This module is side-effect free and safe to import from either context.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import unquote, urlsplit

# ---------------------------------------------------------------------------
# Repository and artifact identity
# ---------------------------------------------------------------------------

_ENCODED_PATH_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_GITHUB_SHA256_DIGEST = re.compile(r"sha256:([0-9a-fA-F]{64})")


def parse_github_repository_url(url: str) -> tuple[str, str]:
    """Return the canonical lowercase ``(owner, repo)`` for a GitHub URL.

    Only the configured-repository form is accepted: HTTPS, the exact
    ``github.com`` host, two decoded path components, and at most one trailing
    slash. Rejecting alternate URL forms keeps verdict, allowlist, audit, and
    catalog identities from drifting apart.
    """
    error = f"Invalid GitHub repository URL: {url!r}"
    if not isinstance(url, str) or not url or url != url.strip():
        raise ValueError(error)

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc

    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(error)

    raw_path = parsed.path
    if not raw_path.startswith("/") or raw_path.endswith("//"):
        raise ValueError(error)
    if _ENCODED_PATH_SEPARATOR.search(raw_path):
        raise ValueError(error)

    path_without_optional_slash = raw_path[:-1] if raw_path.endswith("/") else raw_path
    raw_parts = path_without_optional_slash[1:].split("/")
    if len(raw_parts) != 2 or not all(raw_parts):
        raise ValueError(error)

    parts = tuple(unquote(part) for part in raw_parts)
    if any(not part or "/" in part or "\\" in part for part in parts):
        raise ValueError(error)
    owner, repo = parts
    if repo.lower().endswith(".git"):
        raise ValueError(error)
    return owner.lower(), repo.lower()


def canonicalize_github_repository_url(url: str) -> str:
    """Return the unique HTTPS URL used as a repository identity."""
    owner, repo = parse_github_repository_url(url)
    return f"https://github.com/{owner}/{repo}"


def canonical_repository_key(url: str) -> str:
    """Return a canonical ``owner/repo`` key suitable for sorting and hashing."""
    return "/".join(parse_github_repository_url(url))


def sort_repository_urls(urls: list[str]) -> list[str]:
    """Canonicalize repository URLs and return owner/repo ascending order."""
    return sorted(canonicalize_github_repository_url(url) for url in urls)


def normalize_github_sha256_digest(value: Any) -> Optional[str]:
    """Return a lowercase bare SHA-256 from an exact GitHub digest, else None."""
    if not isinstance(value, str):
        return None
    match = _GITHUB_SHA256_DIGEST.fullmatch(value)
    return match.group(1).lower() if match else None


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

# Matches the version inside a release tag: "v1.2.3", "Release-0.7.1",
# "decky-romm-sync-v0.29.0" all yield the bare version.
_VERSION_IN_TAG = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?")

# Full semver: major.minor[.patch][-prerelease][+build]
_SEMVER = re.compile(
    r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$"
)


def normalize_version(tag_name: str) -> str:
    """Extract a semver-compatible version string from a release tag.

    Decky runs store version strings through compare-versions' validate()
    before offering an update, and anything that is not semver-shaped is
    discarded -- a plugin tagged "Release-0.7.1" can never show an update.
    Pull the version out of the tag, falling back to the bare tag when it
    holds nothing version-shaped.
    """
    match = _VERSION_IN_TAG.search(tag_name)
    if match:
        return match.group(0)
    return tag_name.lstrip("v")


def parse_semver(name: str) -> Optional[tuple]:
    """Return (major, minor, patch, prerelease_identifiers) or None.

    Prerelease identifiers are compared per semver: numeric ones numerically,
    so beta.10 outranks beta.9.  Build metadata is ignored, as compare-versions
    ignores it.
    """
    match = _SEMVER.match((name or "").strip())
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    identifiers: list = []
    for part in (prerelease or "").split(".") if prerelease else []:
        identifiers.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return int(major), int(minor or 0), int(patch or 0), identifiers


def version_sort_key(name: str, created: str = "") -> tuple:
    """Return a sort key for a version string.

    Decky only ever reads versions[0] -- checkForPluginUpdates compares it
    against the installed version and the install dropdown defaults to it -- so
    the highest version has to sort first.  Ordering by release date instead
    puts a late hotfix to an old branch on top, and floats rolling tags
    ("nightly", "dev-build") above every real release, where validate() then
    rejects them and no update is ever offered.  Versions with no parseable
    number sort last.

    A prerelease ranks below the release it leads to: 1.0.0 > 1.0.0-beta.1.
    """
    parsed = parse_semver(name)
    if parsed is None:
        return (0, 0, 0, 0, 0, [], created)
    major, minor, patch, prerelease = parsed
    return (1, major, minor, patch, 0 if prerelease else 1, prerelease, created)


def has_exactly_one_zip(release: dict[str, Any]) -> bool:
    """Return True when the release has exactly one ZIP asset."""
    assets = release.get("assets") or []
    zips = [a for a in assets if a.get("name", "").lower().endswith(".zip")]
    return len(zips) == 1


def get_zip_asset(release: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return the single ZIP asset from a release, or None."""
    assets = release.get("assets") or []
    zips = [a for a in assets if a.get("name", "").lower().endswith(".zip")]
    return zips[0] if len(zips) == 1 else None


def is_release_eligible(
    release: dict[str, Any],
    allow_prerelease: bool = True,
) -> bool:
    """Return whether a release may be audited or published by a consumer."""
    if release.get("draft") or not has_exactly_one_zip(release):
        return False
    return allow_prerelease or not release.get("prerelease")


def _numeric_id(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _timestamp_key(value: Any) -> tuple[int, datetime]:
    if not isinstance(value, str) or not value:
        return 0, datetime.min.replace(tzinfo=timezone.utc)
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return 1, timestamp.astimezone(timezone.utc)
    except ValueError:
        return 0, datetime.min.replace(tzinfo=timezone.utc)


def release_order_key(release: dict[str, Any]) -> tuple[Any, ...]:
    """Return the descending audit-order key for one eligible release."""
    timestamp = release.get("published_at") or release.get("created_at")
    asset = get_zip_asset(release) or {}
    return (
        _timestamp_key(timestamp),
        _numeric_id(release.get("id")),
        _numeric_id(asset.get("id")),
    )


def ordered_eligible_releases(
    releases: list[dict[str, Any]],
    allow_prerelease: bool = True,
) -> list[dict[str, Any]]:
    """Filter releases by the shared contract and return deterministic order."""
    eligible = [
        release
        for release in releases
        if is_release_eligible(release, allow_prerelease=allow_prerelease)
    ]
    return sorted(eligible, key=release_order_key, reverse=True)


def select_best_release(
    releases: list[dict[str, Any]],
    allow_prerelease: bool = False,
) -> Optional[dict[str, Any]]:
    """Return the newest eligible release with exactly one ZIP asset.

    Eligible releases are sorted by semantic version (highest first) so that
    GitHub publication order does not affect the result.

    When ``allow_prerelease`` is False (the stable catalog): only non-prerelease
    releases are considered.  When True (the testing catalog): prereleases are
    also eligible, and the highest semver release (prerelease or not) is returned.

    Returns None when no eligible release exists.
    """
    eligible = [
        release
        for release in releases
        if is_release_eligible(release, allow_prerelease=allow_prerelease)
    ]

    if not eligible:
        return None

    def _key(rel: dict) -> tuple:
        tag = rel.get("tag_name", "")
        normalised = normalize_version(tag)
        created = rel.get("published_at") or rel.get("created_at") or ""
        return version_sort_key(normalised, created)

    eligible.sort(key=_key, reverse=True)
    return eligible[0]
