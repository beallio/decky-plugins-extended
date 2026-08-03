"""plugin_release_utils.py - Shared release-selection logic for Decky Loader plugins.

Both generate_json.py and audit_plugins.py use these functions to ensure the
auditor inspects the exact release artifact that the catalog distributes.

This module is side-effect free and safe to import from either context.
"""

from __future__ import annotations

import re
from typing import Any, Optional

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
    eligible = [r for r in releases if has_exactly_one_zip(r)]
    if not allow_prerelease:
        eligible = [r for r in eligible if not r.get("prerelease")]

    if not eligible:
        return None

    def _key(rel: dict) -> tuple:
        tag = rel.get("tag_name", "")
        normalised = normalize_version(tag)
        created = rel.get("published_at") or rel.get("created_at") or ""
        return version_sort_key(normalised, created)

    eligible.sort(key=_key, reverse=True)
    return eligible[0]
