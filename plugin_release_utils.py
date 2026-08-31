"""plugin_release_utils.py - Shared release-selection logic for Decky Loader plugins.

Both generate_json.py and audit_plugins.py use these functions to ensure the
auditor inspects the exact release artifact that the catalog distributes.

This module is side-effect free and safe to import from either context.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
import time
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote, urlsplit

# The hand-maintained list of plugins the official store does not carry, and the
# generated companion holding store-backed source repositories. Every reader
# consumes the union of the two, so both names live here rather than being
# repeated per module.
PLUGIN_LIST_FILE = "additional_plugins.txt"
DISCOVERED_PLUGIN_LIST_FILE = "store_plugins.txt"

# ---------------------------------------------------------------------------
# Repository and artifact identity
# ---------------------------------------------------------------------------

_ENCODED_PATH_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_GITHUB_SHA256_DIGEST = re.compile(r"sha256:([0-9a-fA-F]{64})")


class ReleasePaginationError(RuntimeError):
    """A repository's complete GitHub release history could not be loaded."""


class ApiDeadlineExceeded(RuntimeError):
    """A producer request cannot complete within its shared API deadline."""


class ApiRequestBudget:
    """One monotonic deadline shared by every producer GitHub API request.

    Retry-After takes precedence when GitHub supplies it.  Otherwise a valid
    X-RateLimit-Reset value is converted from wall-clock time; malformed or
    absent rate-limit headers use the documented 60-second fallback.  Every
    request timeout, retry backoff, and rate-limit wait is clipped to this one
    budget, so a worker cannot sleep past its surrounding Actions deadline.
    """

    malformed_rate_limit_fallback_seconds = 60.0

    def __init__(
        self,
        deadline_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
    ) -> None:
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, (int, float))
            or deadline_seconds <= 0
        ):
            raise ValueError("API deadline must be greater than zero")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise ValueError("max_retries must be a non-negative integer")
        if max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._sleep = sleep
        self._deadline = monotonic() + float(deadline_seconds)
        self.max_retries = max_retries

    def remaining_seconds(self) -> float:
        return self._deadline - self._monotonic()

    def _require_remaining(self, action: str) -> float:
        remaining = self.remaining_seconds()
        if remaining <= 0:
            raise ApiDeadlineExceeded(f"Cannot {action}: no remaining API deadline")
        return remaining

    def clip_timeout(self, timeout: int | float | tuple[float, float]):
        """Clip a request's connect/read timeout to the remaining budget."""
        remaining = self._require_remaining("start GitHub API request")
        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                raise ValueError(
                    "API timeout tuple must contain connect and read values"
                )
            return tuple(min(float(value), remaining) for value in timeout)
        return min(float(timeout), remaining)

    def sleep_within_budget(self, seconds: float, reason: str) -> None:
        if seconds < 0:
            raise ValueError("API retry delay must not be negative")
        remaining = self._require_remaining(reason)
        if seconds > remaining:
            raise ApiDeadlineExceeded(
                f"Cannot {reason}: {seconds:g}s wait exceeds the remaining API deadline "
                f"({remaining:.3f}s)"
            )
        self._sleep(seconds)

    def _rate_limit_wait(self, headers: Any) -> float:
        if isinstance(headers, Mapping):
            retry_after = headers.get("Retry-After")
            if isinstance(retry_after, str):
                try:
                    parsed_retry_after = float(retry_after)
                except ValueError:
                    parsed_retry_after = None
                if parsed_retry_after is not None and parsed_retry_after >= 0:
                    return parsed_retry_after

            reset = headers.get("X-RateLimit-Reset")
            if isinstance(reset, str):
                try:
                    return max(0.0, float(reset) - self._wall_time())
                except ValueError:
                    pass
        return self.malformed_rate_limit_fallback_seconds

    @staticmethod
    def _is_rate_limited(response: Any) -> bool:
        status = getattr(response, "status_code", None)
        text = getattr(response, "text", "")
        return status == 429 or (
            status == 403 and isinstance(text, str) and "rate limit" in text.lower()
        )

    @staticmethod
    def _close_response(response: Any) -> None:
        close = getattr(response, "close", None)
        if callable(close):
            close()

    def get_response(
        self,
        session: Any,
        url: str,
        *,
        timeout: int | float | tuple[float, float],
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Fetch one API response, closing every discarded retry response."""
        last_error: Optional[BaseException] = None
        for attempt in range(self.max_retries + 1):
            response = None
            try:
                kwargs: dict[str, Any] = {"timeout": self.clip_timeout(timeout)}
                if params is not None:
                    kwargs["params"] = params
                response = session.get(url, **kwargs)
                if self._is_rate_limited(response):
                    wait = self._rate_limit_wait(getattr(response, "headers", {}))
                    self._close_response(response)
                    response = None
                    if attempt == self.max_retries:
                        raise ApiDeadlineExceeded(
                            "GitHub API rate limit persisted through the bounded retry budget"
                        )
                    self.sleep_within_budget(wait, "wait for GitHub API rate limit")
                    continue
                response.raise_for_status()
                return response
            except ApiDeadlineExceeded:
                if response is not None:
                    self._close_response(response)
                raise
            except Exception as exc:
                last_error = exc
                if response is not None:
                    self._close_response(response)
                if attempt == self.max_retries:
                    raise
                self.sleep_within_budget(2**attempt, "retry GitHub API request")
        raise RuntimeError(f"GitHub API retry loop exhausted: {last_error}")


def _parse_github_repository_atoms(
    raw_owner: str,
    raw_repo: str,
    *,
    error: str,
) -> tuple[str, str]:
    """Decode and validate the two path atoms that identify a repository."""

    def decode_atom(raw_atom: str) -> str:
        atom = unquote(raw_atom)
        if (
            not atom
            or atom in {".", ".."}
            or any(
                character in "%?#/\\" or unicodedata.category(character) == "Cc"
                for character in atom
            )
        ):
            raise ValueError(error)
        return atom

    owner = decode_atom(raw_owner)
    repo = decode_atom(raw_repo)
    if repo.lower().endswith(".git"):
        raise ValueError(error)
    return owner.lower(), repo.lower()


def get_releases(
    owner: str,
    repo: str,
    *,
    session: Any,
    timeout: int | tuple[int, int] = 10,
    api_budget: Optional[ApiRequestBudget] = None,
) -> list[dict[str, Any]]:
    """Fetch every GitHub release page using an injected HTTP transport.

    Any page failure or repeated ``next`` URL raises instead of exposing the
    accumulated prefix as though it were a complete repository history.
    """
    canonical_owner, canonical_repo = parse_github_repository_url(
        f"https://github.com/{owner}/{repo}"
    )
    next_url: Optional[str] = (
        f"https://api.github.com/repos/{canonical_owner}/{canonical_repo}"
        "/releases?per_page=100"
    )
    releases: list[dict[str, Any]] = []
    visited: set[str] = set()
    page_number = 0

    while next_url is not None:
        if next_url in visited:
            raise ReleasePaginationError(
                f"GitHub release pagination is cyclic for {canonical_owner}/{canonical_repo}"
            )
        visited.add(next_url)
        page_number += 1
        response = None
        try:
            if api_budget is None:
                response = session.get(next_url, timeout=timeout)
                response.raise_for_status()
            else:
                response = api_budget.get_response(
                    session,
                    next_url,
                    timeout=timeout,
                )
            page = response.json()
            if not isinstance(page, list) or not all(
                isinstance(release, dict) for release in page
            ):
                raise ReleasePaginationError(
                    f"GitHub release page {page_number} is not a list of objects"
                )
            releases.extend(page)

            links = getattr(response, "links", {})
            if not isinstance(links, Mapping):
                raise ReleasePaginationError(
                    f"GitHub release page {page_number} has invalid pagination links"
                )
            next_link = links.get("next")
            if next_link is None:
                next_url = None
            elif not isinstance(next_link, Mapping) or not isinstance(
                next_link.get("url"), str
            ):
                raise ReleasePaginationError(
                    f"GitHub release page {page_number} has an invalid next link"
                )
            else:
                next_url = next_link["url"]
                if not next_url or next_url in visited:
                    raise ReleasePaginationError(
                        "GitHub release pagination is cyclic for "
                        f"{canonical_owner}/{canonical_repo}"
                    )
        except (ApiDeadlineExceeded, ReleasePaginationError):
            raise
        except Exception as exc:
            raise ReleasePaginationError(
                "Failed to fetch GitHub releases for "
                f"{canonical_owner}/{canonical_repo} at page {page_number}"
            ) from exc
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if callable(close):
                    close()

    return releases


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
        or parsed.netloc.lower() != "github.com"
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

    return _parse_github_repository_atoms(*raw_parts, error=error)


def parse_github_repository_identity(identity: str) -> tuple[str, str]:
    """Return canonical atoms for a strict GitHub URL or ``owner/repo`` key."""
    error = f"Invalid GitHub repository identity: {identity!r}"
    if not isinstance(identity, str) or not identity or identity != identity.strip():
        raise ValueError(error)

    if identity.lower().startswith("https://"):
        try:
            return parse_github_repository_url(identity)
        except ValueError as exc:
            raise ValueError(error) from exc

    raw_parts = identity.split("/")
    if len(raw_parts) != 2 or not all(raw_parts):
        raise ValueError(error)
    try:
        return _parse_github_repository_atoms(*raw_parts, error=error)
    except ValueError as exc:
        raise ValueError(error) from exc


def canonical_repository_identity(identity: str) -> str:
    """Return a strict GitHub URL or shorthand as canonical ``owner/repo``."""
    return "/".join(parse_github_repository_identity(identity))


def parse_github_release_asset_url(url: str) -> tuple[str, str]:
    """Extract canonical ``(owner, repo)`` from a browser release-asset URL.

    This intentionally accepts only GitHub's
    ``/<owner>/<repo>/releases/download/<tag>/<asset>`` shape. It is separate
    from :func:`parse_github_repository_url` so repository configuration never
    starts accepting artifact paths by accident.
    """
    error = f"Invalid GitHub release asset URL: {url!r}"
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
        or parsed.netloc.lower() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
    ):
        raise ValueError(error)

    raw_parts = parsed.path[1:].split("/")
    if (
        len(raw_parts) != 6
        or not all(raw_parts)
        or raw_parts[2:4] != ["releases", "download"]
    ):
        raise ValueError(error)
    raw_owner, raw_repo, _, _, raw_tag, raw_asset = raw_parts
    if _ENCODED_PATH_SEPARATOR.search(raw_owner + "/" + raw_repo + "/" + raw_asset):
        raise ValueError(error)

    owner, repo = _parse_github_repository_atoms(raw_owner, raw_repo, error=error)

    tag = unquote(raw_tag)
    asset = unquote(raw_asset)
    if (
        not tag
        or "\\" in tag
        or not asset
        or asset in {".", ".."}
        or "/" in asset
        or "\\" in asset
    ):
        raise ValueError(error)
    return owner, repo


def canonicalize_github_release_asset_repository_url(url: str) -> str:
    """Return the canonical repository URL owning a strict release asset URL."""
    owner, repo = parse_github_release_asset_url(url)
    return f"https://github.com/{owner}/{repo}"


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
# Policy-driven bounded downloads
# ---------------------------------------------------------------------------

DEFAULT_RELEASE_MAX_BYTES = 67_108_864
DEFAULT_SOURCE_MAX_BYTES = 268_435_456
DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS = 60
DEFAULT_DOWNLOAD_CHUNK_SIZE_BYTES = 1_048_576


class DownloadLimitError(ValueError):
    """A response declared or streamed more bytes than policy permits."""


@dataclass(frozen=True)
class DownloadPolicy:
    """Validated limits and timeouts shared by every download call path."""

    release_max_bytes: int = DEFAULT_RELEASE_MAX_BYTES
    source_max_bytes: int = DEFAULT_SOURCE_MAX_BYTES
    connect_timeout_seconds: int = DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS
    read_timeout_seconds: int = DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS
    chunk_size_bytes: int = DEFAULT_DOWNLOAD_CHUNK_SIZE_BYTES

    def limit_for(self, kind: str) -> int:
        if kind == "release":
            return self.release_max_bytes
        if kind == "source":
            return self.source_max_bytes
        raise ValueError(f"Unsupported download kind: {kind!r}")


def _positive_download_integer(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"downloads.{name} must be a positive integer")
    return value


def validate_download_policy(
    policy: Optional[Mapping[str, Any] | DownloadPolicy] = None,
) -> DownloadPolicy:
    """Build a validated config from a policy root or ``downloads`` mapping."""
    if isinstance(policy, DownloadPolicy):
        values: Mapping[str, Any] = {
            "release_max_bytes": policy.release_max_bytes,
            "source_max_bytes": policy.source_max_bytes,
            "connect_timeout_seconds": policy.connect_timeout_seconds,
            "read_timeout_seconds": policy.read_timeout_seconds,
            "chunk_size_bytes": policy.chunk_size_bytes,
        }
    elif policy is None:
        values = {}
    elif not isinstance(policy, Mapping):
        raise ValueError("download policy must be a mapping")
    else:
        downloads = policy.get("downloads", policy)
        if not isinstance(downloads, Mapping):
            raise ValueError("policy downloads must be a mapping")
        values = downloads

    defaults = DownloadPolicy()
    return DownloadPolicy(
        release_max_bytes=_positive_download_integer(
            "release_max_bytes",
            values.get("release_max_bytes", defaults.release_max_bytes),
        ),
        source_max_bytes=_positive_download_integer(
            "source_max_bytes",
            values.get("source_max_bytes", defaults.source_max_bytes),
        ),
        connect_timeout_seconds=_positive_download_integer(
            "connect_timeout_seconds",
            values.get("connect_timeout_seconds", defaults.connect_timeout_seconds),
        ),
        read_timeout_seconds=_positive_download_integer(
            "read_timeout_seconds",
            values.get("read_timeout_seconds", defaults.read_timeout_seconds),
        ),
        chunk_size_bytes=_positive_download_integer(
            "chunk_size_bytes",
            values.get("chunk_size_bytes", defaults.chunk_size_bytes),
        ),
    )


@dataclass(frozen=True)
class DownloadResult:
    """Identity and size produced by one successful bounded stream."""

    path: Path
    sha256: str
    size_bytes: int


def bounded_stream_download(
    url: str,
    destination: str | Path,
    *,
    session: Any,
    kind: str,
    policy: Optional[Mapping[str, Any] | DownloadPolicy] = None,
) -> DownloadResult:
    """Atomically stream one response within policy while computing SHA-256."""
    settings = validate_download_policy(policy)
    max_bytes = settings.limit_for(kind)
    destination_path = Path(destination)
    response = session.get(
        url,
        stream=True,
        timeout=(
            settings.connect_timeout_seconds,
            settings.read_timeout_seconds,
        ),
    )
    temporary_path: Optional[Path] = None

    try:
        response.raise_for_status()
        raw_content_length = response.headers.get("Content-Length")
        try:
            declared_length = int(raw_content_length)
        except (TypeError, ValueError):
            declared_length = None
        if declared_length is not None and declared_length > max_bytes:
            raise DownloadLimitError(
                f"Content-Length {declared_length} exceeds {max_bytes} bytes"
            )

        destination_path.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        streamed_bytes = 0
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{destination_path.name}.",
            suffix=".part",
            dir=destination_path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            for chunk in response.iter_content(chunk_size=settings.chunk_size_bytes):
                if not chunk:
                    continue
                streamed_bytes += len(chunk)
                if streamed_bytes > max_bytes:
                    raise DownloadLimitError(
                        f"Streamed response exceeds {max_bytes} bytes"
                    )
                temporary_file.write(chunk)
                hasher.update(chunk)

        os.replace(temporary_path, destination_path)
        temporary_path = None
        return DownloadResult(
            path=destination_path,
            sha256=hasher.hexdigest(),
            size_bytes=streamed_bytes,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        close = getattr(response, "close", None)
        if callable(close):
            close()


# ---------------------------------------------------------------------------
# Pull-request audit-mode selection
# ---------------------------------------------------------------------------

_CHANGED_REPOSITORIES_PATHS = frozenset({PLUGIN_LIST_FILE, DISCOVERED_PLUGIN_LIST_FILE})
_FULL_AUDIT_PATHS = frozenset(
    {
        "audit_plugins.py",
        "generate_json.py",
        "check_for_updates.py",
        "plugin_release_utils.py",
        "security-policy.yml",
        "security-allowlist.yml",
        "security-verdicts.json",
        "semgrep-rules.yml",
        "pyproject.toml",
        "uv.lock",
        "scripts/orchestration/run-quality-gates",
        "scripts/install-security-scanners",
        ".github/workflows/plugin-security-audit.yml",
        ".github/workflows/scheduled-security-audit.yml",
    }
)


def _normalize_changed_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _requires_full_audit(path: str) -> bool:
    if path in _FULL_AUDIT_PATHS or path.startswith("tests/"):
        return True
    if path.startswith(".github/workflows/"):
        workflow_name = path.rsplit("/", 1)[-1].lower()
        if "audit" in workflow_name:
            return True
    return path.startswith("scripts/") and "quality-gate" in path


def select_audit_mode(changed_paths: Iterable[str] | str) -> str:
    """Return ``all``, ``changed``, or ``none`` for a side-effect-free diff."""
    paths = [changed_paths] if isinstance(changed_paths, str) else changed_paths
    plugin_list_changed = False
    for raw_path in paths:
        if not isinstance(raw_path, str):
            raise TypeError("changed paths must be strings")
        path = _normalize_changed_path(raw_path)
        if not path:
            continue
        if _requires_full_audit(path):
            return "all"
        if path in _CHANGED_REPOSITORIES_PATHS:
            plugin_list_changed = True
    return "changed" if plugin_list_changed else "none"


def main(argv: Optional[list[str]] = None) -> int:
    """Run the small executable interface used by audit workflows."""
    parser = argparse.ArgumentParser(description="Shared Decky release utilities")
    parser.add_argument(
        "--select-audit-mode",
        action="store_true",
        help="print all, changed, or none for the supplied changed paths",
    )
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)
    if not args.select_audit_mode:
        parser.error("--select-audit-mode is required")
    paths = args.paths if args.paths else sys.stdin.read().splitlines()
    print(select_audit_mode(paths))
    return 0


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


if __name__ == "__main__":
    raise SystemExit(main())
