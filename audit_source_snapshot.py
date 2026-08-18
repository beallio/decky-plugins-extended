"""Immutable source snapshot materialization primitives for audit workers."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Optional
from urllib.parse import urljoin, urlparse

import plugin_release_utils as pru

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_SOURCE_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_DEFAULT_CODELOAD_HOSTS = frozenset({"codeload.github.com"})
_DEFAULT_MAX_REDIRECTS = 3

_DEFAULT_ARCHIVE_LIMITS = {
    "max_files": 10_000,
    "max_uncompressed_bytes": 1_073_741_824,
    "max_single_file_bytes": 536_870_912,
    "max_path_depth": 30,
}


@dataclass(frozen=True)
class SourceInventoryEntry:
    path: str
    kind: str
    size_bytes: int
    git_blob_sha1: str
    mode: str
    symlink_target: Optional[str] = None


@dataclass(frozen=True)
class SourceSnapshot:
    repository: str
    commit_sha: str
    source_url: str
    archive_sha256: str
    archive_size_bytes: int
    source_root: str
    inventory: tuple[SourceInventoryEntry, ...]
    plugin_json: Optional[bytes]
    package_json: Optional[bytes]


class SourceSnapshotError(ValueError):
    """Raised when source snapshot preparation fails."""


class RedirectPolicyError(SourceSnapshotError):
    """Raised when codeload redirection violates transport allowlist policy."""


def _normalized_repository(repository: str) -> str:
    try:
        owner, repo = pru.parse_github_repository_url(repository)
    except ValueError as exc:
        raise SourceSnapshotError(
            f"Invalid GitHub repository URL: {repository!r}"
        ) from exc
    return f"https://github.com/{owner}/{repo}"


def _normalized_commit_sha(commit_sha: str) -> str:
    if not isinstance(commit_sha, str) or not _GIT_SHA_RE.fullmatch(commit_sha):
        raise SourceSnapshotError("commit SHA must be exactly 40 lowercase hex chars")
    return commit_sha


def _snapshot_source_url(repository: str, commit_sha: str) -> str:
    owner, repo = pru.parse_github_repository_url(repository)
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{commit_sha}"


def _git_blob_sha1(payload: bytes) -> str:
    header = f"blob {len(payload)}\\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def _validate_archive_limits(policy: Optional[Mapping[str, Any]]) -> dict[str, int]:
    if policy is None:
        return dict(_DEFAULT_ARCHIVE_LIMITS)
    if not isinstance(policy, Mapping):
        raise SourceSnapshotError("policy must be a mapping")

    archive = policy.get("archive", policy)
    if not isinstance(archive, Mapping):
        raise SourceSnapshotError("policy['archive'] must be a mapping")

    limits: dict[str, int] = {}
    for key, default in _DEFAULT_ARCHIVE_LIMITS.items():
        value = archive.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise SourceSnapshotError(
                f"policy archive limit {key!r} must be a positive integer"
            )
        limits[key] = value
    return limits


def _validate_and_normalize_archive_path(raw_name: str) -> str:
    if not isinstance(raw_name, str) or not raw_name:
        raise SourceSnapshotError("archive member path must be a non-empty string")
    if "\x00" in raw_name:
        raise SourceSnapshotError(
            f"invalid archive member path {raw_name!r}: null byte"
        )

    normalized = unicodedata.normalize("NFC", raw_name.replace("\\", "/"))
    if normalized.startswith("/"):
        raise SourceSnapshotError(f"invalid archive member path {raw_name!r}: absolute")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SourceSnapshotError(
            f"unsafe archive member path {raw_name!r}: relative traversal"
        )

    return "/".join(parts)


def _archive_member_github_mode(member: tarfile.TarInfo, kind: str) -> str:
    if kind == "symlink":
        return "120000"
    if member.mode is None:
        return "100644"
    return "100755" if (member.mode & 0o111) else "100644"


def _extract_redirect_host(url: str, *, allowed_hosts: frozenset[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise RedirectPolicyError(f"non-HTTPS URL rejected: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise RedirectPolicyError(f"url contains userinfo and was rejected: {url!r}")
    if parsed.port is not None:
        raise RedirectPolicyError(f"explicit port rejected: {url!r}")
    if not parsed.hostname:
        raise RedirectPolicyError(f"url without hostname rejected: {url!r}")
    host = parsed.hostname.lower()
    if host not in allowed_hosts:
        raise RedirectPolicyError(f"host not allowed: {host!r}")
    return host


def _authorize_for_url(
    url: str,
    headers: Mapping[str, str] | None,
    *,
    allowed_hosts: frozenset[str],
) -> dict[str, str]:
    prepared = {} if headers is None else dict(headers)
    for key in list(prepared):
        if key.lower() == "authorization":
            prepared.pop(key)

    _extract_redirect_host(url, allowed_hosts=allowed_hosts)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        prepared["Authorization"] = f"Bearer {token}"
    return prepared


def _codeload_session(
    session: Any,
    *,
    max_redirects: int,
) -> Any:
    if max_redirects < 0:
        raise SourceSnapshotError("max_redirects must be non-negative")
    allowed_hosts = _DEFAULT_CODELOAD_HOSTS

    class _Session:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def _fetch(self, current_url: str, kwargs: Mapping[str, Any]) -> Any:
            _extract_redirect_host(current_url, allowed_hosts=allowed_hosts)
            response = self._inner.get(
                current_url,
                allow_redirects=False,
                **dict(kwargs),
            )
            return response

        def _safe_headers(
            self, current_url: str, kwargs: Mapping[str, Any]
        ) -> dict[str, str]:
            headers = kwargs.get("headers")
            return _authorize_for_url(current_url, headers, allowed_hosts=allowed_hosts)

        def get(self, url: str, **kwargs: Any) -> Any:
            _extract_redirect_host(url, allowed_hosts=allowed_hosts)
            seen: set[str] = set()
            current_url = url
            redirects = 0

            while True:
                if current_url in seen:
                    raise RedirectPolicyError(
                        f"redirect loop detected: {current_url!r}"
                    )
                seen.add(current_url)

                response = None
                try:
                    response = self._fetch(
                        current_url,
                        {
                            **kwargs,
                            "headers": self._safe_headers(current_url, kwargs),
                        },
                    )
                    status = getattr(response, "status_code", 0)
                    if not isinstance(status, int):
                        raise RedirectPolicyError(
                            f"invalid response from {current_url!r}: missing status_code"
                        )
                    if status not in _ALLOWED_SOURCE_REDIRECT_STATUSES:
                        return response

                    if redirects >= max_redirects:
                        response.close()
                        raise RedirectPolicyError(
                            f"too many redirects while requesting {url!r}"
                        )

                    location = getattr(response, "headers", {}).get("Location")
                    if not isinstance(location, str) or not location:
                        response.close()
                        raise RedirectPolicyError(
                            f"missing or malformed redirect location at {current_url!r}"
                        )
                    next_url = urljoin(current_url, location)
                    _extract_redirect_host(next_url, allowed_hosts=allowed_hosts)
                    response.close()
                    current_url = next_url
                    redirects += 1
                except BaseException:
                    if response is not None:
                        close = getattr(response, "close", None)
                        if callable(close):
                            close()
                    raise

    return _Session(session)


def _preflight_source_archive(
    archive_path: Path,
    limits: Mapping[str, int],
) -> tuple[
    str,
    list[tuple[tarfile.TarInfo, str, str, Optional[str]]],
    int,
    int,
]:
    top_dirs: set[str] = set()
    seen_paths: set[str] = set()
    planned: list[tuple[tarfile.TarInfo, str, str, Optional[str]]] = []
    regular_file_count = 0
    file_count = 0
    total_uncompressed = 0

    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            normalized = _validate_and_normalize_archive_path(member.name)
            path = PurePosixPath(normalized)
            if len(path.parts) == 0:
                continue
            if len(path.parts) > limits["max_path_depth"]:
                raise SourceSnapshotError(f"archive path too deep: {member.name!r}")

            top_dirs.add(path.parts[0])
            normalized_key = path.as_posix()
            if normalized_key in seen_paths:
                raise SourceSnapshotError(f"duplicate archive member: {member.name!r}")
            seen_paths.add(normalized_key)

            if member.isdir():
                continue

            if member.islnk():
                raise SourceSnapshotError(f"hard link not allowed: {member.name!r}")
            if (
                member.ischr()
                or member.isblk()
                or member.isfifo()
                or member.type == getattr(tarfile, "SOCKTYPE", "7")
            ):
                raise SourceSnapshotError(
                    f"special archive member not allowed: {member.name!r}"
                )

            if not member.isfile() and not member.issym():
                raise SourceSnapshotError(
                    f"unsupported archive member: {member.name!r}"
                )

            kind = "symlink" if member.issym() else "file"
            if kind == "symlink":
                link_target = member.linkname
                if not isinstance(link_target, str):
                    raise SourceSnapshotError(
                        f"symlink target must be text for {member.name!r}"
                    )
                size = len(link_target.encode("utf-8", errors="replace"))
            else:
                if member.size < 0:
                    raise SourceSnapshotError(
                        f"invalid archive member size: {member.name!r}"
                    )
                size = member.size
                regular_file_count += 1

            if size > limits["max_single_file_bytes"]:
                raise SourceSnapshotError(f"archive member too large: {member.name!r}")
            file_count += 1
            total_uncompressed += size
            if file_count > limits["max_files"]:
                raise SourceSnapshotError("source archive exceeds max file count")
            if total_uncompressed > limits["max_uncompressed_bytes"]:
                raise SourceSnapshotError(
                    "source archive exceeds max uncompressed size"
                )

            target = link_target if kind == "symlink" else None
            planned.append((member, normalized, kind, target))

    if regular_file_count == 0:
        raise SourceSnapshotError("source archive contains no regular files")
    if len(top_dirs) != 1:
        raise SourceSnapshotError(
            "source archive must contain exactly one top-level directory"
        )

    top_dir = next(iter(top_dirs))
    if any(len(PurePosixPath(path).parts) == 1 for _, path, _, _ in planned):
        raise SourceSnapshotError(
            "archive members must all be inside a single top-level directory"
        )

    return top_dir, planned, file_count, total_uncompressed


def _extract_source_archive(
    archive_path: Path,
    destination: Path,
    planned: list[tuple[tarfile.TarInfo, str, str, Optional[str]]],
) -> tuple[tuple[SourceInventoryEntry, ...], Optional[bytes], Optional[bytes]]:
    plugin_json: Optional[bytes] = None
    package_json: Optional[bytes] = None
    entries: list[SourceInventoryEntry] = []

    with tarfile.open(archive_path, "r:*") as archive:
        for member, normalized, kind, symlink_target in planned:
            path = PurePosixPath(normalized)
            relative_parts = path.parts[1:]
            rel_path = "/".join(relative_parts)

            if kind == "symlink":
                payload = symlink_target.encode("utf-8", errors="replace")
                entries.append(
                    SourceInventoryEntry(
                        path=rel_path,
                        kind="symlink",
                        size_bytes=len(payload),
                        git_blob_sha1=_git_blob_sha1(payload),
                        mode="120000",
                        symlink_target=symlink_target,
                    )
                )
                continue

            stream = archive.extractfile(member)
            if stream is None:
                raise SourceSnapshotError(
                    f"unable to read archive member: {normalized!r}"
                )
            payload = stream.read()
            if len(payload) != member.size:
                raise SourceSnapshotError(
                    f"source archive size mismatch: {normalized!r}"
                )
            stream.close()

            out_path = destination / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(payload)
            mode = _archive_member_github_mode(member, kind="file")
            entries.append(
                SourceInventoryEntry(
                    path=rel_path,
                    kind="file",
                    size_bytes=len(payload),
                    git_blob_sha1=_git_blob_sha1(payload),
                    mode=mode,
                )
            )

            if rel_path == "plugin.json":
                plugin_json = payload
            if rel_path == "package.json":
                package_json = payload

    return (
        tuple(sorted(entries, key=lambda item: item.path)),
        plugin_json,
        package_json,
    )


def materialize_source_snapshot(
    repository: str,
    commit_sha: str,
    destination: str | Path,
    *,
    session: Any,
    policy: Optional[Mapping[str, Any]] = None,
    max_redirects: int = _DEFAULT_MAX_REDIRECTS,
) -> SourceSnapshot:
    canonical_repo = _normalized_repository(repository)
    canonical_commit = _normalized_commit_sha(commit_sha)
    source_url = _snapshot_source_url(canonical_repo, canonical_commit)

    destination_path = Path(destination)
    if destination_path.exists():
        raise SourceSnapshotError(f"destination already exists: {destination_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    archive_limits = _validate_archive_limits(policy)
    source_download_policy = policy

    staging_root = Path(
        tempfile.mkdtemp(prefix="source-snapshot-", dir=str(destination_path.parent))
    )
    archive_path = staging_root / "source.tar.gz"
    extracted_path = staging_root / "source-root"

    try:
        download_session = _codeload_session(session, max_redirects=max_redirects)
        download_result = pru.bounded_stream_download(
            source_url,
            archive_path,
            session=download_session,
            kind="source",
            policy=source_download_policy,
        )

        top_directory, planned, _file_count, _total_size = _preflight_source_archive(
            archive_path, archive_limits
        )
        if not top_directory:
            raise SourceSnapshotError("source archive is missing a top-level directory")

        extracted_path.mkdir(parents=True, exist_ok=True)
        inventory, plugin_json, package_json = _extract_source_archive(
            archive_path,
            extracted_path,
            [
                (
                    member,
                    path,
                    kind,
                    target if kind == "symlink" else None,
                )
                for member, path, kind, target in planned
            ],
        )

        # Promote as a completed snapshot in one atomic swap.
        os.replace(extracted_path, destination_path)

        return SourceSnapshot(
            repository=canonical_repo,
            commit_sha=canonical_commit,
            source_url=source_url,
            archive_sha256=download_result.sha256,
            archive_size_bytes=download_result.size_bytes,
            source_root=str(destination_path),
            inventory=inventory,
            plugin_json=plugin_json,
            package_json=package_json,
        )
    except BaseException:
        if destination_path.exists():
            shutil.rmtree(destination_path, ignore_errors=True)
        raise
    finally:
        if archive_path.exists():
            archive_path.unlink(missing_ok=True)
        if extracted_path.exists():
            shutil.rmtree(extracted_path, ignore_errors=True)
        shutil.rmtree(staging_root, ignore_errors=True)
