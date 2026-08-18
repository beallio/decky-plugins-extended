"""Immutable source snapshot materialization primitives for audit workers."""

from __future__ import annotations

import contextlib
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
_ALLOWED_REDIRECTS_PER_WORKER = range(0, 4)
_SOURCE_STREAM_CHUNK_SIZE = 1_048_576

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
    header = f"blob {len(payload)}\0".encode("ascii")
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


def _validate_max_redirects(max_redirects: int) -> int:
    if isinstance(max_redirects, bool) or type(max_redirects) is not int:
        raise SourceSnapshotError("max_redirects must be an int")
    if max_redirects not in _ALLOWED_REDIRECTS_PER_WORKER:
        raise SourceSnapshotError("max_redirects must be 0, 1, 2, or 3")
    return max_redirects


def _validate_and_normalize_archive_path(raw_name: str) -> str:
    if not isinstance(raw_name, str) or not raw_name:
        raise SourceSnapshotError("archive member path must be a non-empty string")
    if "\\" in raw_name:
        raise SourceSnapshotError(
            f"invalid archive member path {raw_name!r}: backslash"
        )
    if "\x00" in raw_name:
        raise SourceSnapshotError(
            f"invalid archive member path {raw_name!r}: null byte"
        )

    normalized = unicodedata.normalize("NFC", raw_name)
    if normalized.startswith("/"):
        raise SourceSnapshotError(f"invalid archive member path {raw_name!r}: absolute")

    parts = normalized.split("/")
    if any(part == "" for part in parts) or any(
        part == "." or part == ".." for part in parts
    ):
        raise SourceSnapshotError(
            f"unsafe archive member path {raw_name!r}: relative traversal"
        )
    if any(len(part) > 1 and part[0].isalpha() and part[1] == ":" for part in parts):
        raise SourceSnapshotError(
            f"unsafe archive member path {raw_name!r}: windows drive form"
        )

    return "/".join(parts)


def _archive_member_github_mode(member: tarfile.TarInfo, kind: str) -> str:
    if kind == "symlink":
        return "120000"
    if member.mode is None:
        return "100644"
    return "100755" if (member.mode & 0o111) else "100644"


def _extract_redirect_host(url: str, *, allowed_hosts: frozenset[str]) -> str:
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise RedirectPolicyError(f"invalid redirect URL: {url!r}") from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise RedirectPolicyError(f"invalid redirect URL port: {url!r}") from exc

    if parsed.scheme.lower() != "https":
        raise RedirectPolicyError(f"non-HTTPS URL rejected: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise RedirectPolicyError(f"url contains userinfo and was rejected: {url!r}")
    if port is not None:
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


@contextlib.contextmanager
def _disable_session_authorization_headers(session: Any) -> Any:
    headers = getattr(session, "headers", None)
    if not hasattr(headers, "pop") or not hasattr(headers, "__setitem__"):
        yield
        return

    removed: list[tuple[str, str]] = []
    for key in list(headers.keys()):  # type: ignore[attr-defined]
        if str(key).lower() == "authorization":
            removed.append((str(key), headers[key]))  # type: ignore[index]
            headers.pop(key)  # type: ignore[attr-defined]

    try:
        yield
    finally:
        for key, value in removed:
            headers[key] = value  # type: ignore[index]


def _codeload_session(
    session: Any,
    *,
    max_redirects: int,
) -> Any:
    validated_max_redirects = _validate_max_redirects(max_redirects)
    allowed_hosts = _DEFAULT_CODELOAD_HOSTS

    class _Session:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def _fetch(self, current_url: str, kwargs: Mapping[str, Any]) -> Any:
            _extract_redirect_host(current_url, allowed_hosts=allowed_hosts)
            with _disable_session_authorization_headers(self._inner):
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

                    if (
                        status // 100 == 3
                        and status not in _ALLOWED_SOURCE_REDIRECT_STATUSES
                    ):
                        response.close()
                        response = None
                        raise RedirectPolicyError(
                            f"unsupported redirect status {status} at {current_url!r}"
                        )

                    if status not in _ALLOWED_SOURCE_REDIRECT_STATUSES:
                        return response

                    if redirects >= validated_max_redirects:
                        response.close()
                        response = None
                        raise RedirectPolicyError(
                            f"too many redirects while requesting {url!r}"
                        )

                    location = getattr(response, "headers", {}).get("Location")
                    if not isinstance(location, str) or not location:
                        response.close()
                        response = None
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
    path_types: dict[str, str] = {}
    planned: list[tuple[tarfile.TarInfo, str, str, Optional[str]]] = []
    regular_file_count = 0
    file_count = 0
    total_uncompressed = 0

    def _check_ambiguous_paths(candidate: str, kind: str) -> None:
        for existing_path, existing_kind in path_types.items():
            if existing_path == candidate:
                raise SourceSnapshotError(
                    f"ambiguous archive path {candidate!r}: duplicate with {existing_kind}"
                )
            if existing_path.startswith(candidate + "/") or candidate.startswith(
                existing_path + "/"
            ):
                raise SourceSnapshotError(
                    f"ambiguous archive path {candidate!r} conflicts with {existing_path!r}"
                )

    try:
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
                if member.isdir():
                    _check_ambiguous_paths(normalized_key, "dir")
                    path_types[normalized_key] = "dir"
                    continue
                _check_ambiguous_paths(normalized_key, "file")
                path_types[normalized_key] = "file"

                if member.islnk():
                    raise SourceSnapshotError(f"hard link not allowed: {member.name!r}")
                if (
                    member.ischr()
                    or member.isblk()
                    or member.isfifo()
                    or member.type == getattr(tarfile, "SOCKTYPE", b"7")
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
                    size = len(link_target.encode("utf-8", errors="surrogateescape"))
                else:
                    if member.size < 0:
                        raise SourceSnapshotError(
                            f"invalid archive member size: {member.name!r}"
                        )
                    size = member.size
                    regular_file_count += 1

                if size > limits["max_single_file_bytes"]:
                    raise SourceSnapshotError(
                        f"archive member too large: {member.name!r}"
                    )
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
    except tarfile.TarError as exc:
        raise SourceSnapshotError("source archive is malformed or unreadable") from exc

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


def _extract_regular_member(
    *,
    archive_stream: Any,
    destination_parent: Path,
    member: tarfile.TarInfo,
    normalized_path: str,
    size: int,
) -> SourceInventoryEntry:
    target = PurePosixPath(normalized_path)
    if len(target.parts) < 2:
        raise SourceSnapshotError(f"malformed archive member path: {normalized_path!r}")
    rel_path = "/".join(target.parts[1:])

    output_path = destination_parent / rel_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha1()
    hasher.update(f"blob {size}\0".encode("ascii"))
    remaining = size
    bytes_read = 0

    def _read_chunk(chunk_size: int) -> bytes:
        if chunk_size <= 0:
            raise SourceSnapshotError(
                f"invalid source read size for {normalized_path!r}: {chunk_size}"
            )
        chunk = archive_stream.read(chunk_size)
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise SourceSnapshotError(f"invalid archive chunk for {normalized_path!r}")
        payload = bytes(chunk)
        if len(payload) > chunk_size:
            raise SourceSnapshotError(
                f"source archive chunk exceeded requested size for {normalized_path!r}"
            )
        return payload

    try:
        with output_path.open("wb") as output:
            while remaining > 0:
                to_read = min(_SOURCE_STREAM_CHUNK_SIZE, remaining)
                chunk = _read_chunk(to_read)
                payload = bytes(chunk)
                if len(payload) == 0:
                    raise SourceSnapshotError(
                        f"source archive size mismatch: {normalized_path!r}"
                    )
                output.write(payload)
                hasher.update(payload)
                remaining -= len(payload)
                bytes_read += len(payload)

            trailing = _read_chunk(1)
            if trailing:
                raise SourceSnapshotError(
                    f"source archive size mismatch: {normalized_path!r}"
                )

        mode = _archive_member_github_mode(member, kind="file")
        return SourceInventoryEntry(
            path=rel_path,
            kind="file",
            size_bytes=bytes_read,
            git_blob_sha1=hasher.hexdigest(),
            mode=mode,
        )
    finally:
        close = getattr(archive_stream, "close", None)
        if callable(close):
            close()


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
                payload = symlink_target.encode("utf-8", errors="surrogateescape")
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
            entry = _extract_regular_member(
                archive_stream=stream,
                destination_parent=destination,
                member=member,
                normalized_path=normalized,
                size=member.size,
            )
            entries.append(entry)

            if rel_path == "plugin.json":
                with (destination / rel_path).open("rb") as payload_file:
                    plugin_json = payload_file.read()
            if rel_path == "package.json":
                with (destination / rel_path).open("rb") as payload_file:
                    package_json = payload_file.read()

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
    download_session = _codeload_session(session, max_redirects=max_redirects)

    staging_root = Path(
        tempfile.mkdtemp(prefix="source-snapshot-", dir=str(destination_path.parent))
    )
    archive_path = staging_root / "source.tar.gz"
    extracted_path = staging_root / "source-root"

    staging_paths = (archive_path, extracted_path, staging_root)

    try:
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
        if destination_path.exists():
            raise SourceSnapshotError(f"destination already exists: {destination_path}")
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
    finally:
        for path in reversed(staging_paths):
            if isinstance(path, Path) and path.exists():
                if path == staging_root or path == extracted_path:
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
