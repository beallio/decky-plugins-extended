#!/usr/bin/env python3
"""Immutable and validated audit worklist preparation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

import plugin_release_utils

WORKLIST_SCHEMA_VERSION = "1"
WORKLIST_SELECTION_MODES = {"all", "changed", "repository", "none"}

_CANONICAL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")

_DOC_KEYS = {"schema_version", "fingerprint", "payload"}
_PAYLOAD_KEYS = {
    "selection_mode",
    "source_revision",
    "repositories",
    "shard_count",
    "items",
    "base_ref",
    "latest_only",
}
_REQUIRED_PAYLOAD_KEYS = {
    "selection_mode",
    "source_revision",
    "repositories",
    "shard_count",
    "items",
}
_ITEM_KEYS = {
    "repository",
    "release_id",
    "tag_name",
    "prerelease",
    "draft",
    "published_at",
    "created_at",
    "asset_id",
    "asset_name",
    "asset_url",
    "asset_digest",
    "resolved_source_commit_sha",
    "source_resolution_error",
    "repository_archived",
}


def _canonical_json_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_worklist_fingerprint(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_payload(payload)).hexdigest()


def _normalise_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _normalise_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid {field_name}: {value!r}")
    try:
        timestamp = value.replace("Z", "+00:00")
        datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value!r}") from exc
    return value


def _parse_asset_from_release(
    repository: str, release: Mapping[str, Any]
) -> Mapping[str, Any]:
    if not isinstance(release, Mapping):
        raise ValueError(f"Invalid release record for {repository}")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError(f"Invalid release asset list for {repository}")
    zip_assets = [
        candidate
        for candidate in assets
        if str(candidate.get("name", "")).lower().endswith(".zip")
    ]
    if len(zip_assets) != 1:
        raise ValueError(
            f"Each worklist item must have exactly one zip asset for {repository}"
        )
    return zip_assets[0]


def _source_resolution_entry(
    repository: str,
    tag_name: str,
    tag_to_commit: Mapping[str, str],
) -> tuple[Optional[str], Optional[str]]:
    commit_sha = tag_to_commit.get(tag_name)
    if commit_sha is None:
        return None, f"{repository}:{tag_name}:source-resolution-failed"
    if not _CANONICAL_GIT_SHA1.fullmatch(commit_sha):
        return None, f"{repository}:{tag_name}:source-resolution-invalid-commit"
    return commit_sha.lower(), None


def _normalise_worklist_item(
    repository: str,
    release: Mapping[str, Any],
    tag_to_commit: Mapping[str, str],
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    metadata_name = metadata.get("full_name")
    if not isinstance(metadata_name, str):
        raise ValueError(f"Missing repository metadata identity for {repository}")
    metadata_repository = plugin_release_utils.canonicalize_github_repository_url(
        f"https://github.com/{metadata_name}"
    )
    if metadata_repository != repository:
        raise ValueError(
            f"Repository metadata mismatch for {repository}: {metadata_name!r}"
        )

    item_release_id = _normalise_positive_int(release.get("id"), "release id")
    tag_name = _normalise_str(release.get("tag_name"), "tag name")

    published_at = release.get("published_at")
    if published_at is None:
        published_at = release.get("created_at")
    published_at = _normalise_timestamp(
        published_at, f"published_at for {repository}@{tag_name}"
    )
    created_at = _normalise_timestamp(
        release.get("created_at"), f"created_at for {repository}@{tag_name}"
    )

    asset = _parse_asset_from_release(repository, release)
    asset_id = _normalise_positive_int(asset.get("id"), "asset id")
    asset_name = _normalise_str(asset.get("name"), "asset name")
    asset_url = _normalise_str(
        asset.get("browser_download_url"),
        "release asset URL",
    )
    asset_owner_repo = (
        plugin_release_utils.canonicalize_github_release_asset_repository_url(asset_url)
    )
    if asset_owner_repo != repository:
        raise ValueError(
            f"Asset URL repository mismatch for {repository}@{item_release_id}:{tag_name}"
        )

    raw_digest = asset.get("digest")
    asset_digest = (
        plugin_release_utils.normalize_github_sha256_digest(raw_digest)
        if raw_digest is not None
        else None
    )
    if raw_digest is not None and asset_digest is None:
        raise ValueError(
            f"Invalid zip asset digest for {repository}@{item_release_id}:{tag_name}"
        )

    repository_archived = _normalise_bool(
        metadata.get("archived"), f"repository_archived for {repository}"
    )

    resolved_source_commit_sha, source_resolution_error = _source_resolution_entry(
        repository,
        tag_name,
        tag_to_commit,
    )

    return {
        "repository": repository,
        "release_id": item_release_id,
        "tag_name": tag_name,
        "prerelease": _normalise_bool(
            release.get("prerelease"), f"prerelease for {repository}@{tag_name}"
        ),
        "draft": _normalise_bool(
            release.get("draft"), f"draft for {repository}@{tag_name}"
        ),
        "published_at": published_at,
        "created_at": created_at,
        "asset_id": asset_id,
        "asset_name": asset_name,
        "asset_url": asset_url,
        "asset_digest": asset_digest,
        "resolved_source_commit_sha": resolved_source_commit_sha,
        "source_resolution_error": source_resolution_error,
        "repository_archived": repository_archived,
    }


def _ordered_item_identity_key(item: Mapping[str, Any]) -> tuple[str, int, int]:
    return (str(item["repository"]), int(item["release_id"]), int(item["asset_id"]))


def _item_order_key(item: Mapping[str, Any]) -> tuple:
    release = {
        "published_at": item["published_at"],
        "created_at": item["created_at"],
        "id": item["release_id"],
        "assets": [{"name": item["asset_name"], "id": item["asset_id"]}],
    }
    return plugin_release_utils.release_order_key(release)


def _validate_worklist_item(item: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise ValueError("Worklist item must be an object")

    provided = set(item.keys())
    if provided != _ITEM_KEYS:
        extras = ", ".join(sorted(provided - _ITEM_KEYS))
        missing = ", ".join(sorted(_ITEM_KEYS - provided))
        if extras and missing:
            raise ValueError(
                f"Unexpected worklist item keys: {extras}; missing worklist item keys: {missing}"
            )
        if extras:
            raise ValueError(f"Unexpected worklist item keys: {extras}")
        raise ValueError(f"Missing worklist item keys: {missing}")

    canonical_repo = plugin_release_utils.canonicalize_github_repository_url(
        _normalise_str(item["repository"], "repository")
    )
    if item["repository"] != canonical_repo:
        raise ValueError("Repository URL is not canonical")

    release_id = _normalise_positive_int(item["release_id"], "release id")
    asset_id = _normalise_positive_int(item["asset_id"], "asset id")
    tag_name = _normalise_str(item["tag_name"], "tag name")
    published_at = _normalise_timestamp(
        item["published_at"],
        f"published_at for {item['repository']}@{item.get('tag_name')}",
    )
    created_at = _normalise_timestamp(
        item["created_at"],
        f"created_at for {item['repository']}@{item.get('tag_name')}",
    )
    asset_name = _normalise_str(item["asset_name"], "asset name")
    asset_url = _normalise_str(item["asset_url"], "asset URL")
    asset_digest = item["asset_digest"]
    if asset_digest is not None:
        asset_digest = _normalise_str(asset_digest, "asset digest")
        if not _CANONICAL_SHA256.fullmatch(asset_digest):
            raise ValueError(f"Invalid asset digest for {canonical_repo}@{release_id}")

    prerelease = _normalise_bool(item["prerelease"], "prerelease")
    draft = _normalise_bool(item["draft"], "draft")
    repository_archived = _normalise_bool(
        item["repository_archived"], "repository_archived"
    )

    resolved_source_commit_sha = item["resolved_source_commit_sha"]
    source_resolution_error = item["source_resolution_error"]
    if (resolved_source_commit_sha is None and source_resolution_error is None) or (
        resolved_source_commit_sha is not None and source_resolution_error is not None
    ):
        raise ValueError(
            "Worklist item source resolution must include exactly one of "
            f"resolved_source_commit_sha or source_resolution_error for "
            f"{canonical_repo}@{release_id}"
        )

    if resolved_source_commit_sha is not None:
        resolved_source_commit_sha = _normalise_str(
            resolved_source_commit_sha, "resolved_source_commit_sha"
        )
        if not _CANONICAL_GIT_SHA1.fullmatch(resolved_source_commit_sha):
            raise ValueError(f"Invalid source commit for {canonical_repo}@{release_id}")

    if source_resolution_error is not None:
        if (
            not isinstance(source_resolution_error, str)
            or not source_resolution_error.strip()
        ):
            raise ValueError(
                f"Invalid source resolution error for {canonical_repo}@{release_id}"
            )

    asset_owner_repo = (
        plugin_release_utils.canonicalize_github_release_asset_repository_url(asset_url)
    )
    if asset_owner_repo != canonical_repo:
        raise ValueError(f"Asset repository mismatch for {canonical_repo}@{release_id}")

    return {
        "repository": canonical_repo,
        "release_id": release_id,
        "tag_name": tag_name,
        "prerelease": prerelease,
        "draft": draft,
        "published_at": published_at,
        "created_at": created_at,
        "asset_id": asset_id,
        "asset_name": asset_name,
        "asset_url": asset_url,
        "asset_digest": asset_digest,
        "resolved_source_commit_sha": (
            None
            if resolved_source_commit_sha is None
            else str(resolved_source_commit_sha).lower()
        ),
        "source_resolution_error": source_resolution_error,
        "repository_archived": repository_archived,
    }


def _normalise_tag_map(tag_map: Mapping[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for tag_name, commit_sha in tag_map.items():
        if not isinstance(tag_name, str) or not tag_name:
            raise ValueError("Invalid tag name in source-resolution map")
        if not isinstance(commit_sha, str):
            raise ValueError(f"Invalid commit for tag {tag_name!r}")
        commit_sha = commit_sha.lower()
        if not _CANONICAL_GIT_SHA1.fullmatch(commit_sha):
            raise ValueError(f"Invalid commit for tag {tag_name!r}")
        if tag_name in normalized:
            raise ValueError(
                f"Conflicting tag refs for {tag_name!r} in source-resolution map"
            )
        normalized[tag_name] = commit_sha
    return normalized


def parse_ls_remote_tags(output: str, repository: str) -> dict[str, str]:
    """Parse `git ls-remote --tags` output into `{tag: commit}`."""
    if not isinstance(output, str):
        raise ValueError(f"Malformed ls-remote output from {repository}")

    tag_commits: dict[str, str] = {}
    peeled_commits: dict[str, str] = {}
    for line_no, raw_line in enumerate(output.splitlines(), start=1):
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t")
        if len(parts) != 2:
            raise ValueError(
                f"Malformed ls-remote output from {repository}: {raw_line!r}"
            )
        object_id, ref = parts
        object_id = object_id.lower()
        if not _CANONICAL_GIT_SHA1.fullmatch(object_id):
            raise ValueError(
                f"Malformed ls-remote object id from {repository}: {object_id!r}"
            )
        if not ref.startswith("refs/tags/"):
            raise ValueError(f"Invalid ls-remote ref from {repository}: {ref!r}")
        tag_name = ref.removeprefix("refs/tags/")
        if not tag_name:
            raise ValueError(f"Invalid ls-remote ref from {repository}: {ref!r}")

        is_peeled = tag_name.endswith("^{}")
        if is_peeled:
            tag_name = tag_name[:-3]
            if not tag_name:
                raise ValueError(f"Invalid tagged ref from {repository}: {ref!r}")
            existing = peeled_commits.get(tag_name)
            if existing is not None:
                raise ValueError(
                    f"Conflicting tag refs for {tag_name!r} in {repository}"
                )
            peeled_commits[tag_name] = object_id.lower()
            continue

        if tag_name in tag_commits:
            raise ValueError(f"Conflicting tag refs for {tag_name!r} in {repository}")
        if tag_name in peeled_commits:
            raise ValueError(f"Conflicting tag refs for {tag_name!r} in {repository}")
        tag_commits[tag_name] = object_id

    for tag_name, commit_sha in peeled_commits.items():
        tag_commits[tag_name] = commit_sha
    return tag_commits


def resolve_repository_tags_via_ls_remote(
    owner: str,
    repo: str,
    timeout_seconds: int,
    *,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict[str, str]:
    if timeout_seconds <= 0:
        raise ValueError("api_deadline_seconds must be greater than zero")
    owner_repo = plugin_release_utils.parse_github_repository_identity(
        f"{owner}/{repo}"
    )
    repo_url = f"https://github.com/{owner_repo[0]}/{owner_repo[1]}"
    try:
        result = run(
            ["git", "ls-remote", "--tags", f"{repo_url}.git"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"git ls-remote timed out for {repo_url}") from exc
    except OSError as exc:
        raise RuntimeError(f"git ls-remote failed for {repo_url}: {exc}") from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"git ls-remote failed for {repo_url}: {getattr(result, 'stderr', '')}"
        )

    output = result.stdout
    if not isinstance(output, str):
        raise ValueError(f"Malformed ls-remote output from {repo_url}")

    return _normalise_tag_map(parse_ls_remote_tags(output, repo_url))


def _validate_worklist_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("worklist payload must be an object")

    provided = set(payload.keys())
    if not _REQUIRED_PAYLOAD_KEYS.issubset(provided):
        missing = ", ".join(sorted(_REQUIRED_PAYLOAD_KEYS - provided))
        raise ValueError(f"Missing worklist payload fields: {missing}")
    if provided - _PAYLOAD_KEYS:
        extras = ", ".join(sorted(provided - _PAYLOAD_KEYS))
        raise ValueError(f"Unexpected worklist payload fields: {extras}")

    selection_mode = _normalise_str(payload["selection_mode"], "selection_mode")
    if selection_mode not in WORKLIST_SELECTION_MODES:
        raise ValueError(f"Invalid selection mode: {selection_mode!r}")

    source_revision = _normalise_str(payload["source_revision"], "source_revision")
    if not _CANONICAL_GIT_SHA1.fullmatch(source_revision):
        raise ValueError("Invalid source_revision; expected 40-hex commit")

    shard_count = _normalise_positive_int(payload["shard_count"], "shard_count")

    repositories = payload.get("repositories")
    if not isinstance(repositories, list):
        raise ValueError("repositories must be a list")
    normalized_repositories: list[str] = []
    seen: set[str] = set()
    for repository in repositories:
        canonical = plugin_release_utils.canonicalize_github_repository_url(repository)
        if canonical in seen:
            raise ValueError(f"Duplicate repository in worklist: {canonical}")
        seen.add(canonical)
        normalized_repositories.append(canonical)
    if normalized_repositories != sorted(normalized_repositories):
        raise ValueError("Worklist repositories are not canonical order")

    latest_only = _normalise_bool(payload.get("latest_only", False), "latest_only")

    base_ref = payload.get("base_ref")
    if selection_mode == "repository":
        if len(repositories) != 1:
            raise ValueError("repository selection requires one repository URL")
    elif selection_mode == "all":
        if not repositories:
            raise ValueError("all selection requires at least one repository")
    elif selection_mode == "changed":
        base_ref = _normalise_str(base_ref, "base_ref")
        if not base_ref:
            raise ValueError("changed selection requires non-empty base_ref")
        if latest_only:
            raise ValueError("latest_only is only valid with repository mode")
    elif selection_mode == "none":
        if repositories:
            raise ValueError("none selection requires no repositories")
    elif base_ref is not None:
        raise ValueError("base_ref is only valid for changed mode")

    if latest_only and selection_mode != "repository":
        raise ValueError("latest_only is only valid with repository mode")

    items = payload.get("items")
    if not isinstance(items, list):
        raise ValueError("items must be a list")

    normalized_items: list[dict[str, Any]] = []
    selected_repositories = set(normalized_repositories)
    for item in items:
        normalized = _validate_worklist_item(item)
        if normalized["repository"] not in selected_repositories:
            raise ValueError(
                "worklist item repository is outside selected repositories"
            )
        normalized_items.append(normalized)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in normalized_items:
        grouped.setdefault(item["repository"], []).append(item)
    for repository in normalized_repositories:
        repo_items = grouped.get(repository, [])
        expected_order = sorted(repo_items, key=_item_order_key, reverse=True)
        if repo_items != expected_order:
            raise ValueError("Worklist items are not in deterministic order")

        grouped[repository] = expected_order
    if [
        item for repo in normalized_repositories for item in grouped[repo]
    ] != normalized_items:
        raise ValueError("Worklist items are not in deterministic repository order")

    for repository, repo_items in grouped.items():
        if any(item["repository"] != repository for item in repo_items):
            raise ValueError("Worklist items are not grouped by repository")

    if normalized_items:
        seen = set()
        for item in normalized_items:
            identity = (item["repository"], item["release_id"], item["asset_id"])
            if identity in seen:
                raise ValueError(f"Duplicate worklist identity: {identity!r}")
            seen.add(identity)

    return {
        "selection_mode": selection_mode,
        "source_revision": source_revision,
        "repositories": normalized_repositories,
        "shard_count": shard_count,
        "items": normalized_items,
        "base_ref": base_ref if selection_mode == "changed" else None,
        "latest_only": _normalise_bool(latest_only, "latest_only"),
    }


def _validate_worklist_document_payload(
    payload: Any, *, document_fingerprint: Optional[str] = None
) -> dict[str, Any]:
    validated_payload = _validate_worklist_payload(payload)
    if document_fingerprint is None:
        return validated_payload
    if not isinstance(document_fingerprint, str) or not _CANONICAL_SHA256.fullmatch(
        document_fingerprint
    ):
        raise ValueError("Invalid worklist fingerprint")
    expected = compute_worklist_fingerprint(validated_payload)
    if expected != document_fingerprint:
        raise ValueError("Worklist fingerprint does not match payload")
    return validated_payload


def _load_worklist_bytes(raw: Any) -> dict[str, Any]:
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Worklist document is not valid UTF-8 JSON") from exc
    try:
        payload_obj = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise ValueError("Worklist document is not valid JSON") from exc

    if not isinstance(payload_obj, Mapping):
        raise ValueError("Worklist document must be an object")
    provided = set(payload_obj.keys())
    if provided != _DOC_KEYS:
        missing = ", ".join(sorted(_DOC_KEYS - provided))
        extras = ", ".join(sorted(provided - _DOC_KEYS))
        if missing and extras:
            raise ValueError(
                f"Invalid worklist document keys. Extras: {extras}; missing: {missing}"
            )
        if missing:
            raise ValueError(f"Invalid worklist document keys. Missing: {missing}")
        raise ValueError(f"Invalid worklist document keys. Extras: {extras}")

    schema_version = payload_obj["schema_version"]
    if schema_version != WORKLIST_SCHEMA_VERSION:
        raise ValueError(f"Unsupported worklist schema version: {schema_version!r}")
    payload = payload_obj["payload"]
    fingerprint = payload_obj["fingerprint"]

    normalized_payload = _validate_worklist_document_payload(
        payload, document_fingerprint=fingerprint
    )

    return {
        "schema_version": schema_version,
        "fingerprint": fingerprint,
        "payload": normalized_payload,
    }


def load_worklist_document(path: str | os.PathLike[str]) -> dict[str, Any]:
    payload_path = Path(path)
    with payload_path.open("r", encoding="utf-8") as source:
        return _load_worklist_bytes(source.read())


def load_worklist_document_from_bytes(raw: bytes | str) -> dict[str, Any]:
    return _load_worklist_bytes(raw)


def _atomic_write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".audit-worklist-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def prepare_audit_worklist(
    output_path: str | os.PathLike[str],
    *,
    source_revision: str,
    selection_mode: str,
    repository_urls: list[str],
    shard_count: int,
    latest_only: bool = False,
    base_ref: Optional[str] = None,
    release_fetcher: Optional[Callable[[str, str], list[dict[str, Any]]]] = None,
    metadata_fetcher: Optional[Callable[[str, str], dict[str, Any]]] = None,
    tag_resolver: Optional[Callable[[str, str, int], dict[str, str]]] = None,
    api_deadline_seconds: int = 300,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(output_path, (str, os.PathLike)):
        raise ValueError("output_path must be a path")
    if not isinstance(source_revision, str):
        raise ValueError("source_revision must be a non-empty string")
    source_revision = source_revision.strip()
    if not source_revision or not _CANONICAL_GIT_SHA1.fullmatch(source_revision):
        raise ValueError("source_revision must be a 40-character hex commit")
    if selection_mode not in WORKLIST_SELECTION_MODES:
        raise ValueError(f"Invalid selection mode: {selection_mode!r}")
    if latest_only and selection_mode != "repository":
        raise ValueError("latest_only is only valid with repository mode")
    if selection_mode == "changed" and (
        not isinstance(base_ref, str) or not base_ref.strip()
    ):
        raise ValueError("changed selection requires --base-ref")
    shard_count = _normalise_positive_int(shard_count, "shard_count")
    if release_fetcher is None or metadata_fetcher is None or tag_resolver is None:
        raise ValueError(
            "release_fetcher, metadata_fetcher, and tag_resolver are required"
        )
    if api_deadline_seconds <= 0:
        raise ValueError("api_deadline_seconds must be greater than zero")

    original_selection_mode = selection_mode
    repositories = plugin_release_utils.sort_repository_urls(repository_urls)
    if selection_mode == "changed" and not repositories:
        selection_mode = "none"

    if selection_mode == "repository" and not repositories:
        raise ValueError("repository selection requires one repository URL")
    if selection_mode == "all" and not repositories:
        raise ValueError("all selection requires at least one repository")
    if selection_mode == "repository" and len(repositories) != 1:
        raise ValueError("repository selection requires exactly one repository URL")

    if selection_mode == "none" and repositories:
        raise ValueError("none selection requires no repositories")
    if original_selection_mode != "changed" and base_ref is not None:
        raise ValueError("base_ref is only valid for changed mode")
    if original_selection_mode == "all":
        base_ref = None

    items: list[dict[str, Any]] = []
    output_file = Path(output_path)
    try:
        if selection_mode != "none":
            for repository in repositories:
                owner, repo = plugin_release_utils.parse_github_repository_url(
                    repository
                )
                tag_map = _normalise_tag_map(
                    tag_resolver(owner, repo, api_deadline_seconds)
                )
                metadata = metadata_fetcher(owner, repo)
                if not isinstance(metadata, Mapping):
                    raise ValueError(f"Invalid repository metadata for {repository}")

                releases = release_fetcher(owner, repo)
                if not isinstance(releases, list):
                    raise ValueError(f"Invalid release list for {repository}")
                eligible = plugin_release_utils.ordered_eligible_releases(
                    releases, allow_prerelease=True
                )
                if latest_only:
                    eligible = eligible[:1]
                for release in eligible:
                    items.append(
                        _normalise_worklist_item(repository, release, tag_map, metadata)
                    )

        prepared_payload = {
            "selection_mode": selection_mode,
            "source_revision": source_revision,
            "repositories": repositories,
            "shard_count": shard_count,
            "items": items,
            "base_ref": base_ref if selection_mode == "changed" else None,
            "latest_only": latest_only,
        }
        payload = _validate_worklist_payload(prepared_payload)
        fingerprint = compute_worklist_fingerprint(payload)
        document = {
            "schema_version": WORKLIST_SCHEMA_VERSION,
            "fingerprint": fingerprint,
            "payload": payload,
        }
        _atomic_write_json(
            output_file,
            json.dumps(document, sort_keys=True, indent=2) + "\n",
        )
        return fingerprint, document
    except Exception:
        if output_file.exists():
            output_file.unlink()
        raise
