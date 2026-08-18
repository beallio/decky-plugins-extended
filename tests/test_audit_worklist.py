import copy
import hashlib
import json
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

import audit_plugins as ap
import audit_worklist as worklist

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REVISION = "a" * 40


def _release(
    tag,
    release_id,
    asset_id,
    published_at=None,
    *,
    prerelease=False,
    draft=False,
    zip_count=1,
    repository_url: str = "https://example.invalid",
):
    return {
        "id": release_id,
        "tag_name": tag,
        "published_at": published_at,
        "created_at": "2026-01-01T00:00:00Z",
        "prerelease": prerelease,
        "draft": draft,
        "assets": [
            {
                "id": asset_id + offset,
                "name": f"plugin-{offset}.zip",
                "browser_download_url": (
                    f"{repository_url}/{tag}-{offset}.zip"
                    if repository_url == "https://example.invalid"
                    else f"{repository_url}/releases/download/{tag}/plugin-{offset}.zip"
                ),
            }
            for offset in range(zip_count)
        ],
    }


def _zip_bytes() -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "plugin/plugin.json",
            json.dumps({"name": "Plugin", "flags": []}),
        )
        archive.writestr("plugin/main.py", "print('clean')\n")
    return buffer.getvalue()


def _with_digest(release: dict, value: str) -> dict:
    release = json.loads(json.dumps(release))
    release["assets"][0]["digest"] = value
    return release


def _with_prefixed_digest(release: dict, value: str) -> dict:
    release = json.loads(json.dumps(release))
    release["assets"][0]["digest"] = f"sha256:{value}"
    return release


def _with_asset_urls(release: dict, repository: str) -> dict:
    release = json.loads(json.dumps(release))
    tag = release.get("tag_name", "")
    for asset in release["assets"]:
        asset["browser_download_url"] = (
            f"{repository}/releases/download/{tag}/{asset['name']}"
        )
    return release


def _release_metadata(
    owner: str, repo: str, archived: bool = False
) -> dict[str, object]:
    return {"full_name": f"{owner}/{repo}", "archived": archived}


def test_worklist_prepare_and_load_roundtrip_is_stable(tmp_path):
    def release_fetcher(owner: str, repo: str) -> list[dict]:
        if (owner, repo) == ("owner", "a"):
            return [
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v2",
                            2,
                            20,
                            "2026-02-01T00:00:00Z",
                            repository_url="https://github.com/owner/a",
                        ),
                        "https://github.com/owner/a",
                    ),
                    "b" * 64,
                ),
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            "2026-01-01T00:00:00Z",
                            repository_url="https://github.com/owner/a",
                        ),
                        "https://github.com/owner/a",
                    ),
                    "a" * 64,
                ),
            ]
        return [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v3",
                        3,
                        30,
                        "2026-03-01T00:00:00Z",
                        repository_url="https://github.com/owner/b",
                    ),
                    "https://github.com/owner/b",
                ),
                "c" * 64,
            ),
        ]

    def metadata_fetcher(owner: str, repo: str) -> dict:
        return _release_metadata(owner, repo)

    def tag_resolver(owner: str, repo: str, *_args) -> dict:
        return {
            ("owner", "a"): {"v1": "a" * 40, "v2": "b" * 40},
            ("owner", "b"): {"v3": "c" * 40},
        }[(owner, repo)]

    output_one = tmp_path / "worklist-one.json"
    output_two = tmp_path / "worklist-two.json"

    first, _ = worklist.prepare_audit_worklist(
        output_one,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=[
            "https://github.com/owner/b",
            "https://github.com/owner/a",
        ],
        shard_count=14,
        latest_only=False,
        release_fetcher=release_fetcher,
        metadata_fetcher=metadata_fetcher,
        tag_resolver=tag_resolver,
        api_deadline_seconds=8,
    )

    second, _ = worklist.prepare_audit_worklist(
        output_two,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=[
            "https://github.com/owner/a",
            "https://github.com/owner/b",
        ],
        shard_count=14,
        latest_only=False,
        release_fetcher=release_fetcher,
        metadata_fetcher=metadata_fetcher,
        tag_resolver=tag_resolver,
        api_deadline_seconds=8,
    )

    assert first == second
    loaded_one = worklist.load_worklist_document(output_one)
    loaded_two = worklist.load_worklist_document(output_two)
    assert loaded_one["fingerprint"] == loaded_two["fingerprint"] == first
    assert loaded_one["payload"]["repositories"] == [
        "https://github.com/owner/a",
        "https://github.com/owner/b",
    ]
    assert len(loaded_one["payload"]["items"]) == 3


def test_worklist_load_rejects_tampered_fingerprint(tmp_path):
    output = tmp_path / "worklist.json"
    fp, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            ),
        ],
        metadata_fetcher=lambda *_args: _release_metadata("owner", "repo"),
        tag_resolver=lambda *_args, **_kwargs: {"v1": "e" * 40},
        api_deadline_seconds=7,
    )
    assert fp == worklist.load_worklist_document(output)["fingerprint"]

    raw = json.loads(output.read_text(encoding="utf-8"))
    raw["fingerprint"] = "0" * 64
    output.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint"):
        worklist.load_worklist_document(output)


def test_worklist_load_rejects_tampered_payload_mutations_and_tracks_fingerprint(
    tmp_path,
):
    output = tmp_path / "worklist.json"
    fp, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=[
            "https://github.com/owner/repo",
            "https://github.com/owner/other",
        ],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda owner, repo: {
            (
                "owner",
                "repo",
            ): [
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            "2026-01-01T00:00:00Z",
                            repository_url=f"https://github.com/{owner}/{repo}",
                        ),
                        "https://github.com/owner/repo",
                    ),
                    "a" * 64,
                )
            ],
            (
                "owner",
                "other",
            ): [
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v2",
                            2,
                            20,
                            "2026-02-01T00:00:00Z",
                            repository_url=f"https://github.com/{owner}/{repo}",
                        ),
                        "https://github.com/owner/other",
                    ),
                    "b" * 64,
                )
            ],
        }[(owner, repo)],
        metadata_fetcher=lambda owner, repo: {
            "full_name": f"{owner}/{repo}",
            "archived": False,
        },
        tag_resolver=lambda *_args, **_kwargs: {
            "v1": "a" * 40,
            "v2": "b" * 40,
        },
        api_deadline_seconds=7,
    )
    base = json.loads(output.read_text(encoding="utf-8"))
    deltas = [
        (
            "metadata.source_revision",
            lambda doc: doc["payload"].update(source_revision="f" * 40),
        ),
        ("metadata.shard_count", lambda doc: doc["payload"].update(shard_count=15)),
        (
            "item.release_id",
            lambda doc: doc["payload"]["items"][0].update(release_id=10),
        ),
        (
            "item.tag_name",
            lambda doc: doc["payload"]["items"][1].update(tag_name="v2-mod"),
        ),
    ]
    for _label, mutate in deltas:
        mutated = copy.deepcopy(base)
        mutate(mutated)
        path = tmp_path / f"mutated-{_label.replace('.', '-')}.json"
        path.write_text(json.dumps(mutated), encoding="utf-8")
        with pytest.raises(ValueError, match="fingerprint"):
            worklist.load_worklist_document(path)

    canonical = worklist._load_worklist_bytes(json.dumps(base))
    mutated_payload = canonical["payload"]
    mutated_payload = copy.deepcopy(mutated_payload)
    mutated_payload["source_revision"] = "f" * 40
    mutated_payload["items"][0]["release_id"] = 10
    recomputed = worklist.compute_worklist_fingerprint(mutated_payload)
    assert recomputed != fp


def test_worklist_load_rejects_tampered_non_canonical_payload_fields(tmp_path):
    output = tmp_path / "noncanonical.json"
    _, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=[
            "https://github.com/owner/repo",
        ],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        "2026-01-01T00:00:00Z",
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            )
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
        api_deadline_seconds=7,
    )
    base = json.loads(output.read_text(encoding="utf-8"))

    bad_payload_mutations = [
        (
            "draft",
            lambda doc: doc["payload"]["items"][0].update(draft=True),
            "Worklist item drafts are ineligible",
        ),
        (
            "asset_name",
            lambda doc: doc["payload"]["items"][0].update(asset_name="plugin.txt"),
            "Invalid asset name",
        ),
        (
            "created_at",
            lambda doc: doc["payload"]["items"][0].update(
                created_at="2026-01-01 00:00:00Z"
            ),
            "Invalid created_at",
        ),
        (
            "asset_digest_uppercase",
            lambda doc: doc["payload"]["items"][0].update(asset_digest="A" * 64),
            "Invalid asset digest",
        ),
        (
            "asset_digest_prefixed",
            lambda doc: doc["payload"]["items"][0].update(
                asset_digest=f"sha256:{'e' * 64}"
            ),
            "Invalid asset digest",
        ),
        (
            "source_resolution_commit_uppercase",
            lambda doc: doc["payload"]["items"][0].update(
                resolved_source_commit_sha="A" * 40,
                source_resolution_error=None,
            ),
            "Invalid source commit",
        ),
        (
            "source_resolution_error_unknown",
            lambda doc: doc["payload"]["items"][0].update(
                resolved_source_commit_sha=None,
                source_resolution_error="https://github.com/owner/repo:v1:??",
            ),
            "Invalid source resolution error",
        ),
        (
            "source_resolution_error_whitespace",
            lambda doc: doc["payload"]["items"][0].update(
                resolved_source_commit_sha=None,
                source_resolution_error="   ",
            ),
            "Invalid source_resolution_error",
        ),
    ]

    for _label, mutate, expected in bad_payload_mutations:
        mutated = copy.deepcopy(base)
        mutate(mutated)
        mutated["fingerprint"] = worklist.compute_worklist_fingerprint(
            mutated["payload"]
        )
        path = tmp_path / f"noncanonical-{_label}.json"
        path.write_text(json.dumps(mutated), encoding="utf-8")
        with pytest.raises(ValueError, match=expected):
            worklist.load_worklist_document(path)


def test_worklist_prepare_rejects_invalid_source_revision_with_preexisting_target(
    tmp_path,
):
    output = tmp_path / "invalid-source-revision.json"
    output.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="source_revision"):
        worklist.prepare_audit_worklist(
            output,
            source_revision="not-a-sha",
            selection_mode="changed",
            repository_urls=[],
            shard_count=14,
            latest_only=False,
            base_ref="HEAD~1",
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {},
            ref_resolver=lambda *_args: "a" * 40,
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_worklist_prepare_rejects_invalid_shard_count_with_preexisting_target(tmp_path):
    output = tmp_path / "invalid-shard-count.json"
    output.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="shard_count"):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="changed",
            repository_urls=[],
            shard_count=0,
            latest_only=False,
            base_ref="HEAD~1",
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {},
            ref_resolver=lambda *_args: "a" * 40,
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_worklist_prepare_rejects_invalid_source_revision():
    with pytest.raises(ValueError, match="source_revision"):
        worklist.prepare_audit_worklist(
            Path("/tmp/ignored"),
            source_revision="not-a-sha",
            selection_mode="all",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {"full_name": "owner/repo"},
            tag_resolver=lambda *_args, **_kwargs: {},
            api_deadline_seconds=7,
        )


def test_worklist_prepare_rejects_uppercase_source_revision():
    with pytest.raises(ValueError, match="source_revision"):
        worklist.prepare_audit_worklist(
            Path("/tmp/ignored"),
            source_revision="A" * 40,
            selection_mode="all",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {"full_name": "owner/repo"},
            tag_resolver=lambda *_args, **_kwargs: {},
            api_deadline_seconds=7,
        )


def test_worklist_validation_rejects_malformed_fields(tmp_path):
    output = tmp_path / "worklist.json"
    _, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            ),
        ],
        metadata_fetcher=lambda *_args: _release_metadata("owner", "repo"),
        tag_resolver=lambda *_args, **_kwargs: {"v1": "e" * 40},
        api_deadline_seconds=7,
    )
    base = json.loads(output.read_text(encoding="utf-8"))

    missing_root = copy.deepcopy(base)
    missing_root.pop("fingerprint")
    with pytest.raises(ValueError, match="Invalid worklist document"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(missing_root).encode("utf-8")
        )

    extra_root = copy.deepcopy(base)
    extra_root["unexpected"] = True
    with pytest.raises(ValueError, match="Invalid worklist document"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(extra_root).encode("utf-8")
        )

    missing_payload_field = copy.deepcopy(base)
    missing_payload_field["payload"].pop("items")
    with pytest.raises(ValueError, match="Missing worklist payload"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(missing_payload_field).encode("utf-8")
        )

    bad_payload = copy.deepcopy(base)
    bad_payload["payload"]["unexpected"] = True
    with pytest.raises(ValueError, match="Unexpected worklist payload fields"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(bad_payload).encode("utf-8")
        )

    bad_item = copy.deepcopy(base)
    bad_item["payload"]["items"][0].pop("asset_url")
    with pytest.raises(ValueError, match="worklist item keys"):
        worklist.load_worklist_document_from_bytes(json.dumps(bad_item).encode("utf-8"))

    invalid_source_error = copy.deepcopy(base)
    invalid_source_error["payload"]["items"][0]["resolved_source_commit_sha"] = None
    invalid_source_error["payload"]["items"][0]["source_resolution_error"] = (
        "https://github.com/owner/repo:v1:unknown-error"
    )
    with pytest.raises(ValueError, match="Invalid source resolution error"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(invalid_source_error).encode("utf-8")
        )

    payload = base["payload"]
    mutated = copy.deepcopy(payload)
    mutated["source_revision"] = "A" * 40
    with pytest.raises(ValueError, match="Invalid source_revision"):
        worklist._validate_worklist_payload(mutated)


def test_worklist_validation_rejects_invalid_resolved_source_fields(tmp_path):
    output = tmp_path / "invalid-source-fields.json"
    _, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            )
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "e" * 40},
        api_deadline_seconds=7,
    )
    base = json.loads(output.read_text(encoding="utf-8"))

    invalid_uppercase_commit = copy.deepcopy(base)
    invalid_uppercase_commit["payload"]["items"][0]["resolved_source_commit_sha"] = (
        "A" * 40
    )
    invalid_uppercase_commit["fingerprint"] = worklist.compute_worklist_fingerprint(
        invalid_uppercase_commit["payload"]
    )
    with pytest.raises(ValueError, match="Invalid source commit"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(invalid_uppercase_commit).encode("utf-8")
        )

    invalid_source_error = copy.deepcopy(base)
    invalid_source_error["payload"]["items"][0]["resolved_source_commit_sha"] = None
    invalid_source_error["payload"]["items"][0]["source_resolution_error"] = (
        "https://github.com/owner/repo :v1:source-resolution-failed"
    )
    invalid_source_error["fingerprint"] = worklist.compute_worklist_fingerprint(
        invalid_source_error["payload"]
    )
    with pytest.raises(ValueError, match="Invalid source resolution error"):
        worklist.load_worklist_document_from_bytes(
            json.dumps(invalid_source_error).encode("utf-8")
        )


def test_worklist_rejects_duplicate_identities_and_non_deterministic_order(tmp_path):
    output = tmp_path / "worklist.json"
    _, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="all",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v2",
                        2,
                        20,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            ),
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "e" * 64,
            ),
        ],
        metadata_fetcher=lambda *_args: _release_metadata("owner", "repo"),
        tag_resolver=lambda *_args, **_kwargs: {"v2": "a" * 40, "v1": "b" * 40},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    duplicated = copy.deepcopy(loaded)
    duplicated["payload"]["items"].insert(
        1, copy.deepcopy(duplicated["payload"]["items"][0])
    )
    dup_file = tmp_path / "dup.json"
    dup_file.write_text(json.dumps(duplicated), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate worklist identity"):
        worklist.load_worklist_document_from_bytes(dup_file.read_bytes())

    out_of_order = copy.deepcopy(loaded)
    out_of_order["payload"]["items"] = list(reversed(out_of_order["payload"]["items"]))
    out_file = tmp_path / "order.json"
    out_file.write_text(json.dumps(out_of_order), encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic"):
        worklist.load_worklist_document_from_bytes(out_file.read_bytes())


def test_worklist_prepare_accepts_none_selection(tmp_path):
    output = tmp_path / "empty.json"
    fp, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="changed",
        repository_urls=[],
        shard_count=14,
        latest_only=False,
        base_ref="HEAD~1",
        release_fetcher=lambda *_args: [],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {},
        ref_resolver=lambda *_args: SOURCE_REVISION,
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert fp == loaded["fingerprint"]
    assert loaded["payload"]["selection_mode"] == "none"
    assert loaded["payload"]["repositories"] == []
    assert loaded["payload"]["items"] == []


def test_worklist_prepare_changed_empty_keeps_resolved_base_commit(tmp_path):
    output = tmp_path / "changed-empty.json"
    resolved_base_commit = "d" * 40
    fp, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="changed",
        repository_urls=[],
        shard_count=14,
        latest_only=False,
        base_ref="HEAD~1",
        release_fetcher=lambda *_args: [],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "e" * 40},
        ref_resolver=lambda *_args: resolved_base_commit,
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert fp == loaded["fingerprint"]
    assert loaded["payload"]["selection_mode"] == "none"
    assert loaded["payload"]["base_commit"] == resolved_base_commit
    assert loaded["payload"]["repositories"] == []
    assert loaded["payload"]["items"] == []


def test_worklist_prepare_rejects_changed_mode_without_eligible_release(tmp_path):
    output = tmp_path / "changed-no-eligible.json"
    with pytest.raises(ValueError, match="No eligible release found"):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="changed",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            base_ref="HEAD",
            release_fetcher=lambda *_args: [
                _release(
                    "v0",
                    1,
                    10,
                    "2026-01-01T00:00:00Z",
                    zip_count=0,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v0": "a" * 40},
            api_deadline_seconds=7,
            ref_resolver=lambda *_args: "a" * 40,
        )
    assert not output.exists()


def test_worklist_prepare_rejects_repository_mode_without_eligible_release(tmp_path):
    output = tmp_path / "repository-no-eligible.json"
    with pytest.raises(ValueError, match="No eligible release found"):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="repository",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _release(
                    "v0",
                    1,
                    10,
                    "2026-01-01T00:00:00Z",
                    zip_count=0,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v0": "a" * 40},
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_worklist_prepare_rejects_empty_all_selection(tmp_path):
    output = tmp_path / "all-empty.json"
    output.write_text("{}", encoding="utf-8")
    with pytest.raises(
        ValueError, match="all selection requires at least one repository"
    ):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="all",
            repository_urls=[],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {},
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_worklist_prepare_rejects_non_canonical_repository():
    with pytest.raises(ValueError, match="Repository URL is not canonical"):
        worklist.prepare_audit_worklist(
            Path("/tmp/noncanonical.json"),
            source_revision=SOURCE_REVISION,
            selection_mode="all",
            repository_urls=["https://github.com/Owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {},
            ref_resolver=lambda *_args: SOURCE_REVISION,
            api_deadline_seconds=7,
        )


def test_worklist_prepare_accepts_explicit_none_selection(tmp_path):
    output = tmp_path / "none.json"
    fp, _ = worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="none",
        repository_urls=[],
        shard_count=14,
        latest_only=False,
        base_ref=None,
        release_fetcher=lambda *_args: [],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert loaded["fingerprint"] == fp
    assert loaded["payload"]["selection_mode"] == "none"
    assert loaded["payload"]["repositories"] == []
    assert loaded["payload"]["items"] == []


def test_worklist_prepare_rejects_repository_mode_with_multiple_repos(tmp_path):
    with pytest.raises(
        ValueError, match="repository selection requires exactly one repository URL"
    ):
        worklist.prepare_audit_worklist(
            tmp_path / "too-many.json",
            source_revision=SOURCE_REVISION,
            selection_mode="repository",
            repository_urls=[
                "https://github.com/owner/repo",
                "https://github.com/owner/other",
            ],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {"full_name": "owner/repo"},
            tag_resolver=lambda *_args, **_kwargs: {},
            api_deadline_seconds=7,
        )


def test_worklist_prepare_rejects_changed_mode_without_base_ref(tmp_path):
    with pytest.raises(ValueError, match="changed selection requires --base-ref"):
        worklist.prepare_audit_worklist(
            tmp_path / "changed.json",
            source_revision=SOURCE_REVISION,
            selection_mode="changed",
            repository_urls=[],
            shard_count=14,
            latest_only=False,
            base_ref=None,
            release_fetcher=lambda *_args: [],
            metadata_fetcher=lambda *_args: {"full_name": "owner/repo"},
            tag_resolver=lambda *_args, **_kwargs: {},
            api_deadline_seconds=7,
        )


def test_worklist_prepare_rejects_metadata_identity_mismatch(tmp_path):
    with pytest.raises(ValueError, match="Repository metadata mismatch"):
        worklist.prepare_audit_worklist(
            tmp_path / "metadata.json",
            source_revision=SOURCE_REVISION,
            selection_mode="repository",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            repository_url="https://github.com/owner/repo",
                        ),
                        "https://github.com/owner/repo",
                    ),
                    "a" * 64,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/other",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
            api_deadline_seconds=7,
        )


def test_prepare_marks_unresolved_source_tag_as_error(tmp_path):
    output = tmp_path / "unresolved.json"
    worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="repository",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v9",
                        9,
                        90,
                        repository_url="https://github.com/owner/repo",
                    ),
                    "https://github.com/owner/repo",
                ),
                "d" * 64,
            ),
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v8": "e" * 40},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    item = loaded["payload"]["items"][0]
    assert item["resolved_source_commit_sha"] is None
    assert item["source_resolution_error"] is not None


def test_prepare_worklist_accepts_missing_asset_digest(tmp_path):
    output = tmp_path / "nodigest.json"
    worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="repository",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_asset_urls(
                _release(
                    "v1",
                    1,
                    10,
                    "2026-01-01T00:00:00Z",
                    repository_url="https://github.com/owner/repo",
                ),
                "https://github.com/owner/repo",
            )
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert loaded["payload"]["items"][0]["asset_digest"] is None


def test_prepare_worklist_rejects_prefixed_asset_digest(tmp_path):
    output = tmp_path / "prefixed-digest.json"
    with pytest.raises(ValueError, match="Invalid zip asset digest"):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="repository",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _with_prefixed_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            repository_url="https://github.com/owner/repo",
                        ),
                        "https://github.com/owner/repo",
                    ),
                    "d" * 64,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
            api_deadline_seconds=7,
        )


def test_resolve_base_ref_to_commit_success():
    expected = "a" * 40

    def run(cmd, *args, **kwargs):
        assert cmd == ["git", "rev-parse", "HEAD~1"]
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{expected}\n", stderr="")

    assert (
        worklist._resolve_base_ref_to_commit("HEAD~1", run=run, timeout_seconds=5)
        == expected
    )


def test_resolve_base_ref_to_commit_rejects_malformed_output():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="not-a-sha\n", stderr="")

    with pytest.raises(ValueError, match="Invalid base commit"):
        worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)


def test_resolve_base_ref_to_commit_rejects_uppercase_output():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{'A' * 40}\n", stderr="")

    with pytest.raises(ValueError, match="Invalid base commit"):
        worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)


def test_resolve_base_ref_to_commit_rejects_base_ref_with_whitespace():
    with pytest.raises(ValueError, match="base_ref must be a canonical git ref"):
        worklist._resolve_base_ref_to_commit(
            " HEAD~1",
            run=lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("run must not be called")
            ),
            timeout_seconds=5,
        )


def test_resolve_base_ref_to_commit_rejects_timeout():
    with pytest.raises(TimeoutError, match="timed out"):
        worklist._resolve_base_ref_to_commit(
            "HEAD~1",
            run=lambda *a, **k: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(["git", "rev-parse", "HEAD~1"], 1)
            ),
            timeout_seconds=5,
        )


def test_resolve_base_ref_to_commit_rejects_nonzero_exit():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="boom")

    with pytest.raises(RuntimeError, match="git rev-parse failed"):
        worklist._resolve_base_ref_to_commit("HEAD~1", run=run, timeout_seconds=5)


def test_prepare_worklist_rejects_non_eligible_repositories_with_no_items(tmp_path):
    output = tmp_path / "no-eligible.json"
    with pytest.raises(ValueError, match="No eligible release found"):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="all",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _release(
                    "v0",
                    1,
                    10,
                    "2026-01-01T00:00:00Z",
                    zip_count=0,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v0": "a" * 40},
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_resolve_tags_prefers_peeled_commit_regardless_of_order():
    raw = "\n".join(
        [
            f"{'b' * 40}\trefs/tags/v1",
            f"{'d' * 40}\trefs/tags/v2^{{}}",
            f"{'c' * 40}\trefs/tags/v2",
            f"{'e' * 40}\trefs/tags/v3^{{}}",
        ]
    )

    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")

    resolved = worklist.resolve_repository_tags_via_ls_remote(
        "owner",
        "repo",
        5,
        run=run,
    )
    assert resolved["v2"] == "d" * 40
    assert resolved["v3"] == "e" * 40


def test_resolve_tags_rejects_uppercase_object_id():
    raw = "\n".join([f"{'A' * 40}\trefs/tags/v1"])

    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")

    with pytest.raises(ValueError, match="Malformed ls-remote object id"):
        worklist.resolve_repository_tags_via_ls_remote("owner", "repo", 5, run=run)


def test_prepare_worklist_failure_leaves_no_partial_file(tmp_path):
    output = tmp_path / "partial.json"
    with pytest.raises(RuntimeError):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="all",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _with_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            repository_url="https://github.com/owner/repo",
                        ),
                        "https://github.com/owner/repo",
                    ),
                    "d" * 64,
                ),
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("ls-remote failed")
            ),
            api_deadline_seconds=7,
        )
    assert not output.exists()


def test_prepare_worklist_failure_removes_pre_existing_target(tmp_path):
    output = tmp_path / "partial.json"
    output.write_text("{}", encoding="utf-8")

    release_calls: list[tuple[str, str]] = []
    metadata_calls: list[tuple[str, str]] = []
    tag_calls: list[tuple[str, str]] = []

    def release_fetcher(owner: str, repo: str) -> list[dict[str, object]]:
        release_calls.append((owner, repo))
        if (owner, repo) == ("owner", "repo"):
            return "not-a-list"  # type: ignore[return-value]
        return [
            _with_digest(
                _with_asset_urls(
                    _release(
                        "v1",
                        1,
                        10,
                        repository_url="https://github.com/owner/other",
                    ),
                    "https://github.com/owner/other",
                ),
                "a" * 64,
            )
        ]

    def metadata_fetcher(owner: str, repo: str) -> dict[str, object]:
        metadata_calls.append((owner, repo))
        return {"full_name": f"{owner}/{repo}", "archived": False}

    def tag_resolver(owner: str, repo: str, *_args) -> dict[str, str]:
        tag_calls.append((owner, repo))
        return {"v1": "b" * 40}

    with pytest.raises(ValueError):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="all",
            repository_urls=[
                "https://github.com/owner/other",
                "https://github.com/owner/repo",
            ],
            shard_count=14,
            latest_only=False,
            release_fetcher=release_fetcher,
            metadata_fetcher=metadata_fetcher,
            tag_resolver=tag_resolver,
            api_deadline_seconds=7,
        )
    assert not output.exists()
    assert release_calls == [("owner", "other"), ("owner", "repo")]
    assert metadata_calls == [("owner", "other"), ("owner", "repo")]
    assert tag_calls == [("owner", "other"), ("owner", "repo")]


def test_resolve_tags_prefers_annotated_peeled_commits():
    lightweight = "b" * 40
    annotated = "c" * 40
    peeled = "d" * 40
    raw = "\n".join(
        [
            f"{lightweight}\trefs/tags/v1",
            f"{annotated}\trefs/tags/v2",
            f"{peeled}\trefs/tags/v2^{{}}",
            f"{lightweight}\trefs/tags/release/v3",
        ]
    )

    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")

    resolved = worklist.resolve_repository_tags_via_ls_remote(
        "owner",
        "repo",
        5,
        run=run,
    )
    assert resolved["v2"] == peeled
    assert resolved["release/v3"] == lightweight


def test_resolve_tags_rejects_malformed_output_and_duplicate_conflicts():
    def run_malformed(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="not-a-valid-line", stderr="")

    with pytest.raises(ValueError, match="Malformed ls-remote"):
        worklist.resolve_repository_tags_via_ls_remote(
            "owner", "repo", 5, run=run_malformed
        )

    raw = "\n".join(
        [
            f"{'a' * 40}\trefs/tags/v1",
            f"{'b' * 40}\trefs/tags/v1",
        ]
    )

    def run_duplicate(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")

    with pytest.raises(ValueError, match="Conflicting tag refs"):
        worklist.resolve_repository_tags_via_ls_remote(
            "owner", "repo", 5, run=run_duplicate
        )


def test_resolve_tags_rejects_duplicate_identical_refs():
    raw = "\n".join(
        [
            f"{'a' * 40}\trefs/tags/v1",
            f"{'a' * 40}\trefs/tags/v1",
        ]
    )

    def run_duplicate(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=raw, stderr="")

    with pytest.raises(ValueError, match="Conflicting tag refs"):
        worklist.resolve_repository_tags_via_ls_remote(
            "owner", "repo", 5, run=run_duplicate
        )


def test_resolve_tags_rejects_timeout_and_oserror():
    with pytest.raises(TimeoutError, match="timed out"):
        worklist.resolve_repository_tags_via_ls_remote(
            "owner",
            "repo",
            5,
            run=lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("", 1)),
        )

    with pytest.raises(RuntimeError, match="git ls-remote failed"):
        worklist.resolve_repository_tags_via_ls_remote(
            "owner",
            "repo",
            5,
            run=lambda *a, **k: (_ for _ in ()).throw(OSError("broken pipe")),
        )


def test_resolve_tags_rejects_nonzero_exit():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="boom")

    with pytest.raises(RuntimeError, match="git ls-remote failed"):
        worklist.resolve_repository_tags_via_ls_remote("owner", "repo", 5, run=run)


def test_resolve_tags_uses_expected_git_arguments():
    calls = []

    def run(cmd, *args, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    worklist.resolve_repository_tags_via_ls_remote("owner", "repo", 1, run=run)
    assert calls == [
        (
            ["git", "ls-remote", "--tags", "https://github.com/owner/repo.git"],
            {
                "capture_output": True,
                "text": True,
                "timeout": 1,
                "check": False,
            },
        )
    ]


def _write_shard_report(path: Path, report: ap.AuditReport) -> None:
    payload = {
        "schema_version": ap.AUDIT_SCHEMA_VERSION,
        "policy_version": ap.POLICY_VERSION,
        "reports": [ap._report_to_dict(report)],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_shard_delta(
    path: Path,
    delta: dict[str, dict[str, dict[str, object]]],
) -> None:
    path.write_text(
        json.dumps(delta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _completed_report(
    *,
    repository: str = "https://github.com/owner/repo",
    release: str = "v1",
    github_release_id: str = "1",
    asset_id: str = "10",
    artifact_sha256: str = "a" * 64,
    audit_timestamp: str = "2026-01-01T00:00:00Z",
    identity_status: str = "CURRENT",
) -> ap.AuditReport:
    return ap.AuditReport(
        audit_timestamp=audit_timestamp,
        repository=repository,
        release=release,
        release_id=f"{release}@{asset_id}",
        github_release_id=github_release_id,
        asset_id=asset_id,
        artifact_url=f"https://example.invalid/{release}.zip",
        artifact_sha256=artifact_sha256,
        identity_status=identity_status,
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="ctx-v1",
        final_classification="PASS",
        completion_status="completed",
    )


def _shard_verdict_delta(
    report: ap.AuditReport,
) -> dict[str, dict[str, dict[str, object]]]:
    return ap._verdict_delta_from_reports([report])


def _write_empty_shard_report(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": ap.AUDIT_SCHEMA_VERSION,
                "policy_version": ap.POLICY_VERSION,
                "reports": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_worklist_audits_every_eligible_release_in_deterministic_order():
    releases = {
        "owner/a": [
            _release("v1", 1, 10, "2026-01-01T00:00:00Z"),
            _release("v3", 3, 30, "2026-03-01T00:00:00Z", prerelease=True),
            _release("draft", 9, 90, "2026-09-01T00:00:00Z", draft=True),
            _release("none", 8, 80, "2026-08-01T00:00:00Z", zip_count=0),
            _release("multi", 7, 70, "2026-07-01T00:00:00Z", zip_count=2),
        ],
        "owner/b": [_release("v2", 2, 20, "2026-02-01T00:00:00Z")],
    }

    worklist, errors = ap.build_audit_worklist(
        ["https://github.com/owner/b", "https://github.com/owner/a"],
        release_fetcher=lambda owner, repo: releases[f"{owner}/{repo}"],
        metadata_fetcher=lambda owner, repo: {"full_name": f"{owner}/{repo}"},
    )

    assert errors == []
    assert [
        (item.repository, item.release["id"], item.release["assets"][0]["id"])
        for item in worklist
    ] == [
        ("https://github.com/owner/a", 3, 30),
        ("https://github.com/owner/a", 1, 10),
        ("https://github.com/owner/b", 2, 20),
    ]


def test_fourteen_shards_are_deterministic_disjoint_and_union_identical():
    items = [
        ap.AuditWorkItem(
            repository="https://github.com/owner/repo",
            release=_release(f"v{index}", index, index * 10),
            repository_metadata={},
        )
        for index in range(1, 33)
    ]

    shard_count = 14
    shards = [
        ap.select_audit_shard(items, shard_count, index) for index in range(shard_count)
    ]
    identities = [
        {(item.repository, item.release["id"]) for item in shard} for shard in shards
    ]

    assert set.union(*identities) == {
        (item.repository, item.release["id"]) for item in items
    }
    assert sum(len(identity) for identity in identities) == len(items)
    assert all(
        identities[left].isdisjoint(identities[right])
        for left in range(shard_count)
        for right in range(left + 1, shard_count)
    )
    for shard_index, shard in enumerate(shards):
        assert all(
            int.from_bytes(
                hashlib.sha256(f"owner/repo\0{item.release['id']}".encode()).digest(),
                "big",
            )
            % shard_count
            == shard_index
            for item in shard
        )


def test_latest_only_is_an_explicit_single_repository_worklist_mode():
    releases = [
        _release("v1", 1, 10, "2026-01-01T00:00:00Z"),
        _release("v2", 2, 20, "2026-02-01T00:00:00Z"),
    ]

    worklist, errors = ap.build_audit_worklist(
        ["https://github.com/owner/repo"],
        latest_only=True,
        release_fetcher=lambda *_args: releases,
        metadata_fetcher=lambda *_args: {},
    )

    assert errors == []
    assert [item.release["id"] for item in worklist] == [2]


def test_latest_only_is_rejected_outside_single_repository_mode():
    with pytest.raises(SystemExit):
        ap.main(["--all", "--latest-only"])


@pytest.mark.parametrize("count,index", ((0, 0), (2, -1), (2, 2)))
def test_invalid_shard_arguments_fail(count, index):
    with pytest.raises(ValueError):
        ap.select_audit_shard([], count, index)


def test_resume_requires_every_identity_field_and_completed_status():
    expected = {
        "repository": "https://github.com/owner/repo",
        "github_release_id": "1",
        "asset_id": "10",
        "artifact_sha256": "a" * 64,
        "resolved_tag_commit_sha": "commit",
        "audit_context_hash": "context",
        "completion_status": "completed",
    }

    assert ap.resume_identity_matches(expected, expected)
    for field in expected:
        mutated = dict(expected)
        mutated[field] = "different"
        assert not ap.resume_identity_matches(mutated, expected), field


def test_aggregation_rejects_duplicate_and_conflicting_release_keys(tmp_path):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_sha256="a" * 64,
        artifact_url="https://example.invalid/v1.zip",
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit",
        audit_context_hash="ctx",
        final_classification="PASS",
        completion_status="completed",
    )
    payload = {
        "schema_version": ap.AUDIT_SCHEMA_VERSION,
        "policy_version": ap.POLICY_VERSION,
        "reports": [ap._report_to_dict(report)],
    }
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(payload), encoding="utf-8")
    second.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate"):
        ap.aggregate_audit_reports([str(first), str(second)])


@pytest.mark.parametrize(
    "second_classification", ["PASS", "BLOCK"], ids=["duplicate", "conflicting"]
)
def test_verdict_delta_aggregation_rejects_repeated_canonical_keys(
    tmp_path, second_classification
):
    repository = "https://github.com/owner/repo"
    first_record = {
        "classification": "PASS",
        "blocking_rule_ids": [],
        "review_rule_ids": [],
        "warning_rule_ids": [],
        "artifact_sha256": "a" * 64,
        "audit_context_hash": "ctx",
        "audited_at": "2026-01-01T00:00:00Z",
    }
    second_record = {
        **first_record,
        "classification": second_classification,
        "blocking_rule_ids": (
            ["ARCHIVE_TRAVERSAL"] if second_classification == "BLOCK" else []
        ),
    }
    first = tmp_path / "first-delta.json"
    second = tmp_path / "second-delta.json"
    first.write_text(
        json.dumps({repository: {"v1@10": first_record}}), encoding="utf-8"
    )
    second.write_text(
        json.dumps({"https://github.com/OWNER/REPO/": {"v1@10": second_record}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate verdict key"):
        ap.aggregate_verdict_deltas([str(first), str(second)])


def test_aggregate_reports_reject_completed_report_missing_identity_fields(tmp_path):
    report = _completed_report()
    reports = {
        "schema_version": ap.AUDIT_SCHEMA_VERSION,
        "policy_version": ap.POLICY_VERSION,
        "reports": [ap._report_to_dict(report)],
    }
    path = tmp_path / "shard.json"

    for field in ("release_id", "artifact_sha256", "asset_id"):
        payload = json.loads(json.dumps(reports))
        payload["reports"][0].pop(field)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Incomplete completed report"):
            ap.aggregate_audit_reports([str(path)])


@pytest.mark.parametrize(
    "missing_field",
    ["classification", "artifact_sha256", "audit_context_hash", "audited_at"],
)
def test_aggregate_verdict_deltas_reject_incomplete_block_delta(
    tmp_path, missing_field
):
    record = {
        "classification": "BLOCK",
        "blocking_rule_ids": ["ARCHIVE_TRAVERSAL"],
        "review_rule_ids": [],
        "warning_rule_ids": [],
        "artifact_sha256": "a" * 64,
        "audit_context_hash": "ctx",
        "audited_at": "2026-01-01T00:00:00Z",
    }
    payload = {"https://github.com/owner/repo": {"v1@10": record}}
    path = tmp_path / "delta.json"

    for missing_field in (missing_field,):
        mutated = json.loads(json.dumps(payload))
        del mutated["https://github.com/owner/repo"]["v1@10"][missing_field]
        path.write_text(json.dumps(mutated) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid"):
            ap.aggregate_verdict_deltas([str(path)])


def test_aggregate_main_rejects_missing_or_extra_delta_entries(tmp_path):
    report = _completed_report()
    report_delta = _shard_verdict_delta(report)
    shard_report = tmp_path / "report-shard.json"
    shard_delta = tmp_path / "delta-shard.json"
    _write_shard_report(shard_report, report)

    empty_delta = tmp_path / "empty-delta.json"
    _write_shard_delta(empty_delta, {})

    # Missing delta entry.
    _write_shard_delta(shard_delta, {})
    code = ap.main(
        [
            "--aggregate-reports",
            str(shard_report),
            "--aggregate-verdict-deltas",
            str(shard_delta),
            "--output-dir",
            str(tmp_path / "missing-entry"),
        ]
    )
    assert code == 1

    # Extra delta entry.
    extra = json.loads(json.dumps(report_delta))
    repository = next(iter(extra))
    extra_record = next(iter(extra[repository].values()))
    extra[repository]["v2@20"] = {
        **extra_record,
        "classification": "PASS",
    }
    _write_shard_delta(shard_delta, extra)
    code = ap.main(
        [
            "--aggregate-reports",
            str(shard_report),
            "--aggregate-verdict-deltas",
            str(shard_delta),
            "--output-dir",
            str(tmp_path / "extra-entry"),
        ]
    )
    assert code == 1


def test_aggregate_main_rejects_mismatched_delta_entry_contents(tmp_path):
    report = _completed_report()
    report_delta = _shard_verdict_delta(report)
    report_shard = tmp_path / "report.json"
    delta_shard = tmp_path / "delta.json"
    _write_shard_report(report_shard, report)

    mutated = json.loads(json.dumps(report_delta))
    repository = next(iter(mutated))
    release_id = next(iter(mutated[repository]))
    mutated[repository][release_id]["classification"] = "MANUAL_REVIEW"
    _write_shard_delta(delta_shard, mutated)

    code = ap.main(
        [
            "--aggregate-reports",
            str(report_shard),
            "--aggregate-verdict-deltas",
            str(delta_shard),
            "--output-dir",
            str(tmp_path / "mismatched"),
        ]
    )
    assert code == 1


def test_aggregate_main_rejects_report_delta_splice_across_shards(tmp_path):
    alpha = _completed_report(
        repository="https://github.com/owner/alpha", release="v1", asset_id="10"
    )
    beta = _completed_report(
        repository="https://github.com/owner/beta", release="v2", asset_id="20"
    )
    alpha_shard = tmp_path / "alpha-report.json"
    beta_shard = tmp_path / "beta-report.json"
    alpha_delta = tmp_path / "alpha-delta.json"
    beta_delta = tmp_path / "beta-delta.json"
    _write_shard_report(alpha_shard, alpha)
    _write_shard_report(beta_shard, beta)
    _write_shard_delta(alpha_delta, _shard_verdict_delta(beta))
    _write_shard_delta(beta_delta, _shard_verdict_delta(alpha))

    code = ap.main(
        [
            "--aggregate-reports",
            str(alpha_shard),
            str(beta_shard),
            "--aggregate-verdict-deltas",
            str(alpha_delta),
            str(beta_delta),
            "--output-dir",
            str(tmp_path / "splice"),
        ]
    )
    assert code == 1


@pytest.mark.parametrize("identity_status", ("STALE_HASH", "UNKNOWN"))
def test_aggregate_main_rejects_non_current_completed_report_identity_status(
    tmp_path, identity_status
):
    report = _completed_report(identity_status=identity_status)
    shard_report = tmp_path / "shard-report.json"
    shard_delta = tmp_path / "shard-delta.json"
    _write_shard_report(shard_report, report)
    _write_shard_delta(shard_delta, _shard_verdict_delta(report))

    code = ap.main(
        [
            "--aggregate-reports",
            str(shard_report),
            "--aggregate-verdict-deltas",
            str(shard_delta),
            "--output-dir",
            str(tmp_path / "aggregate"),
        ]
    )
    assert code == 1


def test_aggregate_main_rejects_missing_shard_delta_argument(tmp_path):
    report = _completed_report()
    shard_report = tmp_path / "shard-report.json"
    _write_shard_report(shard_report, report)

    code = ap.main(
        [
            "--aggregate-reports",
            str(shard_report),
            "--output-dir",
            str(tmp_path / "aggregate"),
        ]
    )
    assert code == 1


def test_aggregate_main_rejects_delta_shard_count_mismatch(tmp_path):
    alpha = _completed_report(repository="https://github.com/owner/alpha", release="v1")
    beta = _completed_report(repository="https://github.com/owner/beta", release="v2")
    alpha_shard = tmp_path / "alpha-report.json"
    beta_shard = tmp_path / "beta-report.json"
    alpha_delta = tmp_path / "alpha-delta.json"
    _write_shard_report(alpha_shard, alpha)
    _write_shard_report(beta_shard, beta)
    _write_shard_delta(alpha_delta, _shard_verdict_delta(alpha))

    code = ap.main(
        [
            "--aggregate-reports",
            str(alpha_shard),
            str(beta_shard),
            "--aggregate-verdict-deltas",
            str(alpha_delta),
            "--output-dir",
            str(tmp_path / "aggregate"),
        ]
    )
    assert code == 1


def test_aggregate_verdict_deltas_reject_unexpected_fields(tmp_path):
    report = _completed_report()
    report_delta = _shard_verdict_delta(report)
    repository = next(iter(report_delta))
    release_id = next(iter(report_delta[repository]))
    record = dict(report_delta[repository][release_id])
    record["unexpected"] = "value"

    payload = json.dumps({repository: {release_id: record}})
    path = tmp_path / "delta.json"
    path.write_text(payload + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unexpected"):
        ap.aggregate_verdict_deltas([str(path)])


def test_aggregate_main_accepts_clean_multi_shard_and_empty_shard_controls(tmp_path):
    alpha = _completed_report(
        repository="https://github.com/owner/alpha", release="v1", asset_id="10"
    )
    beta = _completed_report(
        repository="https://github.com/owner/beta", release="v2", asset_id="20"
    )
    alpha_report = tmp_path / "alpha-report.json"
    beta_report = tmp_path / "beta-report.json"
    empty_report = tmp_path / "empty-report.json"
    alpha_delta = tmp_path / "alpha-delta.json"
    beta_delta = tmp_path / "beta-delta.json"
    empty_delta = tmp_path / "empty-delta.json"
    _write_shard_report(alpha_report, alpha)
    _write_shard_report(beta_report, beta)
    _write_empty_shard_report(empty_report)
    _write_shard_delta(alpha_delta, _shard_verdict_delta(alpha))
    _write_shard_delta(beta_delta, _shard_verdict_delta(beta))
    _write_shard_delta(empty_delta, {})

    code = ap.main(
        [
            "--aggregate-reports",
            str(alpha_report),
            str(empty_report),
            str(beta_report),
            "--aggregate-verdict-deltas",
            str(alpha_delta),
            str(empty_delta),
            str(beta_delta),
            "--output-dir",
            str(tmp_path / "aggregate"),
        ]
    )
    assert code == 0

    payload = json.loads(
        (tmp_path / "aggregate" / "security-report.json").read_text(encoding="utf-8")
    )
    assert payload["report_count"] == 2
    aggregate_delta = json.loads(
        (tmp_path / "aggregate" / "security-verdict-delta.json").read_text(
            encoding="utf-8"
        )
    )
    assert aggregate_delta == {
        **_shard_verdict_delta(alpha),
        **_shard_verdict_delta(beta),
    }


def test_aggregate_main_rejects_incomplete_delta_without_missing_and_empty_controls(
    tmp_path,
):
    report = _completed_report()
    report_shard = tmp_path / "report.json"
    empty_shard = tmp_path / "empty.json"
    report_delta = tmp_path / "report-delta.json"
    empty_delta = tmp_path / "empty-delta.json"

    _write_shard_report(report_shard, report)
    _write_empty_shard_report(empty_shard)
    _write_shard_delta(report_delta, _shard_verdict_delta(report))
    _write_shard_delta(empty_delta, {})

    code = ap.main(
        [
            "--aggregate-reports",
            str(empty_shard),
            str(report_shard),
            "--aggregate-verdict-deltas",
            str(empty_delta),
            str(report_delta),
            "--output-dir",
            str(tmp_path / "aggregate"),
            "--verdict-delta",
            str(tmp_path / "aggregate-verdict.json"),
        ]
    )
    assert code == 0

    out_delta = json.loads(
        (tmp_path / "aggregate-verdict.json").read_text(encoding="utf-8")
    )
    assert out_delta == _shard_verdict_delta(report)

    payload = json.loads(
        (tmp_path / "aggregate" / "security-report.json").read_text(encoding="utf-8")
    )
    assert payload["report_count"] == 1


def test_shard_aggregation_restores_unsharded_deterministic_order(tmp_path):
    reports = [
        ap.AuditReport(
            repository="https://github.com/owner/b",
            release="v3",
            release_id="v3@30",
            github_release_id="3",
            asset_id="30",
            release_published_at="2026-03-01T00:00:00Z",
        ),
        ap.AuditReport(
            repository="https://github.com/owner/a",
            release="v1",
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            release_published_at="2026-01-01T00:00:00Z",
        ),
        ap.AuditReport(
            repository="https://github.com/owner/a",
            release="v2",
            release_id="v2@20",
            github_release_id="2",
            asset_id="20",
            release_published_at="2026-02-01T00:00:00Z",
        ),
    ]
    paths = []
    for index, report in enumerate(reports):
        path = tmp_path / f"shard-{index}.json"
        path.write_text(
            json.dumps({"reports": [ap._report_to_dict(report)]}), encoding="utf-8"
        )
        paths.append(str(path))

    aggregated = ap.aggregate_audit_reports(list(reversed(paths)))

    assert [report.release_id for report in aggregated] == ["v2@20", "v1@10", "v3@30"]


@pytest.mark.parametrize(
    ("classifications", "expected"),
    [
        (["PASS"], 0),
        (["MANUAL_REVIEW"], 3),
        (["BLOCK", "MANUAL_REVIEW"], 2),
        (["AUDIT_ERROR", "BLOCK", "MANUAL_REVIEW"], 4),
    ],
)
def test_release_outcome_exit_precedence(classifications, expected):
    reports = [
        ap.AuditReport(final_classification=classification)
        for classification in classifications
    ]

    assert ap._release_outcome_exit_code(reports, "enforce") == expected


def test_empty_repository_selection_cli_writes_complete_shard_outputs(tmp_path):
    output_dir = tmp_path / "reports"
    progress_path = tmp_path / "state" / "progress.json"
    verdict_delta_path = tmp_path / "deltas" / "shard-2.json"
    tracked_verdict_path = ROOT / "security-verdicts.json"
    tracked_verdict_bytes = tracked_verdict_path.read_bytes()

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "audit_plugins.py"),
            "--changed",
            "--base-ref",
            "HEAD",
            "--shard-count",
            "4",
            "--shard-index",
            "2",
            "--output-dir",
            str(output_dir),
            "--progress-manifest",
            str(progress_path),
            "--verdict-delta",
            str(verdict_delta_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    assert report == {
        "generated_at": "",
        "policy_version": ap.POLICY_VERSION,
        "report_count": 0,
        "reports": [],
        "schema_version": ap.AUDIT_SCHEMA_VERSION,
    }
    assert (output_dir / "security-report.md").read_text(encoding="utf-8") == (
        "# Decky Plugin Security Audit\n\n"
        "Generated: \n\n"
        "No plugin repository changes were detected.\n"
    )
    assert verdict_delta_path.read_text(encoding="utf-8") == "{}\n"
    assert not progress_path.exists()
    assert tracked_verdict_path.read_bytes() == tracked_verdict_bytes


def test_empty_repository_selection_delta_write_failure_is_run_global(
    monkeypatch, tmp_path
):
    output_dir = tmp_path / "reports"
    verdict_delta_path = tmp_path / "deltas" / "shard-0.json"
    original_atomic_write = ap._atomic_write_text

    def fail_delta_write(path, content):
        if Path(path) == verdict_delta_path:
            raise OSError("delta output denied")
        original_atomic_write(path, content)

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "get_changed_repos", lambda *_args: [])
    monkeypatch.setattr(ap, "_atomic_write_text", fail_delta_write)

    code = ap.main(
        [
            "--changed",
            "--output-dir",
            str(output_dir),
            "--verdict-delta",
            str(verdict_delta_path),
        ]
    )

    assert code == 1
    assert not verdict_delta_path.exists()


def test_nonzero_shard_pagination_error_is_run_global_without_outputs(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    output_dir = tmp_path / "reports"
    progress_path = tmp_path / "state" / "progress-shard-7.json"
    verdict_delta_path = tmp_path / "deltas" / "shard-7.json"

    def fail_later_page(*_args):
        raise ap.plugin_release_utils.ReleasePaginationError(
            "Failed to fetch releases page 2"
        )

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(ap, "get_repo_metadata", lambda *_args: {})
    monkeypatch.setattr(ap, "get_releases", fail_later_page)

    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--shard-count",
            "14",
            "--shard-index",
            "7",
            "--output-dir",
            str(output_dir),
            "--progress-manifest",
            str(progress_path),
            "--verdict-delta",
            str(verdict_delta_path),
        ]
    )

    assert code == 1
    assert not (output_dir / "security-report.json").exists()
    assert not (output_dir / "security-report.md").exists()
    assert not verdict_delta_path.exists()
    assert not progress_path.exists()


def test_mixed_release_run_checkpoints_success_and_publishes_error_before_exit_4(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    releases = [_release("v2", 2, 20), _release("v1", 1, 10)]
    worklist = [ap.AuditWorkItem(repository, release, {}) for release in releases]
    seen = []

    def fake_audit(_repository, release, **_kwargs):
        seen.append(release["id"])
        if release["id"] == 2:
            return ap.AuditReport(
                repository=repository,
                release="v2",
                release_id="v2@20",
                github_release_id="2",
                asset_id="20",
                artifact_sha256="a" * 64,
                final_classification="PASS",
                completion_status="completed",
            )
        return ap.AuditReport(
            repository=repository,
            release="v1",
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            artifact_sha256="b" * 64,
            final_classification="AUDIT_ERROR",
            completion_status="incomplete",
            error_scope="release",
            errors=["download failed"],
        )

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(ap, "audit_release", fake_audit)

    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(tmp_path / "reports"),
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )

    assert code == 4
    assert seen == [2, 1]
    payload = json.loads(
        (tmp_path / "reports/security-report.json").read_text(encoding="utf-8")
    )
    assert [report["final_classification"] for report in payload["reports"]] == [
        "PASS",
        "AUDIT_ERROR",
    ]
    delta = json.loads(
        (tmp_path / "reports/verdict-delta-shard-0.json").read_text(encoding="utf-8")
    )
    assert list(delta[repository]) == ["v2@20"]


def test_mixed_release_run_isolates_archive_oserror_and_preserves_prior_verdict(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    failed_release = _release("v2", 2, 20)
    successful_release = _release("v1", 1, 10)
    worklist = [
        ap.AuditWorkItem(repository, failed_release, {}),
        ap.AuditWorkItem(repository, successful_release, {}),
    ]
    zip_data = _zip_bytes()
    artifact_sha256 = hashlib.sha256(zip_data).hexdigest()
    prior_verdicts = {
        repository: {
            "v2@20": {
                "classification": "PASS",
                "blocking_rule_ids": [],
                "artifact_sha256": artifact_sha256,
                "audit_context_hash": "prior-context",
                "audited_at": "2026-08-01T00:00:00Z",
            }
        }
    }
    verdict_path = tmp_path / "security-verdicts.json"
    verdict_path.write_text(
        json.dumps(prior_verdicts, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    prior_verdict_bytes = verdict_path.read_bytes()
    downloads = []

    def download(url, destination, policy=None):
        del policy
        downloads.append(url)
        Path(destination).write_bytes(zip_data)
        return artifact_sha256

    original_infolist = zipfile.ZipFile.infolist
    inspection_calls = 0

    def fail_first_archive_read(archive):
        nonlocal inspection_calls
        inspection_calls += 1
        if inspection_calls == 1:
            raise OSError("unreadable archive")
        return original_infolist(archive)

    policy = ap._default_policy()
    for scanner in policy["scanners"].values():
        scanner["enabled"] = False
        scanner["required"] = False

    monkeypatch.setattr(ap, "VERDICTS_FILE", str(verdict_path))
    monkeypatch.setattr(ap, "load_policy", lambda *_args: policy)
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda _owner, _repo, ref: (f"commit-{ref}", f"tree-{ref}", None),
    )
    monkeypatch.setattr(ap, "get_repo_file_raw", lambda *_args: None)
    monkeypatch.setattr(ap, "_scanner_runtime_identities", lambda *_args: {})
    monkeypatch.setattr(
        ap, "compute_audit_context_hash", lambda *_args, **_kwargs: "current-context"
    )
    monkeypatch.setattr(ap, "download_zip", download)
    monkeypatch.setattr(zipfile.ZipFile, "infolist", fail_first_archive_read)

    output_dir = tmp_path / "reports"
    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(output_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )

    assert code == 4
    assert downloads == [
        "https://example.invalid/v2-0.zip",
        "https://example.invalid/v1-0.zip",
    ]
    assert verdict_path.read_bytes() == prior_verdict_bytes
    payload = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    failed_report, successful_report = payload["reports"]
    assert failed_report["final_classification"] == "AUDIT_ERROR"
    assert failed_report["completion_status"] == "incomplete"
    assert failed_report["error_scope"] == "release"
    assert failed_report["repository"] == repository
    assert failed_report["release"] == "v2"
    assert failed_report["release_id"] == "v2@20"
    assert failed_report["github_release_id"] == "2"
    assert failed_report["asset_id"] == "20"
    assert failed_report["artifact_url"] == "https://example.invalid/v2-0.zip"
    assert failed_report["artifact_sha256"] == artifact_sha256
    assert failed_report["resolved_tag_commit_sha"] == "commit-v2"
    assert failed_report["audit_context_hash"] == "current-context"
    assert failed_report["identity_status"] == "CURRENT"
    assert failed_report["errors"] == ["Archive inspection failed: unreadable archive"]
    assert successful_report["final_classification"] == "PASS"
    delta = json.loads(
        (output_dir / "verdict-delta-shard-0.json").read_text(encoding="utf-8")
    )
    assert set(delta[repository]) == {"v1@10"}
    progress = ap._load_progress_manifest(output_dir / "progress-shard-0.json")
    assert len(progress) == 2


def test_unexpected_audit_oserror_is_run_global_and_publishes_no_outputs(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    release = _release("v1", 1, 10)
    worklist = [ap.AuditWorkItem(repository, release, {})]

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("unexpected cache plumbing failure")
        ),
    )

    output_dir = tmp_path / "reports"
    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(output_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )

    assert code == 1
    assert not (output_dir / "security-report.json").exists()
    assert not (output_dir / "security-report.md").exists()
    assert not (output_dir / "verdict-delta-shard-0.json").exists()
    assert not (output_dir / "progress-shard-0.json").exists()


def test_checkpoint_integrity_error_aborts_without_publishable_outputs(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    release = _release("v1", 1, 10)
    worklist = [ap.AuditWorkItem(repository, release, {})]

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda *_args, **_kwargs: ap.AuditReport(
            repository=repository,
            release="v1",
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            artifact_sha256="b" * 64,
            final_classification="PASS",
            completion_status="completed",
        ),
    )
    monkeypatch.setattr(
        ap,
        "_write_progress_manifest",
        lambda *_args: (_ for _ in ()).throw(OSError("checkpoint denied")),
    )

    output_dir = tmp_path / "reports"
    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(output_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )

    assert code == 1
    assert not (output_dir / "security-report.json").exists()
    assert not (output_dir / "security-report.md").exists()
    assert not (output_dir / "verdict-delta-shard-0.json").exists()


def test_main_reruns_completed_progress_when_audit_context_mismatches(
    monkeypatch, tmp_path
):
    repository = "https://github.com/owner/repo"
    release = _release("v1", 1, 10)
    release["assets"][0]["digest"] = f"sha256:{'a' * 64}"
    worklist = [ap.AuditWorkItem(repository, release, {})]
    prior = ap.AuditReport(
        repository=repository,
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_sha256="a" * 64,
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="stale-context",
        final_classification="PASS",
        completion_status="completed",
    )
    progress_path = tmp_path / "progress.json"
    ap._write_progress_manifest(
        progress_path, {ap._report_identity_key(prior): ap._progress_record(prior)}
    )
    audited = []

    def fake_audit(repository_arg, release_arg, **_kwargs):
        audited.append((repository_arg, release_arg["id"]))
        return ap.AuditReport(
            repository=repository_arg,
            release=release_arg["tag_name"],
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            artifact_sha256="a" * 64,
            resolved_tag_commit_sha="commit-v1",
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda *_args: ("commit-v1", "tree-v1", None),
    )
    monkeypatch.setattr(ap, "_scanner_runtime_identities", lambda *_args: {})
    monkeypatch.setattr(
        ap, "compute_audit_context_hash", lambda *_args, **_kwargs: "current-context"
    )
    monkeypatch.setattr(ap, "audit_release", fake_audit)

    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(tmp_path / "reports"),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--progress-manifest",
            str(progress_path),
        ]
    )

    assert code == 0
    assert audited == [(repository, 1)]
    progress = ap._load_progress_manifest(progress_path)
    assert progress[ap._report_identity_key(prior)]["audit_context_hash"] == (
        "current-context"
    )


def _run_embedded_report_resume_case(monkeypatch, tmp_path, embedded_report):
    repository = "https://github.com/owner/repo"
    release = _release("v1", 1, 10)
    release["assets"][0]["digest"] = f"sha256:{'a' * 64}"
    worklist = [ap.AuditWorkItem(repository, release, {})]
    current_report = ap.AuditReport(
        repository=repository,
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_url="https://example.invalid/v1-0.zip",
        artifact_sha256="a" * 64,
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="current-context",
        plugin_name="checkpoint-report",
        final_classification="PASS",
        completion_status="completed",
    )
    progress_record = ap._progress_record(current_report)
    progress_record["report"] = embedded_report
    progress_path = tmp_path / "progress.json"
    ap._write_progress_manifest(
        progress_path, {ap._report_identity_key(current_report): progress_record}
    )
    audited = []

    def fake_audit(repository_arg, release_arg, **_kwargs):
        audited.append((repository_arg, release_arg["id"]))
        return ap.AuditReport(
            repository=repository_arg,
            release=release_arg["tag_name"],
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            artifact_url=release_arg["assets"][0]["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha="commit-v1",
            audit_context_hash="current-context",
            plugin_name="replacement-report",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "read_repo_urls", lambda *_args: [repository])
    monkeypatch.setattr(
        ap, "build_audit_worklist", lambda *_args, **_kwargs: (worklist, [])
    )
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda *_args: ("commit-v1", "tree-v1", None),
    )
    monkeypatch.setattr(ap, "_scanner_runtime_identities", lambda *_args: {})
    monkeypatch.setattr(
        ap, "compute_audit_context_hash", lambda *_args, **_kwargs: "current-context"
    )
    monkeypatch.setattr(ap, "audit_release", fake_audit)

    output_dir = tmp_path / "reports"
    code = ap.main(
        [
            "--all",
            "--plugins-file",
            str(tmp_path / "plugins.txt"),
            "--output-dir",
            str(output_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--progress-manifest",
            str(progress_path),
        ]
    )
    payload = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    return code, audited, payload["reports"][0]


_CURRENT_EMBEDDED_REPORT_IDENTITY = {
    "repository": "https://github.com/owner/repo",
    "release": "v1",
    "release_id": "v1@10",
    "github_release_id": "1",
    "asset_id": "10",
    "artifact_url": "https://example.invalid/v1-0.zip",
    "artifact_sha256": "a" * 64,
    "identity_status": "CURRENT",
    "resolved_tag_commit_sha": "commit-v1",
    "audit_context_hash": "current-context",
    "completion_status": "completed",
    "final_classification": "PASS",
}


def _embedded_report_identity(report):
    return {field: report[field] for field in _CURRENT_EMBEDDED_REPORT_IDENTITY}


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("repository", "https://github.com/attacker/spliced"),
        pytest.param(
            "repository",
            "https://github.com/OWNER/REPO",
            id="repository-case-only-mismatch",
        ),
        pytest.param(
            "repository",
            "https://github.com/owner/repo/",
            id="repository-trailing-slash-mismatch",
        ),
        ("release", "v2"),
        ("release_id", "v2@10"),
        ("github_release_id", "2"),
        ("asset_id", "20"),
        ("artifact_url", "https://example.invalid/spliced.zip"),
        ("artifact_sha256", "b" * 64),
        ("identity_status", "STALE_HASH"),
        ("resolved_tag_commit_sha", "spliced-commit"),
        ("audit_context_hash", "spliced-context"),
        ("completion_status", "incomplete"),
        ("final_classification", "AUDIT_ERROR"),
    ],
)
def test_main_rejects_mismatched_embedded_report_before_resume(
    monkeypatch, tmp_path, field, replacement
):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_url="https://example.invalid/v1-0.zip",
        artifact_sha256="a" * 64,
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="current-context",
        plugin_name="spliced-report",
        final_classification="PASS",
        completion_status="completed",
    )
    embedded_report = ap._report_to_dict(report)
    embedded_report[field] = replacement

    code, audited, emitted_report = _run_embedded_report_resume_case(
        monkeypatch, tmp_path, embedded_report
    )

    assert code == 0
    assert audited == [("https://github.com/owner/repo", 1)]
    assert emitted_report["plugin_name"] == "replacement-report"
    assert _embedded_report_identity(emitted_report) == (
        _CURRENT_EMBEDDED_REPORT_IDENTITY
    )


@pytest.mark.parametrize("malformation", ["missing", "invalid-nested-report"])
def test_main_reruns_malformed_or_incomplete_embedded_report(
    monkeypatch, tmp_path, malformation
):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_url="https://example.invalid/v1-0.zip",
        artifact_sha256="a" * 64,
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="current-context",
        plugin_name="spliced-report",
        final_classification="PASS",
        completion_status="completed",
    )
    embedded_report = ap._report_to_dict(report)
    if malformation == "missing":
        embedded_report.pop("artifact_url")
    else:
        embedded_report["findings"] = [{"unexpected": True}]

    code, audited, emitted_report = _run_embedded_report_resume_case(
        monkeypatch, tmp_path, embedded_report
    )

    assert code == 0
    assert audited == [("https://github.com/owner/repo", 1)]
    assert emitted_report["plugin_name"] == "replacement-report"
    assert _embedded_report_identity(emitted_report) == (
        _CURRENT_EMBEDDED_REPORT_IDENTITY
    )


def test_main_resumes_only_an_exact_publishable_embedded_report(monkeypatch, tmp_path):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_url="https://example.invalid/v1-0.zip",
        artifact_sha256="a" * 64,
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit-v1",
        audit_context_hash="current-context",
        plugin_name="checkpoint-report",
        final_classification="PASS",
        completion_status="completed",
    )

    code, audited, emitted_report = _run_embedded_report_resume_case(
        monkeypatch, tmp_path, ap._report_to_dict(report)
    )

    assert code == 0
    assert audited == []
    assert emitted_report["plugin_name"] == "checkpoint-report"
    assert _embedded_report_identity(emitted_report) == (
        _CURRENT_EMBEDDED_REPORT_IDENTITY
    )
