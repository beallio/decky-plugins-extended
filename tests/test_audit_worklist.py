import copy
import hashlib
import json
import subprocess
import sys
import tarfile
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
    release["assets"][0]["digest"] = f"sha256:{value}"
    return release


def _with_bare_digest(release: dict, value: str) -> dict:
    release = json.loads(json.dumps(release))
    release["assets"][0]["digest"] = value
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
    assert all(
        item["asset_digest"] == str(item["asset_digest"]).lower()
        for item in loaded_one["payload"]["items"]
    )
    assert all(
        item["asset_digest"] is not None for item in loaded_one["payload"]["items"]
    )
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


@pytest.mark.parametrize(
    ("release_id", "asset_id"),
    [
        ("01", "10"),
        ("1", "010"),
        ("1 ", "10"),
        (" 1", "10"),
        ("1", "01"),
        ("1", "\u0661"),
        ("-1", "10"),
        ("0", "10"),
        ("+1", "10"),
    ],
)
def test_worklist_identity_rejects_aliasing_and_alias_decimal_forms(
    release_id, asset_id
):
    with pytest.raises(ValueError, match="must be a positive decimal"):
        worklist.worklist_identity(
            {
                "repository": "https://github.com/owner/repo",
                "release_id": release_id,
                "asset_id": asset_id,
            }
        )


@pytest.mark.parametrize(
    ("release_id", "asset_id"),
    [
        (1, 10),
        (True, 10),
        (1.0, 10),
        ("1", 10.0),
        ("1", False),
        ("1", "１０"),
    ],
)
def test_normalise_worklist_identity_rejects_non_string_release_and_asset_ids(
    release_id, asset_id
):
    with pytest.raises(ValueError):
        worklist._normalise_worklist_identity(
            {
                "repository": "https://github.com/owner/repo",
                "release_id": release_id,
                "asset_id": asset_id,
            }
        )


def test_worklist_identity_adapts_integer_release_and_asset_ids():
    assert worklist.worklist_identity(
        {
            "repository": "https://github.com/owner/repo",
            "release_id": 1,
            "asset_id": 10,
        }
    ) == {
        "repository": "https://github.com/owner/repo",
        "github_release_id": "1",
        "asset_id": "10",
    }


@pytest.mark.parametrize(
    ("release_id", "asset_id"),
    [
        ("01", "１０"),
        ("１", "10"),
    ],
)
def test_worklist_identity_rejects_textual_aliases_of_same_value(release_id, asset_id):
    with pytest.raises(ValueError, match="must be a positive decimal"):
        worklist.worklist_identity(
            {
                "repository": "https://github.com/owner/repo",
                "release_id": release_id,
                "asset_id": asset_id,
            }
        )


def test_worklist_identity_rejects_non_canonical_repository_alias():
    with pytest.raises(ValueError, match="Repository URL is not canonical"):
        worklist.worklist_identity(
            {
                "repository": "https://github.com/OWNER/repo",
                "release_id": "1",
                "asset_id": "10",
            }
        )


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


def test_prepare_worklist_accepts_uppercase_zip_asset_name(tmp_path):
    output = tmp_path / "uppercase-zip-name.json"
    uppercase_release = _with_asset_urls(
        _release(
            "v1",
            1,
            10,
            "2026-01-01T00:00:00Z",
            repository_url="https://github.com/owner/repo",
        ),
        "https://github.com/owner/repo",
    )
    uppercase_release["assets"][0]["name"] = "plugin.ZIP"

    worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="repository",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_digest(
                uppercase_release,
                "d" * 64,
            )
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert loaded["payload"]["items"][0]["asset_name"] == "plugin.ZIP"


def test_prepare_worklist_normalizes_prefixed_asset_digest(tmp_path):
    output = tmp_path / "prefixed-digest.json"
    for raw_digest, expected in (
        (f"sha256:{'d' * 64}", "d" * 64),
        (f"sha256:{'D' * 64}", "d" * 64),
    ):
        worklist.prepare_audit_worklist(
            output,
            source_revision=SOURCE_REVISION,
            selection_mode="repository",
            repository_urls=["https://github.com/owner/repo"],
            shard_count=14,
            latest_only=False,
            release_fetcher=lambda *_args: [
                _with_bare_digest(
                    _with_asset_urls(
                        _release(
                            "v1",
                            1,
                            10,
                            repository_url="https://github.com/owner/repo",
                        ),
                        "https://github.com/owner/repo",
                    ),
                    raw_digest,
                )
            ],
            metadata_fetcher=lambda *_args: {
                "full_name": "owner/repo",
                "archived": False,
            },
            tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
            api_deadline_seconds=7,
        )
        loaded = worklist.load_worklist_document(output)
        assert loaded["payload"]["items"][0]["asset_digest"] == expected


def test_prepare_worklist_treats_malformed_asset_digest_as_missing(tmp_path):
    output = tmp_path / "malformed-digest.json"
    release = _release(
        "v1",
        1,
        10,
        "2026-01-01T00:00:00Z",
        repository_url="https://github.com/owner/repo",
    )
    release["assets"] = [
        {
            "id": 10,
            "name": "plugin.zip",
            "browser_download_url": "https://github.com/owner/repo/v1/plugin.zip",
            "digest": "sha256:not-a-valid-digest",
        }
    ]
    worklist.prepare_audit_worklist(
        output,
        source_revision=SOURCE_REVISION,
        selection_mode="repository",
        repository_urls=["https://github.com/owner/repo"],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda *_args: [
            _with_asset_urls(
                release,
                "https://github.com/owner/repo",
            )
        ],
        metadata_fetcher=lambda *_args: {"full_name": "owner/repo", "archived": False},
        tag_resolver=lambda *_args, **_kwargs: {"v1": "a" * 40},
        api_deadline_seconds=7,
    )
    loaded = worklist.load_worklist_document(output)
    assert loaded["payload"]["items"][0]["asset_digest"] is None


def test_resolve_base_ref_to_commit_success():
    expected = "a" * 40

    def run(cmd, *args, **kwargs):
        assert cmd == [
            "git",
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            "HEAD~1^{commit}",
        ]
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{expected}\n", stderr="")

    assert (
        worklist._resolve_base_ref_to_commit("HEAD~1", run=run, timeout_seconds=5)
        == expected
    )


def test_resolve_base_ref_to_commit_verifies_commit_objects_in_repo():
    def run(cmd, *args, **kwargs):
        return subprocess.run(cmd, cwd=ROOT, *args, **kwargs)

    expected = worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)
    direct = subprocess.check_output(
        [
            "git",
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            "HEAD^{commit}",
        ],
        cwd=ROOT,
        text=True,
    ).strip()
    assert expected == direct

    with pytest.raises(RuntimeError, match="git rev-parse failed"):
        worklist._resolve_base_ref_to_commit("HEAD^{tree}", run=run, timeout_seconds=5)
    with pytest.raises(RuntimeError, match="git rev-parse failed"):
        worklist._resolve_base_ref_to_commit(
            "HEAD:README.md", run=run, timeout_seconds=5
        )


def test_resolve_base_ref_to_commit_rejects_missing_output_newline():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="a" * 40, stderr="")

    with pytest.raises(ValueError, match="Invalid base commit"):
        worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)


def test_resolve_base_ref_to_commit_rejects_duplicate_output_lines():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout=f"{'a' * 40}\n{'b' * 40}\n", stderr=""
        )

    with pytest.raises(ValueError, match="Invalid base commit"):
        worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)


def test_resolve_base_ref_to_commit_rejects_output_with_whitespace():
    def run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout=f"{'a' * 39} {'a'}\n", stderr=""
        )

    with pytest.raises(ValueError, match="Invalid base commit"):
        worklist._resolve_base_ref_to_commit("HEAD", run=run, timeout_seconds=5)


def test_resolve_base_ref_to_commit_rejects_blob_ref():
    def run(cmd, *args, **kwargs):
        assert cmd == [
            "git",
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            "HEAD:README.md^{commit}",
        ]
        return subprocess.CompletedProcess(
            cmd, 2, stdout="", stderr="fatal: bad revision"
        )

    with pytest.raises(RuntimeError, match="git rev-parse failed"):
        worklist._resolve_base_ref_to_commit(
            "HEAD:README.md", run=run, timeout_seconds=5
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
        "worklist_fingerprint": "b" * 64,
    }

    assert ap.resume_identity_matches(expected, expected)
    for field in expected:
        mutated = dict(expected)
        mutated[field] = "different"
        assert not ap.resume_identity_matches(mutated, expected), field


def test_resume_identity_allows_v1_missing_fingerprint_but_mismatch_if_worklist_fingerprint_present():
    legacy_expected = {
        "repository": "https://github.com/owner/repo",
        "github_release_id": "1",
        "asset_id": "10",
        "artifact_sha256": "a" * 64,
        "resolved_tag_commit_sha": "commit",
        "audit_context_hash": "context",
        "completion_status": "completed",
    }
    assert ap.resume_identity_matches(legacy_expected, legacy_expected)

    worklist_expected = dict(legacy_expected)
    worklist_expected["worklist_fingerprint"] = "f" * 64
    assert not ap.resume_identity_matches(legacy_expected, worklist_expected)
    assert not ap.resume_identity_matches(worklist_expected, legacy_expected)
    worklist_expected["worklist_fingerprint"] = "b" * 64
    assert ap.resume_identity_matches(worklist_expected, worklist_expected)


# ---------------------------------------------------------------------------
# Task 3B: validated worklist worker mode
# ---------------------------------------------------------------------------


def _write_worker_worklist(tmp_path, *, items=None, shard_count=1):
    """Write the smallest canonical producer document for worker-mode tests."""
    repository = "https://github.com/owner/repo"
    if items is None:
        items = [
            {
                "repository": repository,
                "release_id": 1,
                "tag_name": "v1",
                "prerelease": False,
                "draft": False,
                "published_at": "2026-01-01T00:00:00Z",
                "created_at": "2026-01-01T00:00:00Z",
                "asset_id": 10,
                "asset_name": "plugin.zip",
                "asset_url": (
                    "https://github.com/owner/repo/releases/download/v1/plugin.zip"
                ),
                "asset_digest": "a" * 64,
                "resolved_source_commit_sha": "b" * 40,
                "source_resolution_error": None,
                "repository_archived": False,
            }
        ]
    payload = {
        "selection_mode": "repository",
        "source_revision": SOURCE_REVISION,
        "repositories": [repository],
        "shard_count": shard_count,
        "items": items,
        "base_commit": None,
        "latest_only": False,
    }
    fingerprint = worklist.compute_worklist_fingerprint(payload)
    path = tmp_path / "worklist.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": worklist.WORKLIST_SCHEMA_VERSION,
                "fingerprint": fingerprint,
                "payload": payload,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path, fingerprint


def _worker_cli(worklist_path, fingerprint, output_dir, *extra):
    return [
        "--worklist",
        str(worklist_path),
        "--expected-worklist-fingerprint",
        fingerprint,
        "--shard-count",
        "1",
        "--shard-index",
        "0",
        "--output-dir",
        str(output_dir),
        *extra,
    ]


def test_worker_mode_validates_snapshot_before_creating_any_output(tmp_path):
    worklist_path, fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / "outputs"

    assert ap.main(_worker_cli(worklist_path, "c" * 64, output_dir)) == 1
    assert not output_dir.exists()

    with pytest.raises(SystemExit):
        ap.main(
            _worker_cli(
                worklist_path,
                fingerprint,
                output_dir,
                "--repository",
                "https://github.com/owner/repo",
            )
        )


@pytest.mark.parametrize(
    ("case", "extra"),
    [
        ("base-ref-empty", ("--base-ref", "")),
        ("aggregate-deltas-bare", ("--aggregate-verdict-deltas",)),
        ("plugins-file-empty", ("--plugins-file", "")),
        ("source-revision-empty", ("--source-revision", "")),
        ("prepare-worklist-empty", ("--prepare-worklist", "")),
        ("api-deadline", ("--api-deadline-seconds", "1")),
        ("latest-only", ("--latest-only",)),
    ],
)
def test_worker_mode_rejects_prohibited_option_presence_before_output(
    monkeypatch, tmp_path, case, extra
):
    """Worker-mode conflicts are rejected even when their values are empty."""
    worklist_path, fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / case
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda *_args, **_kwargs: pytest.fail("option validation reached auditing"),
    )

    with pytest.raises(SystemExit):
        ap.main(_worker_cli(worklist_path, fingerprint, output_dir, *extra))
    assert not output_dir.exists()


@pytest.mark.parametrize(
    ("case", "argv"),
    [
        (
            "empty-worker-fingerprint",
            lambda _path, output_dir: _worker_cli(_path, "", output_dir),
        ),
        (
            "empty-fingerprint-outside-worker",
            lambda _path, output_dir: [
                "--all",
                "--expected-worklist-fingerprint",
                "",
                "--output-dir",
                str(output_dir),
            ],
        ),
    ],
)
def test_expected_worklist_fingerprint_option_is_presence_checked(
    monkeypatch, tmp_path, case, argv
):
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / case
    monkeypatch.setattr(
        ap,
        "read_repo_urls",
        lambda *_args: pytest.fail("fingerprint validation reached discovery"),
    )
    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda *_args, **_kwargs: pytest.fail(
            "fingerprint validation reached auditing"
        ),
    )

    with pytest.raises(SystemExit):
        ap.main(argv(worklist_path, output_dir))
    assert not output_dir.exists()


def test_worker_mode_uses_only_prepared_items_and_checkpoints_manifest(
    monkeypatch, tmp_path
):
    worklist_path, fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / "outputs"
    forbidden = (
        "read_repo_urls",
        "get_changed_repos",
        "build_audit_worklist",
        "get_repo_metadata",
        "get_releases",
        "_gh_get",
        "_resolve_ref_to_commit_and_tree_sha",
        "audit_repository",
    )
    for name in forbidden:
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"worker called forbidden seam {_name}"
            ),
        )

    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    observed = []

    def audit_prepared(repository, release, **kwargs):
        observed.append((repository, release, kwargs))
        return ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id=f"{release['tag_name']}@{release['assets'][0]['id']}",
            github_release_id=str(release["id"]),
            asset_id=str(release["assets"][0]["id"]),
            artifact_url=release["assets"][0]["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha="b" * 40,
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "audit_release", audit_prepared)
    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 0
    assert len(observed) == 1
    repository, release, kwargs = observed[0]
    assert repository == "https://github.com/owner/repo"
    assert release == {
        "id": 1,
        "tag_name": "v1",
        "prerelease": False,
        "draft": False,
        "published_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
        "assets": [
            {
                "id": 10,
                "name": "plugin.zip",
                "browser_download_url": (
                    "https://github.com/owner/repo/releases/download/v1/plugin.zip"
                ),
                "digest": "sha256:" + "a" * 64,
            }
        ],
    }
    assert kwargs["_repo_metadata"] == {
        "full_name": "owner/repo",
        "archived": False,
    }
    assert kwargs["_prepared_commit_sha"] == "b" * 40
    assert kwargs["_prepared_source_resolution_error"] is None

    progress = ap._load_progress_manifest(
        output_dir / "progress-shard-0.json", fingerprint
    )
    assert len(progress) == 1
    manifest = ap._load_shard_manifest(output_dir / "shard-manifest.json")
    assert manifest["worklist_fingerprint"] == fingerprint
    assert manifest["source_revision"] == SOURCE_REVISION
    assert manifest["assigned_identities"] == manifest["attempted_identities"]
    assert manifest["attempted_identities"] == manifest["report_identities"]


def test_prepared_source_error_is_identity_complete_release_error_without_resolution(
    monkeypatch, tmp_path
):
    del tmp_path
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda *_args: pytest.fail("prepared source error must not resolve a ref"),
    )
    for name in (
        "_scanner_runtime_identities",
        "download_zip",
        "run_trivy",
        "compare_source_and_artifact_from_snapshot",
    ):
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"prepared source error must not call {_name}"
            ),
        )
    monkeypatch.setattr(
        ap.audit_source_snapshot,
        "materialize_source_snapshot",
        lambda *_args, **_kwargs: pytest.fail(
            "prepared source error must not materialize source"
        ),
    )
    policy = ap._default_policy()
    report = ap.audit_release(
        "https://github.com/owner/repo",
        {
            "id": 1,
            "tag_name": "v1",
            "created_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "id": 10,
                    "name": "plugin.zip",
                    "browser_download_url": (
                        "https://github.com/owner/repo/releases/download/v1/plugin.zip"
                    ),
                    "digest": "sha256:" + "a" * 64,
                }
            ],
        },
        policy,
        [],
        _repo_metadata={"full_name": "owner/repo", "archived": False},
        _prepared_source_resolution_error=(
            "https://github.com/owner/repo:v1:source-resolution-failed"
        ),
        _persist_verdict=False,
    )
    assert report.final_classification == "AUDIT_ERROR"
    assert report.error_scope == "release"
    assert report.identity_status == "CURRENT"
    assert report.github_release_id == "1"
    assert report.asset_id == "10"
    assert report.completion_status == "incomplete"
    assert report.resolved_tag_commit_sha == ""
    assert report.errors == [
        "Prepared source resolution failed: "
        "https://github.com/owner/repo:v1:source-resolution-failed"
    ]


def test_prepared_source_error_is_bounded_before_worker_checkpointing(monkeypatch):
    """The worker-only error seam redacts before enforcing its output bound."""
    monkeypatch.setattr(
        ap,
        "_scanner_runtime_identities",
        lambda *_args: pytest.fail("prepared error must return before scanner probing"),
    )
    secret = "prepared-worker-secret-value-0123456789"
    redacted_token = 'token="[REDACTED]"'
    detail = (
        "x" * (ap.EVIDENCE_MAX_LEN - len(redacted_token) - 1)
        + f'token="{secret}"'
        + "y" * ap.EVIDENCE_MAX_LEN
    )
    report = ap.audit_release(
        "https://github.com/owner/repo",
        {
            "id": 1,
            "tag_name": "v1",
            "created_at": "2026-01-01T00:00:00Z",
            "assets": [
                {
                    "id": 10,
                    "name": "plugin.zip",
                    "browser_download_url": (
                        "https://github.com/owner/repo/releases/download/v1/plugin.zip"
                    ),
                    "digest": "sha256:" + "a" * 64,
                }
            ],
        },
        ap._default_policy(),
        [],
        _repo_metadata={"full_name": "owner/repo", "archived": False},
        _prepared_source_resolution_error=detail,
        _persist_verdict=False,
    )

    assert report.final_classification == "AUDIT_ERROR"
    assert report.error_scope == "release"
    detail_output = report.errors[0]
    assert (
        len(detail_output)
        <= len("Prepared source resolution failed: ") + ap.EVIDENCE_MAX_LEN
    )
    assert ap.SECRET_REDACT in detail_output
    assert secret not in detail_output
    assert secret[:8] not in detail_output
    assert secret[-8:] not in detail_output


@pytest.mark.parametrize(
    ("digest", "expected_sha256", "expected_identity_status"),
    [
        ("sha256:" + "a" * 64, "a" * 64, "CURRENT"),
        (None, "", "UNKNOWN"),
        ("sha256:not-a-valid-digest", "", "UNKNOWN"),
    ],
)
def test_prepared_source_error_uses_truthful_asset_identity_fallback(
    monkeypatch, digest, expected_sha256, expected_identity_status
):
    """Worker-local source failures retain only a verified asset identity."""
    monkeypatch.setattr(
        ap,
        "_scanner_runtime_identities",
        lambda *_args: pytest.fail("prepared error must return before scanner probing"),
    )
    asset = {
        "id": 10,
        "name": "plugin.zip",
        "browser_download_url": (
            "https://github.com/owner/repo/releases/download/v1/plugin.zip"
        ),
    }
    if digest is not None:
        asset["digest"] = digest

    report = ap.audit_release(
        "https://github.com/owner/repo",
        {
            "id": 1,
            "tag_name": "v1",
            "created_at": "2026-01-01T00:00:00Z",
            "assets": [asset],
        },
        ap._default_policy(),
        [],
        _repo_metadata={"full_name": "owner/repo", "archived": False},
        _prepared_source_resolution_error="owner/repo:v1:source-resolution-failed",
        _persist_verdict=False,
    )

    assert report.final_classification == "AUDIT_ERROR"
    assert report.artifact_sha256 == expected_sha256
    assert report.identity_status == expected_identity_status


def test_worker_mode_prepared_error_checkpoints_safe_sibling_and_exit_precedence(
    monkeypatch, tmp_path
):
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    document = json.loads(worklist_path.read_text(encoding="utf-8"))
    safe_item = document["payload"]["items"][0]
    error_item = copy.deepcopy(safe_item)
    error_item.update(
        release_id=2,
        tag_name="v2",
        published_at="2026-02-01T00:00:00Z",
        created_at="2026-02-01T00:00:00Z",
        asset_id=20,
        asset_name="plugin-v2.zip",
        asset_url="https://github.com/owner/repo/releases/download/v2/plugin-v2.zip",
        resolved_source_commit_sha=None,
        source_resolution_error=(
            "https://github.com/owner/repo:v2:source-resolution-failed"
        ),
    )
    document["payload"]["items"] = [error_item, safe_item]
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")

    archive = _zip_bytes()
    safe_item["asset_digest"] = hashlib.sha256(archive).hexdigest()
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")
    source_root = tmp_path / "prepared-source"
    source_root.mkdir()
    snapshot = ap.audit_source_snapshot.SourceSnapshot(
        repository="https://github.com/owner/repo",
        commit_sha="b" * 40,
        source_url="https://codeload.github.com/owner/repo/tar.gz/" + "b" * 40,
        archive_sha256="c" * 64,
        archive_size_bytes=0,
        source_root=str(source_root),
        inventory=(),
        plugin_json=None,
        package_json=None,
    )
    policy = ap._default_policy()
    for scanner in policy["scanners"].values():
        scanner.update(enabled=False, required=False)
    calls = {"scanner-identities": 0, "downloads": 0, "materializations": 0}

    def scanner_identities(_policy):
        calls["scanner-identities"] += 1
        return {}

    def download(_url, destination, policy=None):
        del policy
        calls["downloads"] += 1
        Path(destination).write_bytes(archive)
        return hashlib.sha256(archive).hexdigest()

    def materialize(*_args, **_kwargs):
        calls["materializations"] += 1
        return snapshot

    monkeypatch.setattr(ap, "load_policy", lambda *_args: policy)
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "_scanner_runtime_identities", scanner_identities)
    monkeypatch.setattr(ap, "download_zip", download)
    monkeypatch.setattr(
        ap.audit_source_snapshot, "materialize_source_snapshot", materialize
    )

    output_dir = tmp_path / "outputs"
    assert (
        ap.main(_worker_cli(worklist_path, fingerprint, output_dir, "--skip-cache"))
        == 4
    )
    assert calls == {
        "scanner-identities": 1,
        "downloads": 1,
        "materializations": 1,
    }

    expected_identities = [
        worklist.worklist_identity(error_item),
        worklist.worklist_identity(safe_item),
    ]
    reports = json.loads((output_dir / "security-report.json").read_text())
    assert [report["github_release_id"] for report in reports["reports"]] == ["2", "1"]
    assert reports["reports"][0]["completion_status"] == "incomplete"
    assert reports["reports"][1]["completion_status"] == "completed"
    progress = ap._load_progress_manifest(
        output_dir / "progress-shard-0.json", fingerprint
    )
    assert {
        (record["github_release_id"], record["asset_id"])
        for record in progress.values()
    } == {("2", "20"), ("1", "10")}
    manifest = ap._load_shard_manifest(output_dir / "shard-manifest.json")
    assert manifest["assigned_identities"] == expected_identities
    assert manifest["attempted_identities"] == expected_identities
    assert manifest["report_identities"] == expected_identities
    delta = json.loads((output_dir / "verdict-delta-shard-0.json").read_text())
    assert set(delta["https://github.com/owner/repo"]) == {"v1@10"}


def test_worker_mode_writes_valid_empty_outputs_and_manifest(monkeypatch, tmp_path):
    worklist_path, fingerprint = _write_worker_worklist(tmp_path, items=[])
    output_dir = tmp_path / "outputs"
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})

    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 0
    assert (
        json.loads((output_dir / "security-report.json").read_text(encoding="utf-8"))[
            "reports"
        ]
        == []
    )
    assert (
        json.loads(
            (output_dir / "verdict-delta-shard-0.json").read_text(encoding="utf-8")
        )
        == {}
    )
    assert ap._load_shard_manifest(output_dir / "shard-manifest.json") == {
        "schema_version": "1",
        "worklist_fingerprint": fingerprint,
        "source_revision": SOURCE_REVISION,
        "shard_count": 1,
        "shard_index": 0,
        "assigned_identities": [],
        "attempted_identities": [],
        "report_identities": [],
    }


def test_worker_mode_real_prepared_audit_reuses_one_source_snapshot(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    source_plugin = json.dumps({"name": "Plugin", "flags": []}).encode("utf-8")
    source_main = b"print('clean')\n"
    artifact_buffer = BytesIO()
    with zipfile.ZipFile(artifact_buffer, "w") as artifact:
        artifact.writestr("plugin.json", source_plugin)
        artifact.writestr("main.py", source_main)
    archive = artifact_buffer.getvalue()
    digest = hashlib.sha256(archive).hexdigest()
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    document = json.loads(worklist_path.read_text(encoding="utf-8"))
    document["payload"]["items"][0]["asset_digest"] = digest
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")

    source_archive = BytesIO()
    with tarfile.open(fileobj=source_archive, mode="w:gz") as archive_file:
        for path, payload in (("plugin.json", source_plugin), ("main.py", source_main)):
            member = tarfile.TarInfo(f"owner-repo-{'b' * 8}/{path}")
            member.size = len(payload)
            archive_file.addfile(member, BytesIO(payload))
    source_archive_bytes = source_archive.getvalue()

    policy = ap._default_policy()
    policy["scanners"]["clamav"].update(enabled=False, required=False)
    policy["scanners"]["semgrep"].update(enabled=False, required=False)
    policy["scanners"]["trivy"].update(enabled=True, required=True)
    policy["scanners"]["source_artifact_diff"].update(enabled=True, required=True)
    codeload_calls = []
    scanner_calls = []
    observed = {}
    extraction_calls = []

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload
            self.headers = {"Content-Length": str(len(payload))}
            self.status_code = 200

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size=8192):
            for offset in range(0, len(self._payload), chunk_size):
                yield self._payload[offset : offset + chunk_size]

        def close(self):
            return None

    class FakeSession:
        def __init__(self):
            self.headers = {}
            self.auth = None

        def get(self, url, **kwargs):
            codeload_calls.append((url, kwargs))
            return FakeResponse(source_archive_bytes)

    def download(_url, destination, policy=None):
        del policy
        Path(destination).write_bytes(archive)
        return digest

    def fake_which(command):
        return "/tmp/fake-trivy" if command == "trivy" else None

    def fake_run(command, **_kwargs):
        scanner_calls.append(command)
        if command == ["/tmp/fake-trivy", "--version"]:
            return subprocess.CompletedProcess(command, 0, "trivy 1.0\n", "")
        if command == ["/tmp/fake-trivy", "version", "--format", "json"]:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(
                    {
                        "VulnerabilityDB": {
                            "Version": 1,
                            "UpdatedAt": "2026-01-01T00:00:00Z",
                        }
                    }
                ),
                "",
            )
        if command[:5] == ["trivy", "fs", "--format", "json", "--quiet"]:
            return subprocess.CompletedProcess(command, 0, '{"Results": []}', "")
        pytest.fail(f"unexpected scanner command: {command!r}")

    real_compare = ap.compare_source_and_artifact_from_snapshot

    def capture_compare(extract_dir, snapshot, ref):
        observed["snapshot"] = snapshot
        observed["source_diff_root"] = snapshot.source_root
        return real_compare(extract_dir, snapshot, ref)

    real_extract = ap.audit_source_snapshot._extract_source_archive

    def capture_extract(*args, **kwargs):
        extraction_calls.append(args[0])
        return real_extract(*args, **kwargs)

    for name in (
        "read_repo_urls",
        "get_changed_repos",
        "build_audit_worklist",
        "get_repo_metadata",
        "get_releases",
        "_gh_get",
        "_resolve_ref_to_commit_and_tree_sha",
        "audit_repository",
    ):
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"worker called forbidden seam {_name}"
            ),
        )
    monkeypatch.setattr(ap, "load_policy", lambda *_args: policy)
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "download_zip", download)
    monkeypatch.setattr(ap, "_gh_session", FakeSession())
    monkeypatch.setattr(ap.shutil, "which", fake_which)
    monkeypatch.setattr(ap.subprocess, "run", fake_run)
    monkeypatch.setattr(
        ap.audit_source_snapshot, "_extract_source_archive", capture_extract
    )
    monkeypatch.setattr(
        ap, "compare_source_and_artifact_from_snapshot", capture_compare
    )

    assert (
        ap.main(
            _worker_cli(
                worklist_path,
                fingerprint,
                tmp_path / "outputs",
                "--skip-cache",
            )
        )
        == 0
    )
    assert codeload_calls == [
        (
            "https://codeload.github.com/owner/repo/tar.gz/" + "b" * 40,
            {
                "allow_redirects": False,
                "stream": True,
                "timeout": (10, 60),
                "headers": {},
            },
        )
    ]
    assert len(extraction_calls) == 1
    assert observed["snapshot"].commit_sha == "b" * 40
    assert observed["snapshot"].source_root == observed["source_diff_root"]
    source_scans = [
        command[-1] for command in scanner_calls if command[:2] == ["trivy", "fs"]
    ]
    assert observed["source_diff_root"] in source_scans
    assert len(source_scans) == 2


def test_worker_mode_matching_resume_never_calls_audit_or_discovery(
    monkeypatch, tmp_path
):
    worklist_path, fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / "outputs"
    policy = ap._default_policy()
    monkeypatch.setattr(ap, "load_policy", lambda *_args: policy)
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(ap, "_scanner_runtime_identities", lambda *_args: {})
    monkeypatch.setattr(
        ap,
        "compute_audit_context_hash",
        lambda *_args, **_kwargs: "current-context",
    )

    def completed(repository, release, **_kwargs):
        return ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id="v1@10",
            github_release_id="1",
            asset_id="10",
            artifact_url=release["assets"][0]["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha="b" * 40,
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "audit_release", completed)
    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 0

    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda *_args, **_kwargs: pytest.fail("matching worker checkpoint reran audit"),
    )
    for name in (
        "read_repo_urls",
        "get_changed_repos",
        "build_audit_worklist",
        "get_repo_metadata",
        "get_releases",
        "_gh_get",
        "_resolve_ref_to_commit_and_tree_sha",
        "audit_repository",
    ):
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"resume called forbidden seam {_name}"
            ),
        )
    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 0


@pytest.mark.parametrize(
    ("case", "progress_payload"),
    [
        ("v1", lambda _fingerprint: json.dumps({"schema_version": "1", "entries": {}})),
        ("malformed", lambda _fingerprint: "not valid JSON"),
        (
            "mismatched-fingerprint",
            lambda _fingerprint: json.dumps(
                {
                    "schema_version": "2",
                    "worklist_fingerprint": "c" * 64,
                    "entries": {},
                }
            ),
        ),
    ],
)
def test_worker_mode_stale_progress_reruns_prepared_commit_without_discovery(
    monkeypatch, tmp_path, case, progress_payload
):
    worklist_path, fingerprint = _write_worker_worklist(tmp_path)
    output_dir = tmp_path / case
    output_dir.mkdir()
    (output_dir / "progress-shard-0.json").write_text(
        progress_payload(fingerprint), encoding="utf-8"
    )
    observed_commits = []

    for name in (
        "read_repo_urls",
        "get_changed_repos",
        "build_audit_worklist",
        "get_repo_metadata",
        "get_releases",
        "_gh_get",
        "_resolve_ref_to_commit_and_tree_sha",
        "audit_repository",
    ):
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"stale resume called forbidden seam {_name}"
            ),
        )
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})

    def completed(repository, release, **kwargs):
        observed_commits.append(kwargs["_prepared_commit_sha"])
        asset = release["assets"][0]
        return ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id=f"{release['tag_name']}@{asset['id']}",
            github_release_id=str(release["id"]),
            asset_id=str(asset["id"]),
            artifact_url=asset["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha=kwargs["_prepared_commit_sha"],
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "audit_release", completed)
    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 0
    assert observed_commits == ["b" * 40]
    progress = ap._load_progress_manifest(
        output_dir / "progress-shard-0.json", fingerprint
    )
    assert len(progress) == 1
    assert all(
        record["worklist_fingerprint"] == fingerprint for record in progress.values()
    )


def test_worker_mode_multi_shard_manifests_follow_worklist_order(monkeypatch, tmp_path):
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    document = json.loads(worklist_path.read_text(encoding="utf-8"))
    template = document["payload"]["items"][0]
    shard_count = 4
    by_shard = {index: [] for index in range(shard_count)}

    def item_for(release_id):
        item = copy.deepcopy(template)
        item.update(
            release_id=release_id,
            tag_name=f"v{release_id}",
            asset_id=1000 + release_id,
            asset_name=f"plugin-{release_id}.zip",
            asset_url=(
                "https://github.com/owner/repo/releases/download/"
                f"v{release_id}/plugin-{release_id}.zip"
            ),
        )
        return item

    for release_id in range(1, 100):
        candidate = item_for(release_id)
        by_shard[worklist.shard_index_for_worklist_item(candidate, shard_count)].append(
            candidate
        )
        primary_indices = [
            index for index, candidates in by_shard.items() if len(candidates) >= 2
        ]
        secondary_indices = [
            index
            for index, candidates in by_shard.items()
            if index not in primary_indices and candidates
        ]
        if primary_indices and secondary_indices:
            break

    primary_index = primary_indices[0]
    secondary_index = secondary_indices[0]
    unassigned_index = next(
        index
        for index in range(shard_count)
        if index not in {primary_index, secondary_index}
    )
    document["payload"]["shard_count"] = shard_count
    document["payload"]["items"] = sorted(
        [
            by_shard[primary_index][0],
            by_shard[primary_index][1],
            by_shard[secondary_index][0],
        ],
        key=lambda item: item["release_id"],
        reverse=True,
    )
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")
    observed_release_ids = []

    for name in (
        "read_repo_urls",
        "get_changed_repos",
        "build_audit_worklist",
        "get_repo_metadata",
        "get_releases",
        "_gh_get",
        "_resolve_ref_to_commit_and_tree_sha",
        "audit_repository",
    ):
        monkeypatch.setattr(
            ap,
            name,
            lambda *_args, _name=name, **_kwargs: pytest.fail(
                f"sharded worker called forbidden seam {_name}"
            ),
        )
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})

    def completed(repository, release, **kwargs):
        asset = release["assets"][0]
        observed_release_ids.append(release["id"])
        return ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id=f"{release['tag_name']}@{asset['id']}",
            github_release_id=str(release["id"]),
            asset_id=str(asset["id"]),
            artifact_url=asset["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha=kwargs["_prepared_commit_sha"],
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "audit_release", completed)
    for shard_index in range(shard_count):
        observed_release_ids.clear()
        output_dir = tmp_path / f"shard-{shard_index}"
        args = [
            "--worklist",
            str(worklist_path),
            "--expected-worklist-fingerprint",
            fingerprint,
            "--shard-count",
            str(shard_count),
            "--shard-index",
            str(shard_index),
            "--output-dir",
            str(output_dir),
        ]
        assert ap.main(args) == 0
        selected = worklist.select_worklist_shard(document["payload"], shard_index)
        expected_identities = [worklist.worklist_identity(item) for item in selected]
        assert observed_release_ids == [item["release_id"] for item in selected]
        manifest = ap._load_shard_manifest(output_dir / "shard-manifest.json")
        assert manifest["assigned_identities"] == expected_identities
        assert manifest["attempted_identities"] == expected_identities
        assert manifest["report_identities"] == expected_identities

    assert not worklist.select_worklist_shard(document["payload"], unassigned_index)


def test_worker_mode_manifest_checkpoint_failure_is_run_global(monkeypatch, tmp_path):
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    document = json.loads(worklist_path.read_text(encoding="utf-8"))
    first = document["payload"]["items"][0]
    second = copy.deepcopy(first)
    second.update(
        release_id=2,
        tag_name="v2",
        published_at="2026-02-01T00:00:00Z",
        created_at="2026-02-01T00:00:00Z",
        asset_id=20,
        asset_name="plugin-v2.zip",
        asset_url="https://github.com/owner/repo/releases/download/v2/plugin-v2.zip",
        resolved_source_commit_sha="c" * 40,
    )
    document["payload"]["items"] = [second, first]
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")
    output_dir = tmp_path / "outputs"
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})
    monkeypatch.setattr(
        ap,
        "audit_release",
        lambda repository, release, **_kwargs: ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id=f"{release['tag_name']}@{release['assets'][0]['id']}",
            github_release_id=str(release["id"]),
            asset_id=str(release["assets"][0]["id"]),
            artifact_url=release["assets"][0]["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha=_kwargs["_prepared_commit_sha"],
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        ),
    )
    real_write_manifest = ap._write_shard_manifest
    manifest_writes = 0

    def fail_second_manifest(path, manifest):
        nonlocal manifest_writes
        manifest_writes += 1
        if manifest_writes == 2:
            raise OSError("manifest denied")
        real_write_manifest(path, manifest)

    monkeypatch.setattr(
        ap,
        "_write_shard_manifest",
        fail_second_manifest,
    )

    assert ap.main(_worker_cli(worklist_path, fingerprint, output_dir)) == 1
    assert manifest_writes == 2
    assert (output_dir / "progress-shard-0.json").exists()
    assert (output_dir / "security-report.json").exists()
    assert (output_dir / "verdict-delta-shard-0.json").exists()
    manifest = ap._load_shard_manifest(output_dir / "shard-manifest.json")
    first_identity = worklist.worklist_identity(second)
    assert manifest["assigned_identities"] == [
        first_identity,
        worklist.worklist_identity(first),
    ]
    assert manifest["attempted_identities"] == [first_identity]
    assert manifest["report_identities"] == [first_identity]
    reports = json.loads((output_dir / "security-report.json").read_text())
    assert [report["github_release_id"] for report in reports["reports"]] == ["2"]
    delta = json.loads((output_dir / "verdict-delta-shard-0.json").read_text())
    assert set(delta["https://github.com/owner/repo"]) == {"v2@20"}
    progress = ap._load_progress_manifest(
        output_dir / "progress-shard-0.json", fingerprint
    )
    assert len(progress) == 1


def test_worker_checkpoint_promotion_rolls_back_every_visible_output(
    monkeypatch, tmp_path
):
    """A later promotion failure leaves the prior worker generation intact."""
    worklist_path, _fingerprint = _write_worker_worklist(tmp_path)
    document = json.loads(worklist_path.read_text(encoding="utf-8"))
    first = document["payload"]["items"][0]
    second = copy.deepcopy(first)
    second.update(
        release_id=2,
        tag_name="v2",
        published_at="2026-02-01T00:00:00Z",
        created_at="2026-02-01T00:00:00Z",
        asset_id=20,
        asset_name="plugin-v2.zip",
        asset_url="https://github.com/owner/repo/releases/download/v2/plugin-v2.zip",
        resolved_source_commit_sha="c" * 40,
    )
    document["payload"]["items"] = [second, first]
    fingerprint = worklist.compute_worklist_fingerprint(document["payload"])
    document["fingerprint"] = fingerprint
    worklist_path.write_text(json.dumps(document), encoding="utf-8")

    output_dir = tmp_path / "outputs"
    progress_path = tmp_path / "state" / "progress.json"
    delta_path = tmp_path / "deltas" / "delta.json"
    visible_targets = (
        progress_path,
        output_dir / "security-report.json",
        output_dir / "security-report.md",
        delta_path,
        output_dir / "shard-manifest.json",
    )
    monkeypatch.setattr(ap, "load_policy", lambda *_args: ap._default_policy())
    monkeypatch.setattr(ap, "load_allowlist", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ap, "load_verdicts", lambda *_args: {})

    audit_calls = 0
    prior_generation = None
    inject_failure = False

    def completed(repository, release, **kwargs):
        nonlocal audit_calls, prior_generation, inject_failure
        audit_calls += 1
        if audit_calls == 2:
            prior_generation = {
                target: target.read_bytes() for target in visible_targets
            }
            inject_failure = True
        asset = release["assets"][0]
        return ap.AuditReport(
            repository=repository,
            release=release["tag_name"],
            release_id=f"{release['tag_name']}@{asset['id']}",
            github_release_id=str(release["id"]),
            asset_id=str(asset["id"]),
            artifact_url=asset["browser_download_url"],
            artifact_sha256="a" * 64,
            identity_status="CURRENT",
            resolved_tag_commit_sha=kwargs["_prepared_commit_sha"],
            audit_context_hash="current-context",
            final_classification="PASS",
            completion_status="completed",
        )

    monkeypatch.setattr(ap, "audit_release", completed)
    real_replace = ap.os.replace
    replacement_failed = False

    def fail_middle_promotion(source, destination):
        nonlocal replacement_failed
        if (
            inject_failure
            and not replacement_failed
            and Path(destination) == delta_path
        ):
            replacement_failed = True
            raise OSError("injected verdict-delta promotion failure")
        return real_replace(source, destination)

    monkeypatch.setattr(ap.os, "replace", fail_middle_promotion)

    assert (
        ap.main(
            _worker_cli(
                worklist_path,
                fingerprint,
                output_dir,
                "--progress-manifest",
                str(progress_path),
                "--verdict-delta",
                str(delta_path),
            )
        )
        == 1
    )
    assert replacement_failed
    assert prior_generation is not None
    assert {
        target: target.read_bytes() for target in visible_targets
    } == prior_generation
    assert not list(tmp_path.rglob(".audit-worker-checkpoint-*"))
    assert not list(tmp_path.rglob("*.checkpoint-stage-*"))
    assert not list(tmp_path.rglob("*.checkpoint-backup-*"))


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
    assert successful_report["final_classification"] == "PASS_WITH_WARNINGS"
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
