import json
from pathlib import Path

import pytest

import audit_plugins as ap
import audit_worklist


def _release(
    tag: str,
    release_id: int,
    asset_id: int,
    *,
    owner: str = "owner",
    repo: str = "repo",
    published_at: str = "2026-01-01T00:00:00Z",
):
    return {
        "id": release_id,
        "tag_name": tag,
        "published_at": published_at,
        "created_at": "2026-01-01T00:00:00Z",
        "prerelease": False,
        "draft": False,
        "assets": [
            {
                "id": asset_id,
                "name": f"plugin-{tag}.zip",
                "browser_download_url": (
                    f"https://github.com/{owner}/{repo}/"
                    f"releases/download/{tag}/plugin-{tag}.zip"
                ),
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }


def _metadata(_owner: str, _repo: str, *, archived: bool = False):
    return {"full_name": f"{_owner}/{_repo}", "archived": archived}


def _build_worklist(tmp_path: Path):
    worklist_path = tmp_path / "worklist.json"
    fp, _ = audit_worklist.prepare_audit_worklist(
        worklist_path,
        source_revision="a" * 40,
        selection_mode="all",
        repository_urls=[
            "https://github.com/owner/repo",
            "https://github.com/owner/other",
        ],
        shard_count=14,
        latest_only=False,
        release_fetcher=lambda owner, repo: (
            [
                _release("v2", 2, 20, owner=owner, repo=repo),
                _release("v1", 1, 10, owner=owner, repo=repo),
            ]
            if (owner, repo) == ("owner", "repo")
            else [_release("v1", 3, 30, owner=owner, repo=repo)]
        ),
        metadata_fetcher=lambda owner, repo: _metadata(owner, repo),
        tag_resolver=lambda owner, repo, *_args: {"v1": "f" * 40, "v2": "e" * 40},
        api_deadline_seconds=8,
    )
    return worklist_path, fp


def _expected_shard_index(item: dict, shard_count: int) -> int:
    return ap._shard_index_for_manifest_identity(
        {
            "repository": item["repository"],
            "github_release_id": str(item["release_id"]),
            "asset_id": str(item["asset_id"]),
        },
        shard_count,
    )


def _identity_key(item):
    return (item["repository"], str(item["release_id"]), str(item["asset_id"]))


def _manifest_identity_for_shard(shard_index: int, shard_count: int, repository: str):
    for release_id in range(1, 2000):
        candidate = {
            "repository": repository,
            "github_release_id": str(release_id),
            "asset_id": str(release_id + 100),
        }
        if ap._shard_index_for_manifest_identity(candidate, shard_count) == shard_index:
            return candidate
    raise AssertionError("unable to construct identity for requested shard")


def _sample_progress_record(report_id: str = "v1@10", *, fingerprint: str = "f" * 64):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id=report_id,
        github_release_id="10",
        asset_id="20",
        artifact_sha256="a" * 64,
        resolved_tag_commit_sha="d" * 40,
        audit_context_hash="context",
        completion_status="completed",
        final_classification="PASS",
    )
    return ap._report_identity_key(report), ap._progress_record(report, fingerprint)


def test_load_expected_worklist_document_enforces_exact_fingerprint(tmp_path):
    path, fingerprint = _build_worklist(tmp_path)

    doc = audit_worklist.load_expected_worklist_document(
        path, expected_worklist_fingerprint=fingerprint
    )
    assert doc["fingerprint"] == fingerprint

    with pytest.raises(ValueError, match="fingerprint"):
        audit_worklist.load_expected_worklist_document(
            path,
            expected_worklist_fingerprint="0" * 64,
        )


@pytest.mark.parametrize("tamper", ["repositories", "items"])
def test_load_expected_worklist_document_rejects_tampering(tmp_path, tamper):
    path, fingerprint = _build_worklist(tmp_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if tamper == "repositories":
        raw["payload"]["repositories"] = ["https://github.com/evil/repo"]
    else:
        raw["payload"]["items"].append(
            {
                "repository": "https://github.com/owner/repo",
                "release_id": 99,
                "tag_name": "v99",
                "prerelease": False,
                "draft": False,
                "published_at": "2026-01-01T00:00:00Z",
                "created_at": "2026-01-01T00:00:00Z",
                "asset_id": 99,
                "asset_name": "plugin.zip",
                "asset_url": "https://github.com/owner/repo/releases/download/v99/plugin.zip",
                "asset_digest": "a" * 64,
                "resolved_source_commit_sha": None,
                "source_resolution_error": "owner/repo:v99:source-resolution-failed",
                "repository_archived": False,
            }
        )
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError):
        audit_worklist.load_expected_worklist_document(
            path, expected_worklist_fingerprint=fingerprint
        )


def test_select_worklist_shard_is_deterministic_and_covering(tmp_path):
    path, fingerprint = _build_worklist(tmp_path)
    payload = audit_worklist.load_expected_worklist_document(
        path,
        expected_worklist_fingerprint=fingerprint,
    )["payload"]

    shard_count = payload["shard_count"]
    expected = payload["items"]
    seen = set()
    for shard_index in range(shard_count):
        selected = audit_worklist.select_worklist_shard(payload, shard_index)
        expected_shard = [
            item
            for item in expected
            if _expected_shard_index(item, shard_count) == shard_index
        ]
        assert selected == expected_shard
        for item in selected:
            key = _identity_key(item)
            assert key not in seen
            seen.add(key)
    assert seen == {_identity_key(item) for item in expected}


def test_progress_v2_manifest_is_bound_to_fingerprint(tmp_path):
    key, record = _sample_progress_record()
    fp = "f" * 64
    progress_path = tmp_path / "progress.json"

    ap._write_progress_manifest(progress_path, {key: record}, worklist_fingerprint=fp)
    loaded = ap._load_progress_manifest(progress_path, expected_worklist_fingerprint=fp)

    assert loaded == {key: record}
    assert loaded[key]["worklist_fingerprint"] == fp

    no_resume = ap._load_progress_manifest(
        progress_path, expected_worklist_fingerprint="e" * 64
    )
    assert no_resume == {}


def test_load_progress_manifest_uses_v1_for_legacy_without_expected_filter(tmp_path):
    key, record = _sample_progress_record()
    progress_path = tmp_path / "progress.json"
    ap._write_progress_manifest(progress_path, {key: record})

    assert ap._load_progress_manifest(progress_path) == {key: record}
    assert (
        ap._load_progress_manifest(
            progress_path,
            expected_worklist_fingerprint="f" * 64,
        )
        == {}
    )


def test_load_progress_manifest_rejects_malformed_v2_payload(tmp_path):
    path = tmp_path / "progress.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "2",
                "worklist_fingerprint": "f" * 64,
                "entries": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid progress manifest"):
        ap._load_progress_manifest(path, expected_worklist_fingerprint="f" * 64)


def _base_manifest(index: int, shard_count: int = 14, fingerprint: str = "f" * 64):
    identity = _manifest_identity_for_shard(
        index, shard_count, "https://github.com/owner/repo"
    )
    return {
        "schema_version": "1",
        "worklist_fingerprint": fingerprint,
        "source_revision": "a" * 40,
        "shard_count": shard_count,
        "shard_index": index,
        "assigned_identities": [identity],
        "attempted_identities": [identity],
        "report_identities": [identity],
    }


def test_shard_manifest_roundtrip_with_empty_and_non_empty_assignments(tmp_path):
    path = tmp_path / "manifest.json"
    manifest = _base_manifest(0)
    ap._write_shard_manifest(path, manifest)
    loaded = ap._load_shard_manifest(path)

    assert loaded == {
        "schema_version": "1",
        "worklist_fingerprint": "f" * 64,
        "source_revision": "a" * 40,
        "shard_count": 14,
        "shard_index": 0,
        "assigned_identities": manifest["assigned_identities"],
        "attempted_identities": manifest["attempted_identities"],
        "report_identities": manifest["report_identities"],
    }

    empty_path = tmp_path / "empty.json"
    ap._write_shard_manifest(
        empty_path,
        {
            "schema_version": "1",
            "worklist_fingerprint": "f" * 64,
            "source_revision": "b" * 40,
            "shard_count": 7,
            "shard_index": 3,
            "assigned_identities": [],
            "attempted_identities": [],
            "report_identities": [],
        },
    )
    assert ap._load_shard_manifest(empty_path)["assigned_identities"] == []


def test_shard_manifest_rejects_wrong_shard_identity(tmp_path):
    path = tmp_path / "manifest.json"
    manifest = _base_manifest(0)
    manifest["shard_index"] = 1

    with pytest.raises(ValueError, match="assigned_identities include"):
        ap._write_shard_manifest(path, manifest)


def test_shard_manifest_rejects_invalid_schema_fields(tmp_path):
    path = tmp_path / "manifest.json"

    with pytest.raises(ValueError, match="fingerprint"):
        ap._write_shard_manifest(
            path,
            {
                "schema_version": "1",
                "worklist_fingerprint": "not-a-fingerprint",
                "source_revision": "a" * 40,
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
            },
        )

    with pytest.raises(ValueError, match="source_revision"):
        ap._write_shard_manifest(
            path,
            {
                "schema_version": "1",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "short",
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
            },
        )


def test_shard_manifest_rejects_out_of_assignment_identities_and_duplicates(tmp_path):
    shard_count = 14
    shard_index = 0
    first = _manifest_identity_for_shard(
        shard_index, shard_count, "https://github.com/owner/repo"
    )

    with pytest.raises(ValueError, match="attempted_identities must be a subset"):
        ap._normalise_shard_manifest(
            {
                "schema_version": "1",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": shard_index,
                "assigned_identities": [first],
                "attempted_identities": [
                    {
                        "repository": "https://github.com/owner/other",
                        "github_release_id": "9",
                        "asset_id": "9",
                    }
                ],
                "report_identities": [],
            }
        )

    with pytest.raises(ValueError, match="Duplicate identity"):
        ap._normalise_shard_manifest(
            {
                "schema_version": "1",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": shard_index,
                "assigned_identities": [first, first],
                "attempted_identities": [first],
                "report_identities": [first],
            }
        )


def test_shard_manifest_rejects_completed_shard_with_incomplete_reports(tmp_path):
    path = tmp_path / "manifest.json"
    shard_count = 14
    index = 1
    first = _manifest_identity_for_shard(
        index, shard_count, "https://github.com/owner/repo"
    )
    second = _manifest_identity_for_shard(
        index, shard_count, "https://github.com/owner/other"
    )
    with pytest.raises(
        ValueError, match="report_identities must equal attempted_identities"
    ):
        ap._write_shard_manifest(
            path,
            {
                "schema_version": "1",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": index,
                "assigned_identities": [first, second],
                "attempted_identities": [first, second],
                "report_identities": [first],
            },
        )


def test_progress_manifest_atomic_write_failure_leaves_no_file(tmp_path, monkeypatch):
    key, record = _sample_progress_record()
    path = tmp_path / "progress.json"

    def fail(_path, _content):
        raise RuntimeError("write failed")

    monkeypatch.setattr(ap, "_atomic_write_text", fail)

    with pytest.raises(RuntimeError, match="write failed"):
        ap._write_progress_manifest(
            path,
            {key: record},
            worklist_fingerprint="f" * 64,
        )

    assert not path.exists()


def test_shard_manifest_atomic_write_failure_leaves_no_file(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"

    def fail(_path, _content):
        raise RuntimeError("write failed")

    monkeypatch.setattr(ap, "_atomic_write_text", fail)

    with pytest.raises(RuntimeError, match="write failed"):
        ap._write_shard_manifest(
            path,
            {
                "schema_version": "1",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
            },
        )

    assert not path.exists()
