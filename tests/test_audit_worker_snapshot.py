import hashlib
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


def _manifest_identity_for_repository_and_shard(
    shard_index: int,
    shard_count: int,
    repository: str,
    start: int = 1,
):
    for release_id in range(start, 20000):
        candidate = {
            "repository": repository,
            "github_release_id": str(release_id),
            "asset_id": str(release_id + 100),
        }
        if ap._shard_index_for_manifest_identity(candidate, shard_count) == shard_index:
            return candidate
    raise AssertionError("unable to construct requested repository/shard identity")


def _alternate_identity_same_shard(shard_index: int, shard_count: int, excluded: dict):
    for repository in (
        "https://github.com/owner/repo",
        "https://github.com/owner/other",
    ):
        for release_id in range(1, 50000):
            candidate = {
                "repository": repository,
                "github_release_id": str(release_id),
                "asset_id": str(release_id + 100),
            }
            if candidate == excluded:
                continue
            if (
                ap._shard_index_for_manifest_identity(candidate, shard_count)
                == shard_index
            ):
                return candidate
    raise AssertionError("unable to construct alternate same-shard identity")


def _expected_assigned_identities(doc: dict, shard_index: int):
    payload = doc["payload"]
    return [
        audit_worklist.worklist_identity(item)
        for item in audit_worklist.select_worklist_shard(payload, shard_index)
    ]


def _make_shard_manifest(
    shard_index: int,
    assigned,
    attempt,
    report,
    *,
    shard_count: int = 14,
    fingerprint: str = "f" * 64,
    source_revision: str = "a" * 40,
):
    return {
        "schema_version": "2",
        "worklist_fingerprint": fingerprint,
        "source_revision": source_revision,
        "shard_count": shard_count,
        "shard_index": shard_index,
        "assigned_identities": assigned,
        "attempted_identities": attempt,
        "report_identities": report,
        "artifacts": _manifest_artifacts(),
    }


def _make_valid_manifest_for_expected_shard(
    worklist_doc: dict,
    shard_index: int,
    *,
    assigned=None,
    attempted=None,
    report=None,
    source_revision: str | None = None,
    shard_count: int | None = None,
    fingerprint: str | None = None,
):
    payload = worklist_doc["payload"]
    if assigned is None:
        assigned = _expected_assigned_identities(worklist_doc, shard_index)
    if attempted is None:
        attempted = assigned
    if report is None:
        report = attempted
    if shard_count is None:
        shard_count = payload["shard_count"]
    if fingerprint is None:
        fingerprint = worklist_doc["fingerprint"]
    if source_revision is None:
        source_revision = payload["source_revision"]
    return {
        "schema_version": "2",
        "worklist_fingerprint": fingerprint,
        "source_revision": source_revision,
        "shard_count": shard_count,
        "shard_index": shard_index,
        "assigned_identities": assigned,
        "attempted_identities": attempted,
        "report_identities": report,
        "artifacts": _manifest_artifacts(),
    }


def _find_same_shard_release_pair_for_order_probe(
    shard_index: int, shard_count: int, repository: str
):
    candidates = []
    for release_id in range(1, 5000):
        candidate = {
            "repository": repository,
            "github_release_id": str(release_id),
            "asset_id": str(release_id + 100),
        }
        if ap._shard_index_for_manifest_identity(candidate, shard_count) != shard_index:
            continue
        candidates.append(candidate)
        if len(candidates) == 2:
            return candidates[0], candidates[1]
    raise AssertionError("unable to find same-shard identity pair")


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


def _manifest_artifacts():
    return {
        name: {"sha256": "a" * 64, "size_bytes": 0}
        for name in (
            "progress",
            "report_json",
            "report_markdown",
            "verdict_delta",
        )
    }


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


def test_load_progress_manifest_rejects_v2_payload_with_extra_record_key(tmp_path):
    key, record = _sample_progress_record()
    malformed = dict(record)
    malformed["unexpected"] = "value"
    path = tmp_path / "progress.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "2",
                "worklist_fingerprint": "f" * 64,
                "entries": {key: malformed},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid progress manifest"):
        ap._load_progress_manifest(path, expected_worklist_fingerprint="f" * 64)


def test_load_progress_manifest_validates_v2_payload_even_when_fingerprint_mismatched(
    tmp_path,
):
    path = tmp_path / "progress.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "2",
                "worklist_fingerprint": "f" * 64,
                "entries": {
                    "bad-key": {
                        "repository": "https://github.com/owner/repo",
                        "github_release_id": "10",
                        "asset_id": "20",
                        "artifact_sha256": "a" * 64,
                        "resolved_tag_commit_sha": "c" * 40,
                        "audit_context_hash": "ctx",
                        "completion_status": "completed",
                        "report": {},
                        "worklist_fingerprint": "f" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid progress manifest"):
        ap._load_progress_manifest(path, expected_worklist_fingerprint="0" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("audit_context_hash", None),
        ("audit_context_hash", ""),
        ("audit_context_hash", 123),
        ("audit_context_hash", " "),
    ],
)
def test_load_progress_manifest_rejects_invalid_audit_context_hash(
    tmp_path, field, value
):
    key, record = _sample_progress_record()
    mutated = dict(record)
    mutated[field] = value

    with pytest.raises(
        ValueError, match="Invalid progress manifest|Invalid audit_context_hash"
    ):
        ap._normalise_progress_record(
            key,
            mutated,
            expected_fingerprint="f" * 64,
        )


def test_write_progress_manifest_rejects_non_canonical_progress_keys(tmp_path):
    key, record = _sample_progress_record(fingerprint="f" * 64)
    path = tmp_path / "progress.json"
    bad_key = "https://github.com/OWNER/repo\x00" + "\x00".join(key.split("\x00")[1:])
    bad_record = dict(record)
    bad_record["repository"] = "https://github.com/OWNER/repo"

    with pytest.raises(
        ValueError, match="Invalid progress manifest|Repository URL is not canonical"
    ):
        ap._write_progress_manifest(
            path, {bad_key: bad_record}, worklist_fingerprint="f" * 64
        )


def test_write_progress_manifest_rejects_v2_payload_with_extra_record_key(tmp_path):
    key, record = _sample_progress_record(fingerprint="f" * 64)
    malformed = dict(record)
    malformed["unexpected"] = "value"
    path = tmp_path / "progress.json"

    with pytest.raises(ValueError, match="Invalid progress manifest"):
        ap._write_progress_manifest(
            path,
            {key: malformed},
            worklist_fingerprint="f" * 64,
        )


@pytest.mark.parametrize("value", ["", 123, None, "   "])
def test_write_progress_manifest_rejects_invalid_audit_context_hash(tmp_path, value):
    key, record = _sample_progress_record(fingerprint="f" * 64)
    malformed = dict(record)
    malformed["audit_context_hash"] = value
    path = tmp_path / "progress.json"

    with pytest.raises(
        ValueError, match="Invalid progress manifest|Invalid audit_context_hash"
    ):
        ap._write_progress_manifest(
            path,
            {key: malformed},
            worklist_fingerprint="f" * 64,
        )


def _base_manifest(index: int, shard_count: int = 14, fingerprint: str = "f" * 64):
    identity = _manifest_identity_for_shard(
        index, shard_count, "https://github.com/owner/repo"
    )
    return {
        "schema_version": "2",
        "worklist_fingerprint": fingerprint,
        "source_revision": "a" * 40,
        "shard_count": shard_count,
        "shard_index": index,
        "assigned_identities": [identity],
        "attempted_identities": [identity],
        "report_identities": [identity],
        "artifacts": _manifest_artifacts(),
    }


def test_shard_manifest_roundtrip_with_empty_and_non_empty_assignments(tmp_path):
    path = tmp_path / "manifest.json"
    manifest = _base_manifest(0)
    ap._write_shard_manifest(path, manifest)
    loaded = ap._load_shard_manifest(path)

    assert loaded == {
        "schema_version": "2",
        "worklist_fingerprint": "f" * 64,
        "source_revision": "a" * 40,
        "shard_count": 14,
        "shard_index": 0,
        "assigned_identities": manifest["assigned_identities"],
        "attempted_identities": manifest["attempted_identities"],
        "report_identities": manifest["report_identities"],
        "artifacts": _manifest_artifacts(),
    }

    empty_path = tmp_path / "empty.json"
    ap._write_shard_manifest(
        empty_path,
        {
            "schema_version": "2",
            "worklist_fingerprint": "f" * 64,
            "source_revision": "b" * 40,
            "shard_count": 7,
            "shard_index": 3,
            "assigned_identities": [],
            "attempted_identities": [],
            "report_identities": [],
            "artifacts": _manifest_artifacts(),
        },
    )
    assert ap._load_shard_manifest(empty_path)["assigned_identities"] == []


def test_shard_manifest_v2_binds_and_verifies_all_worker_artifacts(tmp_path):
    artifact_paths = {}
    for name, content in {
        "progress": b'{"schema_version":"2"}\n',
        "report_json": b'{"reports":[]}\n',
        "report_markdown": b"# Empty\n",
        "verdict_delta": b"{}\n",
    }.items():
        path = tmp_path / f"{name}.bin"
        path.write_bytes(content)
        artifact_paths[name] = path

    manifest = _base_manifest(0)
    manifest["artifacts"] = {
        name: {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for name, path in artifact_paths.items()
    }

    assert ap._verify_shard_manifest_artifacts(manifest, artifact_paths) == manifest
    serialized = json.dumps(manifest, sort_keys=True)
    assert all(str(path) not in serialized for path in artifact_paths.values())

    artifact_paths["report_json"].write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="size mismatch|digest mismatch"):
        ap._verify_shard_manifest_artifacts(manifest, artifact_paths)


@pytest.mark.parametrize("artifact_name", ["report_json", "verdict_delta"])
def test_shard_manifest_single_artifact_verifier_binds_exact_bytes(
    tmp_path, artifact_name
):
    artifact_paths = {}
    for name in ap._SHARD_MANIFEST_ARTIFACT_KEYS:
        path = tmp_path / f"{name}.bin"
        path.write_bytes(f"{name}-exact".encode("utf-8"))
        artifact_paths[name] = path
    manifest = _base_manifest(0)
    manifest["artifacts"] = {
        name: {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for name, path in artifact_paths.items()
    }

    assert (
        ap._verify_shard_manifest_artifact(
            manifest, artifact_name, artifact_paths[artifact_name]
        )
        == manifest
    )

    swapped_name = "verdict_delta" if artifact_name == "report_json" else "report_json"
    with pytest.raises(ValueError, match="Artifact (size|digest) mismatch"):
        ap._verify_shard_manifest_artifact(
            manifest, artifact_name, artifact_paths[swapped_name]
        )

    artifact_paths[artifact_name].write_bytes(b"tampered")
    with pytest.raises(ValueError, match="Artifact (size|digest) mismatch"):
        ap._verify_shard_manifest_artifact(
            manifest, artifact_name, artifact_paths[artifact_name]
        )


def test_shard_manifest_single_artifact_verifier_rejects_unknown_artifact_name(
    tmp_path,
):
    path = tmp_path / "artifact.bin"
    path.write_bytes(b"artifact")
    manifest = _base_manifest(0)

    with pytest.raises(ValueError, match="Unknown shard manifest artifact"):
        ap._verify_shard_manifest_artifact(manifest, "not-an-artifact", path)


def test_shard_manifest_loader_rejects_duplicate_json_schema_keys(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version":"2","schema_version":"2"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate key"):
        ap._load_shard_manifest(path)


@pytest.mark.parametrize(
    "artifact_name",
    ["progress", "report_json", "report_markdown", "verdict_delta"],
)
def test_shard_manifest_verifier_rejects_each_independently_tampered_artifact(
    tmp_path, artifact_name
):
    artifact_paths = {}
    for name in ap._SHARD_MANIFEST_ARTIFACT_KEYS:
        path = tmp_path / f"{name}.bin"
        path.write_bytes(f"{name}-original".encode("utf-8"))
        artifact_paths[name] = path
    manifest = _base_manifest(0)
    manifest["artifacts"] = {
        name: {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
        }
        for name, path in artifact_paths.items()
    }

    target = artifact_paths[artifact_name]
    target.write_bytes(b"x" * target.stat().st_size)
    with pytest.raises(ValueError, match="digest mismatch"):
        ap._verify_shard_manifest_artifacts(manifest, artifact_paths)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda manifest: manifest.pop("artifacts"),
        lambda manifest: manifest["artifacts"].pop("progress"),
        lambda manifest: manifest["artifacts"].__setitem__(
            "extra", _manifest_artifacts()["progress"]
        ),
        lambda manifest: manifest["artifacts"].__setitem__(
            "progress", {"sha256": "A" * 64, "size_bytes": 0}
        ),
        lambda manifest: manifest["artifacts"].__setitem__(
            "progress", {"sha256": "a" * 64, "size_bytes": -1}
        ),
    ],
)
def test_shard_manifest_v2_rejects_malformed_artifact_bindings(mutate):
    manifest = _base_manifest(0)
    mutate(manifest)

    with pytest.raises(ValueError, match="artifact|Artifact|Missing|Unexpected"):
        ap._normalise_shard_manifest(manifest)


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
                "schema_version": "2",
                "worklist_fingerprint": "not-a-fingerprint",
                "source_revision": "a" * 40,
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
                "artifacts": _manifest_artifacts(),
            },
        )

    with pytest.raises(ValueError, match="source_revision"):
        ap._write_shard_manifest(
            path,
            {
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "short",
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
                "artifacts": _manifest_artifacts(),
            },
        )


@pytest.mark.parametrize(
    ("repository", "release_id", "asset_id"),
    [
        ("https://github.com/OWNER/repo", "1", "10"),
        ("https://github.com/owner/repo", "01", "10"),
        ("https://github.com/owner/repo", "1", "01"),
        ("https://github.com/owner/repo", " 1", "10"),
        ("https://github.com/owner/repo", "1", " 10"),
        ("https://github.com/owner/repo", "０", "10"),
        ("https://github.com/owner/repo", "1", "１"),
    ],
)
def test_shard_manifest_rejects_non_canonical_identities(
    tmp_path, repository, release_id, asset_id
):
    identity = {
        "repository": repository,
        "github_release_id": release_id,
        "asset_id": asset_id,
    }

    with pytest.raises(
        ValueError, match="Repository URL is not canonical|github_release_id|asset_id"
    ):
        ap._normalise_shard_manifest(
            {
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [identity],
                "attempted_identities": [identity],
                "report_identities": [identity],
                "artifacts": _manifest_artifacts(),
            }
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
                "schema_version": "2",
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
                "artifacts": _manifest_artifacts(),
            }
        )

    with pytest.raises(ValueError, match="Duplicate identity"):
        ap._normalise_shard_manifest(
            {
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": shard_index,
                "assigned_identities": [first, first],
                "attempted_identities": [first],
                "report_identities": [first],
                "artifacts": _manifest_artifacts(),
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
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": index,
                "assigned_identities": [first, second],
                "attempted_identities": [first, second],
                "report_identities": [first],
                "artifacts": _manifest_artifacts(),
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
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": 2,
                "shard_index": 1,
                "assigned_identities": [],
                "attempted_identities": [],
                "report_identities": [],
                "artifacts": _manifest_artifacts(),
            },
        )

    assert not path.exists()


def test_shard_manifest_preserves_supplied_identity_order(tmp_path):
    shard_index = 0
    path, _fingerprint = _build_worklist(tmp_path)
    worklist_doc = audit_worklist.load_worklist_document(path)
    payload = worklist_doc["payload"]
    one_digit, two_digit = _find_same_shard_release_pair_for_order_probe(
        shard_index,
        payload["shard_count"],
        "https://github.com/owner/repo",
    )
    manifest = _make_shard_manifest(
        shard_index=shard_index,
        assigned=[one_digit, two_digit],
        attempt=[one_digit, two_digit],
        report=[one_digit, two_digit],
        fingerprint=worklist_doc["fingerprint"],
        source_revision=payload["source_revision"],
        shard_count=payload["shard_count"],
    )
    path = tmp_path / "ordered.json"
    ap._write_shard_manifest(path, manifest)
    loaded = ap._load_shard_manifest(path)
    assert loaded["assigned_identities"] == [one_digit, two_digit]
    assert loaded["attempted_identities"] == [one_digit, two_digit]
    assert loaded["report_identities"] == [one_digit, two_digit]


def test_shard_manifest_rejects_partial_report_order_mismatch(tmp_path):
    shard_count = 14
    shard_index = 0
    first = _manifest_identity_for_shard(
        shard_index, shard_count, "https://github.com/owner/repo"
    )
    second = _manifest_identity_for_shard(
        shard_index, shard_count, "https://github.com/owner/other"
    )
    with pytest.raises(
        ValueError, match="report_identities must equal attempted_identities"
    ):
        ap._normalise_shard_manifest(
            {
                "schema_version": "2",
                "worklist_fingerprint": "a" * 64,
                "source_revision": "a" * 40,
                "shard_count": shard_count,
                "shard_index": shard_index,
                "assigned_identities": [first, second],
                "attempted_identities": [first, second],
                "report_identities": [second, first],
                "artifacts": _manifest_artifacts(),
            }
        )


def test_validate_expected_shard_manifest_rejects_all_expected_mismatches(tmp_path):
    path, _fp = _build_worklist(tmp_path)
    worklist_doc = audit_worklist.load_worklist_document(path)
    payload = worklist_doc["payload"]
    non_empty = None
    for shard_index in range(payload["shard_count"]):
        identities = _expected_assigned_identities(worklist_doc, shard_index)
        if identities:
            non_empty = shard_index
            break
    assert non_empty is not None
    manifest = _make_valid_manifest_for_expected_shard(
        worklist_doc,
        non_empty,
    )
    ap._validate_expected_shard_manifest(manifest, worklist_doc, non_empty)

    with pytest.raises(
        ValueError, match="Invalid shard manifest: source_revision mismatch"
    ):
        ap._validate_expected_shard_manifest(
            _make_valid_manifest_for_expected_shard(
                worklist_doc, non_empty, source_revision="b" * 40
            ),
            worklist_doc,
            non_empty,
        )

    with pytest.raises(
        ValueError, match="Invalid shard manifest: worklist_fingerprint mismatch"
    ):
        ap._validate_expected_shard_manifest(
            _make_valid_manifest_for_expected_shard(
                worklist_doc, non_empty, fingerprint="b" * 64
            ),
            worklist_doc,
            non_empty,
        )

    with pytest.raises(
        ValueError, match="Invalid shard manifest: shard_count mismatch"
    ):
        ap._validate_expected_shard_manifest(
            _make_valid_manifest_for_expected_shard(
                worklist_doc,
                non_empty,
                shard_count=payload["shard_count"] + 1,
                assigned=[],
                attempted=[],
                report=[],
            ),
            worklist_doc,
            non_empty,
        )

    with pytest.raises(
        ValueError, match="Invalid shard manifest: shard_index mismatch"
    ):
        ap._validate_expected_shard_manifest(
            _make_valid_manifest_for_expected_shard(
                worklist_doc,
                non_empty,
                shard_count=payload["shard_count"],
                assigned=[],
                attempted=[],
                report=[],
            )
            | {"shard_index": (non_empty + 1) % payload["shard_count"]},
            worklist_doc,
            non_empty,
        )

    mismatch_assigned = list(manifest["assigned_identities"])
    mismatch_assigned[0] = _alternate_identity_same_shard(
        non_empty, payload["shard_count"], mismatch_assigned[0]
    )
    with pytest.raises(
        ValueError, match="Invalid shard manifest: assigned_identities mismatch"
    ):
        ap._validate_expected_shard_manifest(
            _make_valid_manifest_for_expected_shard(
                worklist_doc, non_empty, assigned=mismatch_assigned
            ),
            worklist_doc,
            non_empty,
        )


def test_validate_expected_shard_manifest_supports_empty_shards(tmp_path):
    path, _fp = _build_worklist(tmp_path)
    worklist_doc = audit_worklist.load_worklist_document(path)
    payload = worklist_doc["payload"]
    empty_index = next(
        i
        for i in range(payload["shard_count"])
        if not _expected_assigned_identities(worklist_doc, i)
    )
    manifest = _make_valid_manifest_for_expected_shard(
        worklist_doc,
        empty_index,
        assigned=[],
        attempted=[],
        report=[],
    )
    ap._validate_expected_shard_manifest(manifest, worklist_doc, empty_index)
