import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import audit_plugins as ap
import check_for_updates
import generate_json
import plugin_release_utils as pru

REPOSITORY = "https://github.com/owner/plugin"
ARTIFACT_URL = "https://github.com/owner/plugin/releases/download/v1.0.0/plugin.zip"
CALLERS = (
    "release-audit",
    "generator-hash",
    "upstream-reconciliation",
    "update-detection",
)

BOUNDARY_CASES = (
    {"name": "oversized-content-length", "header": "oversized"},
    {"name": "absent-length-overflow", "header": None},
    {"name": "understated-length-overflow", "header": "understated"},
    {"name": "malformed-length-overflow", "header": "malformed"},
    {"name": "negative-length-overflow", "header": "negative"},
    {"name": "chunk-crosses-limit", "header": "at-limit", "split": True},
    {"name": "limit-minus-one", "success": True, "headroom": 1},
    {"name": "exact-limit", "success": True, "headroom": 0},
)


class FakeResponse:
    def __init__(self, headers, chunks):
        self.headers = headers
        self.chunks = chunks
        self.iterated = False
        self.closed = False
        self.requested_chunk_sizes = []

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        self.iterated = True
        self.requested_chunk_sizes.append(chunk_size)
        yield from self.chunks

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def _release():
    return {
        "id": 101,
        "tag_name": "v1.0.0",
        "prerelease": False,
        "published_at": "2026-08-08T00:00:00Z",
        "assets": [
            {
                "id": 7,
                "name": "plugin.zip",
                "browser_download_url": ARTIFACT_URL,
            }
        ],
    }


def _release_zip_bytes():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(
            "plugin/plugin.json",
            json.dumps({"name": "Plugin", "flags": []}),
        )
        archive.writestr("plugin/main.py", "print('clean')\n")
    return stream.getvalue()


def _payload_for(caller):
    if caller in {"release-audit", "generator-hash"}:
        return _release_zip_bytes()
    return b"current catalog artifact bytes\n"


def _response_and_limit(payload, case):
    if case.get("success", False):
        limit = len(payload) + case["headroom"]
        return FakeResponse({"Content-Length": str(len(payload))}, [payload]), limit

    limit = len(payload) - 1
    header = case["header"]
    if header == "oversized":
        content_length = str(len(payload))
    elif header == "understated":
        content_length = str(limit - 1)
    elif header == "malformed":
        content_length = "not-a-number"
    elif header == "negative":
        content_length = "-1"
    elif header == "at-limit":
        content_length = str(limit)
    else:
        content_length = None

    headers = {} if content_length is None else {"Content-Length": content_length}
    chunks = [payload]
    if case.get("split"):
        chunks = [payload[:limit], payload[limit:]]
    return FakeResponse(headers, chunks), limit


def _download_policy(caller, target_limit):
    policy = ap._default_policy()
    release_limit = target_limit
    source_limit = target_limit
    policy["downloads"].update(
        {
            "release_max_bytes": release_limit,
            "source_max_bytes": source_limit,
            "connect_timeout_seconds": 2,
            "read_timeout_seconds": 3,
            "chunk_size_bytes": 4,
        }
    )
    for scanner in policy["scanners"].values():
        scanner["enabled"] = False
        scanner["required"] = False
    return policy


def _retain_generator_download(monkeypatch, root):
    class RetainedTemporaryDirectory:
        def __init__(self, *_args, **_kwargs):
            root.mkdir(parents=True, exist_ok=True)
            self.name = str(root)

        def __enter__(self):
            return self.name

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        generate_json.tempfile,
        "TemporaryDirectory",
        RetainedTemporaryDirectory,
    )


def _seed_prior_verdict(path):
    path.write_text(
        json.dumps(
            {
                REPOSITORY: {
                    "v1.0.0@7": {
                        "classification": "PASS",
                        "blocking_rule_ids": [],
                        "artifact_sha256": "a" * 64,
                        "audit_context_hash": "prior-context",
                        "audited_at": "2026-08-01T00:00:00Z",
                    }
                }
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _forbid_downstream(probes, name):
    def forbidden(*_args, **_kwargs):
        probes.append(name)
        pytest.fail(f"{name} must not run after a bounded download failure")

    return forbidden


def _invoke_release_audit(monkeypatch, tmp_path, session, policy, should_succeed):
    work_root = tmp_path / "release-audit-work"
    cache_dir = tmp_path / "audit-cache"
    verdict_path = Path(ap.VERDICTS_FILE)
    _seed_prior_verdict(verdict_path)
    prior_verdict = verdict_path.read_bytes()
    probes = []

    monkeypatch.setattr(ap, "_gh_session", session)
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda _owner, _repo, _ref: ("commit-sha", "tree-sha", None),
    )
    monkeypatch.setattr(ap.tempfile, "mkdtemp", lambda **_kwargs: str(work_root))
    if not should_succeed:
        for name in (
            "inspect_zip",
            "safe_extract_zip",
            "run_trivy",
            "run_clamav",
            "run_semgrep",
            "compare_source_and_artifact_from_snapshot",
        ):
            monkeypatch.setattr(ap, name, _forbid_downstream(probes, name))

    report = ap.audit_release(
        REPOSITORY,
        _release(),
        policy,
        [],
        cache_dir=str(cache_dir),
        _repo_metadata={"archived": False},
        _policy_path=None,
        _allowlist_path=None,
    )

    if should_succeed:
        return {
            "sha": report.artifact_sha256,
            "safe_value": report,
            "destination": work_root / "release.zip",
            "downloaded_bytes": None,
            "probes": probes,
        }

    assert verdict_path.read_bytes() == prior_verdict
    assert list(cache_dir.rglob("*.json")) == []
    return {
        "failure": report,
        "safe_value": None,
        "destination": work_root / "release.zip",
        "downloaded_bytes": None,
        "probes": probes,
    }


def _invoke_generator_hash(monkeypatch, tmp_path, session, policy):
    work_root = tmp_path / "generator-hash-work"
    _retain_generator_download(monkeypatch, work_root)
    monkeypatch.setattr(generate_json, "anon_session", session)
    try:
        version = generate_json.build_version_object(_release(), policy=policy)
    except Exception as exc:
        return {
            "failure": exc,
            "safe_value": None,
            "destination": work_root / "release.zip",
            "downloaded_bytes": None,
            "probes": [],
        }

    destination = work_root / "release.zip"
    return {
        "sha": version["hash"],
        "safe_value": version,
        "destination": destination,
        "downloaded_bytes": destination.read_bytes(),
        "probes": [],
    }


def _upstream_plugin():
    return {
        "name": "Plugin",
        "versions": [
            {
                "name": "1.0.0",
                "hash": "a" * 64,
                "artifact": ARTIFACT_URL,
            }
        ],
    }


def _invoke_upstream_reconciliation(
    monkeypatch, tmp_path, session, policy, expected_sha
):
    work_root = tmp_path / "upstream-reconciliation-work"
    _retain_generator_download(monkeypatch, work_root)
    monkeypatch.setattr(generate_json, "anon_session", session)
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [_upstream_plugin()])
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [_release()])
    try:
        missing = check_for_updates.check_upstream(
            {"Plugin": {("1.0.0", expected_sha)}},
            {},
            set(),
            download_policy=policy,
        )
    except Exception as exc:
        return {
            "failure": exc,
            "safe_value": None,
            "destination": work_root / "release.zip",
            "downloaded_bytes": None,
            "probes": [],
        }

    destination = work_root / "release.zip"
    assert missing == []
    return {
        "sha": expected_sha,
        "safe_value": missing,
        "destination": destination,
        "downloaded_bytes": destination.read_bytes(),
        "probes": [],
    }


def _invoke_update_detection(monkeypatch, tmp_path, session, policy, expected_sha):
    work_root = tmp_path / "update-detection-work"
    _retain_generator_download(monkeypatch, work_root)
    monkeypatch.setattr(generate_json, "anon_session", session)
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json,
        "get_plugin_json",
        lambda *_args: {"name": "Plugin"},
    )
    monkeypatch.setattr(
        generate_json,
        "get_package_json",
        lambda *_args: {"name": "plugin"},
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [_release()])
    try:
        missing = check_for_updates.check_custom_repos(
            {"Plugin": {("1.0.0", expected_sha)}},
            {},
            set(),
            download_policy=policy,
        )
    except Exception as exc:
        return {
            "failure": exc,
            "safe_value": None,
            "destination": work_root / "release.zip",
            "downloaded_bytes": None,
            "probes": [],
        }

    destination = work_root / "release.zip"
    assert missing == []
    return {
        "sha": expected_sha,
        "safe_value": missing,
        "destination": destination,
        "downloaded_bytes": destination.read_bytes(),
        "probes": [],
    }


def _invoke_caller(
    caller, monkeypatch, tmp_path, session, policy, should_succeed, expected_sha
):
    if caller == "release-audit":
        return _invoke_release_audit(
            monkeypatch, tmp_path, session, policy, should_succeed
        )
    if caller == "generator-hash":
        return _invoke_generator_hash(monkeypatch, tmp_path, session, policy)
    if caller == "upstream-reconciliation":
        return _invoke_upstream_reconciliation(
            monkeypatch, tmp_path, session, policy, expected_sha
        )
    return _invoke_update_detection(
        monkeypatch, tmp_path, session, policy, expected_sha
    )


@pytest.mark.parametrize("caller", CALLERS)
@pytest.mark.parametrize(
    "case",
    BOUNDARY_CASES,
    ids=[case["name"] for case in BOUNDARY_CASES],
)
def test_bounded_download_boundary_matrix(caller, case, monkeypatch, tmp_path):
    payload = _payload_for(caller)
    response, target_limit = _response_and_limit(payload, case)
    policy = _download_policy(caller, target_limit)
    session = FakeSession(response)
    expected_sha = hashlib.sha256(payload).hexdigest()

    downloads = policy["downloads"]
    assert downloads["release_max_bytes"] != pru.DEFAULT_RELEASE_MAX_BYTES
    assert downloads["source_max_bytes"] != pru.DEFAULT_SOURCE_MAX_BYTES

    result = _invoke_caller(
        caller,
        monkeypatch,
        tmp_path,
        session,
        policy,
        case.get("success", False),
        expected_sha,
    )

    assert len(session.calls) == 1
    url, request_kwargs = session.calls[0]
    expected_url = ARTIFACT_URL
    assert url == expected_url
    assert request_kwargs == {"stream": True, "timeout": (2, 3)}
    assert response.closed is True

    if case.get("success", False):
        assert result["safe_value"] is not None
        assert result["sha"] == expected_sha
        if caller == "release-audit":
            assert result["safe_value"].archive_stats.sha256 == expected_sha
        if result["downloaded_bytes"] is not None:
            assert result["downloaded_bytes"] == payload
        assert response.iterated is True
        assert response.requested_chunk_sizes == [4]
    else:
        assert result["safe_value"] is None
        assert not result["destination"].exists()
        assert list(tmp_path.rglob("*.part")) == []
        assert result["probes"] == []
        assert not (tmp_path / "public").exists()
        if caller == "release-audit":
            report = result["failure"]
            assert report.final_classification == "AUDIT_ERROR"
            assert report.completion_status == "incomplete"
            assert report.error_scope == "release"
            assert any("exceeds" in error for error in report.errors)
        else:
            assert isinstance(result["failure"], generate_json.ArtifactDownloadError)
        assert "exceeds" in str(result["failure"])

        if case["name"] == "oversized-content-length":
            assert response.iterated is False
            assert response.requested_chunk_sizes == []
        else:
            assert response.iterated is True
            assert response.requested_chunk_sizes == [4]
