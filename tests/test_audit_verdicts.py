import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

import audit_plugins as ap

REPOSITORY = "https://github.com/owner/plugin"


def _release(tag: str, asset_id: int) -> dict:
    return {
        "tag_name": tag,
        "prerelease": False,
        "assets": [
            {
                "name": "plugin.zip",
                "id": asset_id,
                "browser_download_url": f"https://example.com/{tag}.zip",
            }
        ],
    }


def _zip_bytes(*, traversal: bool = False) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        if traversal:
            archive.writestr("../escape.py", "print('blocked')")
        else:
            archive.writestr(
                "plugin/plugin.json",
                json.dumps({"name": "Plugin", "flags": []}),
            )
            archive.writestr("plugin/main.py", "print('clean')\n")
    return buffer.getvalue()


def _policy() -> dict:
    policy = ap._default_policy()
    for scanner in policy["scanners"].values():
        scanner["required"] = False
    return policy


def _configure_successful_audit(monkeypatch, zip_data: bytes) -> None:
    monkeypatch.setattr(
        ap,
        "_resolve_ref_to_commit_and_tree_sha",
        lambda _owner, _repo, ref: (f"commit-{ref}", f"tree-{ref}", None),
    )
    monkeypatch.setattr(ap, "get_repo_metadata", lambda *_args: {"archived": False})
    monkeypatch.setattr(ap, "get_repo_file_raw", lambda *_args: None)

    def download(_url: str, destination: str) -> str:
        Path(destination).write_bytes(zip_data)
        return hashlib.sha256(zip_data).hexdigest()

    monkeypatch.setattr(ap, "download_zip", download)
    monkeypatch.setattr(
        ap,
        "run_clamav",
        lambda *_args: (ap.ScannerStatus(name="clamav", status="passed"), []),
    )
    monkeypatch.setattr(
        ap,
        "run_trivy",
        lambda *_args: (ap.ScannerStatus(name="trivy", status="passed"), []),
    )
    monkeypatch.setattr(
        ap,
        "run_semgrep",
        lambda *_args: (ap.ScannerStatus(name="semgrep", status="skipped"), []),
    )
    monkeypatch.setattr(
        ap,
        "compare_source_and_artifact",
        lambda *_args: (
            {"checked": True},
            [],
            ap.ScannerStatus(name="source-artifact-diff", status="passed"),
        ),
    )


def _seed_pass_verdict(cache_dir: Path, release_id: str) -> dict:
    verdicts = {
        REPOSITORY: {
            release_id: {
                "classification": "PASS",
                "blocking_rule_ids": [],
                "artifact_sha256": "a" * 64,
                "audit_context_hash": "prior-context",
                "audited_at": "2026-08-01T00:00:00Z",
            }
        }
    }
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / "verdicts.json").write_text(json.dumps(verdicts), encoding="utf-8")
    return verdicts


def test_audit_release_audits_the_exact_release_passed(monkeypatch, tmp_path):
    older = _release("v1.0.0", 1)
    _configure_successful_audit(monkeypatch, _zip_bytes())
    monkeypatch.setattr(
        ap,
        "get_releases",
        lambda *_args: pytest.fail("audit_release must not select another release"),
    )

    report = ap.audit_release(
        REPOSITORY,
        older,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )

    assert report.release == "v1.0.0"
    assert report.release_id == "v1.0.0@1"


def test_audit_repository_selects_then_delegates(monkeypatch, tmp_path):
    older = _release("v1.0.0", 1)
    newer = _release("v2.0.0", 2)
    delegated = ap.AuditReport(release="v2.0.0", final_classification="PASS")
    seen = {}

    monkeypatch.setattr(ap, "get_repo_metadata", lambda *_args: {"archived": False})
    monkeypatch.setattr(ap, "get_releases", lambda *_args: [older, newer])

    def audit_release(
        repo_url, release, policy, exceptions, cache_dir, skip_cache, **kwargs
    ):
        seen.update(
            repo_url=repo_url, release=release, metadata=kwargs.get("_repo_metadata")
        )
        return delegated

    monkeypatch.setattr(ap, "audit_release", audit_release)

    result = ap.audit_repository(
        REPOSITORY,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )

    assert result is delegated
    assert seen["repo_url"] == REPOSITORY
    assert seen["release"] is newer
    assert seen["metadata"] == {"archived": False}


def test_audit_error_preserves_good_verdict_and_reports_both_states(
    monkeypatch, tmp_path
):
    release = _release("v1.0.0", 1)
    _seed_pass_verdict(tmp_path, "v1.0.0@1")
    _configure_successful_audit(monkeypatch, _zip_bytes())
    monkeypatch.setattr(
        ap, "download_zip", lambda *_args: (_ for _ in ()).throw(OSError("offline"))
    )

    report = ap.audit_release(
        REPOSITORY,
        release,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )
    verdicts = ap.load_verdicts(str(tmp_path))
    result = ap.classification_for(REPOSITORY, report, verdicts)

    assert verdicts[REPOSITORY]["v1.0.0@1"]["classification"] == "PASS"
    assert result.effective_classification == "PASS"
    assert result.audit_classification == "AUDIT_ERROR"


def test_completed_audit_error_does_not_overwrite_good_verdict(monkeypatch, tmp_path):
    release = _release("v1.0.0", 1)
    prior = _seed_pass_verdict(tmp_path, "v1.0.0@1")
    _configure_successful_audit(monkeypatch, _zip_bytes())
    monkeypatch.setattr(
        ap,
        "run_trivy",
        lambda *_args: (
            ap.ScannerStatus(name="trivy", status="failed", detail="scanner failed"),
            [],
        ),
    )
    policy = _policy()
    policy["scanners"]["trivy"]["required"] = True

    report = ap.audit_release(
        REPOSITORY,
        release,
        policy,
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )

    assert report.final_classification == "AUDIT_ERROR"
    assert ap.load_verdicts(str(tmp_path)) == prior


def test_first_seen_audit_error_is_not_laundered_into_pass(monkeypatch, tmp_path):
    release = _release("v1.0.0", 1)
    _configure_successful_audit(monkeypatch, _zip_bytes())
    monkeypatch.setattr(
        ap, "download_zip", lambda *_args: (_ for _ in ()).throw(OSError("offline"))
    )

    report = ap.audit_release(
        REPOSITORY,
        release,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )
    result = ap.classification_for(REPOSITORY, report, ap.load_verdicts(str(tmp_path)))

    assert result.effective_classification == "AUDIT_ERROR"
    assert result.audit_classification == "AUDIT_ERROR"


def test_blocking_rule_ids_survive_verdict_round_trip(monkeypatch, tmp_path):
    release = _release("v1.0.0", 1)
    _configure_successful_audit(monkeypatch, _zip_bytes(traversal=True))

    report = ap.audit_release(
        REPOSITORY,
        release,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )
    verdicts = ap.load_verdicts(str(tmp_path))
    result = ap.classification_for(REPOSITORY, report, verdicts)

    assert result.effective_classification == "BLOCK"
    assert result.blocking_rule_ids
    assert "ARCHIVE_TRAVERSAL" in result.blocking_rule_ids
    assert verdicts[REPOSITORY]["v1.0.0@1"]["blocking_rule_ids"] == [
        "ARCHIVE_TRAVERSAL"
    ]


def test_atomic_write_failure_preserves_prior_verdict_file(monkeypatch, tmp_path):
    prior = _seed_pass_verdict(tmp_path, "v1.0.0@1")
    replacement = {
        **prior,
        REPOSITORY: {
            **prior[REPOSITORY],
            "v2.0.0@2": {
                "classification": "BLOCK",
                "blocking_rule_ids": ["STATIC_EVAL"],
                "artifact_sha256": "b" * 64,
                "audit_context_hash": "new-context",
                "audited_at": "2026-08-02T00:00:00Z",
            },
        },
    }
    monkeypatch.setattr(
        ap.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError())
    )

    with pytest.raises(OSError):
        ap._write_verdicts_atomic(replacement)

    assert json.loads((tmp_path / "verdicts.json").read_text(encoding="utf-8")) == prior


def test_two_release_round_trip_negative_control(monkeypatch, tmp_path):
    first = _release("v1.0.0", 1)
    second = _release("v2.0.0", 2)
    _configure_successful_audit(monkeypatch, _zip_bytes())

    first_report = ap.audit_release(
        REPOSITORY,
        first,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )
    second_report = ap.audit_release(
        REPOSITORY,
        second,
        _policy(),
        [],
        cache_dir=str(tmp_path),
        skip_cache=True,
    )
    verdicts = ap.load_verdicts(str(tmp_path))

    assert first_report.final_classification == "PASS"
    assert second_report.final_classification == "PASS"
    assert set(verdicts[REPOSITORY]) == {"v1.0.0@1", "v2.0.0@2"}
    for release in (first, second):
        result = ap.classification_for(REPOSITORY, release, verdicts)
        assert result.effective_classification == "PASS"
        assert result.audit_classification == "PASS"
        assert result.blocking_rule_ids == []
