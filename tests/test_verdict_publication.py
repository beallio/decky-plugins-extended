import json
import shutil
import subprocess

import audit_plugins as ap

REPOSITORY = "https://github.com/owner/plugin"


def _verdict(*, classification="PASS", audited_at="2026-08-03T00:00:00Z"):
    return {
        REPOSITORY: {
            "v1.0.0@1": {
                "classification": classification,
                "blocking_rule_ids": [],
                "artifact_sha256": "a" * 64,
                "audit_context_hash": "context",
                "audited_at": audited_at,
            }
        }
    }


def _report(*, classification="PASS", audited_at="2026-08-03T00:00:00Z"):
    return ap.AuditReport(
        audit_timestamp=audited_at,
        repository=REPOSITORY,
        release="v1.0.0",
        release_id="v1.0.0@1",
        artifact_sha256="a" * 64,
        audit_context_hash="context",
        final_classification=classification,
    )


def test_loads_tracked_verdicts_without_audit_cache(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    cache_dir.mkdir()
    shutil.rmtree(cache_dir)
    tracked.write_text(json.dumps(_verdict()), encoding="utf-8")
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    assert ap.load_verdicts(str(cache_dir)) == _verdict()
    assert not cache_dir.exists()


def test_tracked_verdicts_win_over_legacy_cache(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    cache_dir.mkdir()
    tracked.write_text(json.dumps(_verdict(classification="BLOCK")), encoding="utf-8")
    (cache_dir / "verdicts.json").write_text(
        json.dumps(_verdict(classification="PASS")), encoding="utf-8"
    )
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    loaded = ap.load_verdicts(str(cache_dir))

    assert loaded[REPOSITORY]["v1.0.0@1"]["classification"] == "BLOCK"


def test_legacy_cache_is_fallback_when_tracked_store_is_absent(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    cache_dir.mkdir()
    legacy = _verdict()
    (cache_dir / "verdicts.json").write_text(json.dumps(legacy), encoding="utf-8")
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    assert ap.load_verdicts(str(cache_dir)) == legacy


def test_unchanged_verdict_preserves_identical_bytes_and_timestamp(
    monkeypatch, tmp_path
):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    ap._record_verdict(str(cache_dir), _report())
    initial_bytes = tracked.read_bytes()

    unchanged = _report(audited_at="2026-08-03T06:00:00Z")
    unchanged.audit_context_hash = "new-context"
    ap._record_verdict(str(cache_dir), unchanged)

    assert tracked.read_bytes() == initial_bytes
    persisted = json.loads(tracked.read_text(encoding="utf-8"))
    assert persisted[REPOSITORY]["v1.0.0@1"]["audited_at"] == ("2026-08-03T00:00:00Z")

    ap._record_verdict(
        str(cache_dir),
        _report(classification="MANUAL_REVIEW", audited_at="2026-08-03T12:00:00Z"),
    )

    assert tracked.read_bytes() != initial_bytes
    assert tracked.read_bytes().endswith(b"\n")
    changed = json.loads(tracked.read_text(encoding="utf-8"))
    assert changed[REPOSITORY]["v1.0.0@1"]["audited_at"] == ("2026-08-03T12:00:00Z")


def test_workflow_diff_probe_distinguishes_unchanged_and_changed_store(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    verdict_path = repository / "security-verdicts.json"
    verdict_path.write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "add", "security-verdicts.json"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=repository,
        check=True,
    )

    unchanged = subprocess.run(
        ["git", "diff", "--quiet", "--", "security-verdicts.json"],
        cwd=repository,
        check=False,
    )
    verdict_path.write_text(json.dumps(_verdict()) + "\n", encoding="utf-8")
    changed = subprocess.run(
        ["git", "diff", "--quiet", "--", "security-verdicts.json"],
        cwd=repository,
        check=False,
    )

    assert unchanged.returncode == 0
    assert changed.returncode == 1
