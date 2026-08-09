import hashlib
import json
import shutil
import subprocess

import pytest

import audit_plugins as ap

REPOSITORY = "https://github.com/owner/plugin"


def _verdict(
    *,
    classification="PASS",
    audit_context_hash="context",
    audited_at="2026-08-03T00:00:00Z",
):
    return {
        REPOSITORY: {
            "v1.0.0@1": {
                "classification": classification,
                "blocking_rule_ids": [],
                "artifact_sha256": "a" * 64,
                "audit_context_hash": audit_context_hash,
                "audited_at": audited_at,
            }
        }
    }


def _report(
    *,
    classification="PASS",
    audit_context_hash="context",
    audited_at="2026-08-03T00:00:00Z",
    findings=None,
):
    return ap.AuditReport(
        audit_timestamp=audited_at,
        repository=REPOSITORY,
        release="v1.0.0",
        release_id="v1.0.0@1",
        artifact_sha256="a" * 64,
        audit_context_hash=audit_context_hash,
        final_classification=classification,
        findings=findings or [],
    )


def _finding(
    rule_id,
    classification,
    *,
    evidence="fixture evidence",
    allowlisted=False,
):
    return ap.Finding(
        rule_id=rule_id,
        severity="medium",
        classification=classification,
        path="plugin/main.py",
        line=1,
        message="fixture finding",
        evidence=evidence,
        scanner="fixture",
        allowlisted=allowlisted,
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


def test_missing_tracked_store_is_empty_and_ignores_legacy_cache(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    cache_dir.mkdir()
    legacy = _verdict()
    (cache_dir / "verdicts.json").write_text(json.dumps(legacy), encoding="utf-8")
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    assert ap.load_verdicts(str(cache_dir)) == {}


@pytest.mark.parametrize(
    "payload, message",
    (
        ("{not-json", "valid JSON"),
        ([], "root"),
        ({REPOSITORY: []}, "repository"),
        ({REPOSITORY: {"v1@1": []}}, "release record"),
        ({REPOSITORY: {"invalid": {"classification": "PASS"}}}, "release key"),
        (
            {REPOSITORY: {"v1@1": {"classification": "NOT_A_VERDICT"}}},
            "classification",
        ),
        ({REPOSITORY: {"v1@1": {"classification": 1}}}, "classification"),
        (
            {
                REPOSITORY: {
                    "v1@1": {
                        "classification": "PASS",
                        "blocking_rule_ids": "RULE",
                    }
                }
            },
            "blocking_rule_ids",
        ),
        (
            {
                REPOSITORY: {
                    "v1@1": {
                        "classification": "PASS",
                        "review_rule_ids": [1],
                    }
                }
            },
            "review_rule_ids",
        ),
        (
            {
                REPOSITORY: {
                    "v1@1": {
                        "classification": "PASS",
                        "artifact_sha256": "A" * 64,
                    }
                }
            },
            "artifact_sha256",
        ),
    ),
)
def test_invalid_nested_verdict_state_fails_closed(
    monkeypatch, tmp_path, payload, message
):
    tracked = tmp_path / "security-verdicts.json"
    if isinstance(payload, str):
        tracked.write_text(payload, encoding="utf-8")
    else:
        tracked.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    with pytest.raises(ValueError, match=message):
        ap.load_verdicts(str(tmp_path / ".audit-cache"))


def test_legacy_record_without_artifact_sha_is_valid(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    legacy = _verdict()
    del legacy[REPOSITORY]["v1.0.0@1"]["artifact_sha256"]
    tracked.write_text(json.dumps(legacy), encoding="utf-8")
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    assert ap.load_verdicts(str(tmp_path / ".audit-cache")) == legacy


def test_verdict_records_sorted_deduplicated_rationale_rule_ids(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))
    findings = [
        _finding("BLOCK_Z", "BLOCK"),
        _finding("BLOCK_A", "BLOCK"),
        _finding("BLOCK_Z", "BLOCK"),
        _finding("REVIEW_Z", "MANUAL_REVIEW"),
        _finding("REVIEW_A", "MANUAL_REVIEW"),
        _finding("REVIEW_Z", "MANUAL_REVIEW"),
        _finding("WARNING_Z", "PASS_WITH_WARNINGS"),
        _finding("WARNING_A", "PASS_WITH_WARNINGS"),
        _finding("WARNING_Z", "PASS_WITH_WARNINGS"),
    ]

    ap._record_verdict(
        str(cache_dir),
        _report(classification="BLOCK", findings=findings),
    )

    record = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]
    assert record["blocking_rule_ids"] == ["BLOCK_A", "BLOCK_Z"]
    assert record["review_rule_ids"] == ["REVIEW_A", "REVIEW_Z"]
    assert record["warning_rule_ids"] == ["WARNING_A", "WARNING_Z"]


def test_allowlisted_findings_are_excluded_from_rationale(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))
    findings = [
        _finding("REVIEW_ALLOWED", "MANUAL_REVIEW", allowlisted=True),
        _finding("REVIEW_KEPT", "MANUAL_REVIEW"),
        _finding("WARNING_ALLOWED", "PASS_WITH_WARNINGS", allowlisted=True),
        _finding("WARNING_KEPT", "PASS_WITH_WARNINGS"),
    ]

    ap._record_verdict(
        str(cache_dir),
        _report(classification="MANUAL_REVIEW", findings=findings),
    )

    record = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]
    assert record["review_rule_ids"] == ["REVIEW_KEPT"]
    assert record["warning_rule_ids"] == ["WARNING_KEPT"]


def test_verdict_rationale_never_serializes_finding_evidence(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))
    secret = "ZXQVJPRKNFLBGHCM"

    ap._record_verdict(
        str(cache_dir),
        _report(
            classification="MANUAL_REVIEW",
            findings=[
                _finding("REVIEW_FIXTURE", "MANUAL_REVIEW", evidence=secret),
                _finding("WARNING_FIXTURE", "PASS_WITH_WARNINGS", evidence=secret),
            ],
        ),
    )

    serialized = tracked.read_text(encoding="utf-8")
    assert secret not in serialized
    assert all(secret[index : index + 4] not in serialized for index in range(13))
    assert hashlib.sha256(secret.encode()).hexdigest() not in serialized


def test_unchanged_old_shape_backfills_rationale_without_changing_timestamp(
    monkeypatch, tmp_path
):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))
    seed = _verdict(
        classification="MANUAL_REVIEW",
        audited_at="2026-08-02T00:00:00Z",
    )
    tracked.write_text(json.dumps(seed), encoding="utf-8")

    ap._record_verdict(
        str(cache_dir),
        _report(
            classification="MANUAL_REVIEW",
            audited_at="2026-08-03T12:00:00Z",
            findings=[
                _finding("REVIEW_REASON", "MANUAL_REVIEW"),
                _finding("WARNING_REASON", "PASS_WITH_WARNINGS"),
            ],
        ),
    )

    record = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]
    assert record["review_rule_ids"] == ["REVIEW_REASON"]
    assert record["warning_rule_ids"] == ["WARNING_REASON"]
    assert record["audited_at"] == "2026-08-02T00:00:00Z"


def test_unchanged_verdict_repairs_stale_rationale_without_changing_timestamp(
    monkeypatch, tmp_path
):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))
    seed = _verdict(
        classification="MANUAL_REVIEW",
        audited_at="2026-08-02T00:00:00Z",
    )
    record = seed[REPOSITORY]["v1.0.0@1"]
    record["review_rule_ids"] = ["STALE_REVIEW"]
    record["warning_rule_ids"] = ["STALE_WARNING"]
    tracked.write_text(json.dumps(seed), encoding="utf-8")

    ap._record_verdict(
        str(cache_dir),
        _report(
            classification="MANUAL_REVIEW",
            audited_at="2026-08-03T12:00:00Z",
            findings=[_finding("CURRENT_REVIEW", "MANUAL_REVIEW")],
        ),
    )

    record = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]
    assert record["review_rule_ids"] == ["CURRENT_REVIEW"]
    assert record["warning_rule_ids"] == []
    assert record["audited_at"] == "2026-08-02T00:00:00Z"


def test_unchanged_verdict_preserves_identical_bytes_without_writing(
    monkeypatch, tmp_path
):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    ap._record_verdict(str(cache_dir), _report())
    initial_bytes = tracked.read_bytes()
    write_calls = 0
    original_write = ap._write_verdicts_atomic

    def track_write(verdicts):
        nonlocal write_calls
        write_calls += 1
        original_write(verdicts)

    monkeypatch.setattr(ap, "_write_verdicts_atomic", track_write)

    ap._record_verdict(
        str(cache_dir),
        _report(audited_at="2026-08-03T06:00:00Z"),
    )

    assert tracked.read_bytes() == initial_bytes
    assert write_calls == 0
    persisted = json.loads(tracked.read_text(encoding="utf-8"))
    assert persisted[REPOSITORY]["v1.0.0@1"]["audited_at"] == ("2026-08-03T00:00:00Z")


def test_context_only_change_updates_hash_and_preserves_timestamp(
    monkeypatch, tmp_path
):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    ap._record_verdict(str(cache_dir), _report())
    initial = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]

    ap._record_verdict(
        str(cache_dir),
        _report(
            audit_context_hash="new-context",
            audited_at="2026-08-03T06:00:00Z",
        ),
    )

    persisted = json.loads(tracked.read_text(encoding="utf-8"))[REPOSITORY]["v1.0.0@1"]
    assert persisted == {**initial, "audit_context_hash": "new-context"}
    assert persisted["audited_at"] == "2026-08-03T00:00:00Z"


def test_changed_verdict_updates_timestamp(monkeypatch, tmp_path):
    tracked = tmp_path / "security-verdicts.json"
    cache_dir = tmp_path / ".audit-cache"
    monkeypatch.setattr(ap, "VERDICTS_FILE", str(tracked))

    ap._record_verdict(str(cache_dir), _report())
    initial_bytes = tracked.read_bytes()

    ap._record_verdict(
        str(cache_dir),
        _report(classification="MANUAL_REVIEW", audited_at="2026-08-03T12:00:00Z"),
    )

    assert tracked.read_bytes() != initial_bytes
    assert tracked.read_bytes().endswith(b"\n")
    changed = json.loads(tracked.read_text(encoding="utf-8"))
    assert changed[REPOSITORY]["v1.0.0@1"]["classification"] == "MANUAL_REVIEW"
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
