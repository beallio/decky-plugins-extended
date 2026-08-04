import copy
import json
import os
from unittest.mock import patch

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import generate_json

BASE_CATALOG = [
    {
        "id": 1,
        "name": "Base Plugin",
        "versions": [
            {
                "name": "1.0.0",
                "hash": "a" * 64,
                "artifact": "https://example.invalid/base.zip",
            }
        ],
    }
]


def _run_minimal_generator(tmp_path, policy_mode="report-only"):
    (tmp_path / "additional_plugins.txt").write_text("", encoding="utf-8")

    with (
        patch.object(
            generate_json,
            "fetch_json",
            side_effect=lambda _url: copy.deepcopy(BASE_CATALOG),
        ),
        patch.object(
            generate_json,
            "load_policy",
            return_value={"enforcement": {"mode": policy_mode}},
        ),
    ):
        generate_json.main()


def test_empty_verdict_store_writes_valid_html_and_json(tmp_path):
    destination = tmp_path / "public"

    generate_json.write_audit_outputs({}, "report-only", destination)

    html = (destination / "audit.html").read_text(encoding="utf-8")
    payload = json.loads((destination / "audit.json").read_text(encoding="utf-8"))
    assert html.startswith("<!DOCTYPE html>")
    assert html.endswith("</html>\n")
    assert "No releases have been audited yet." in html
    assert payload == {"enforcement_mode": "report-only", "releases": []}


def test_public_audit_whitelists_fields_and_never_leaks_evidence(tmp_path):
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    file_contents = "private key file contents"
    verdicts = {
        "https://github.com/example/plugin": {
            "v1.2.3@42": {
                "artifact_sha256": "f" * 64,
                "audit_context_hash": "context-hash",
                "audited_at": "2026-08-04T12:34:56Z",
                "blocking_rule_ids": ["ARCHIVE_TRAVERSAL"],
                "classification": "BLOCK",
                "review_rule_ids": ["PRIVILEGE_SUDO"],
                "warning_rule_ids": ["EXEC_SUBPROCESS_RUN"],
                "evidence": secret,
                "file_contents": file_contents,
            }
        }
    }

    generate_json.write_audit_outputs(verdicts, "report-only", tmp_path)

    html = (tmp_path / "audit.html").read_text(encoding="utf-8")
    raw_json = (tmp_path / "audit.json").read_text(encoding="utf-8")
    payload = json.loads(raw_json)
    release = payload["releases"][0]

    assert set(payload) == {"enforcement_mode", "releases"}
    assert set(release) == {
        "repository",
        "release",
        "classification",
        "rule_ids",
        "audited_at",
    }
    assert release["rule_ids"] == [
        "ARCHIVE_TRAVERSAL",
        "EXEC_SUBPROCESS_RUN",
        "PRIVILEGE_SUDO",
    ]
    assert '"evidence"' not in raw_json
    assert '"file_contents"' not in raw_json
    for forbidden in (secret, file_contents, "f" * 64):
        assert forbidden not in html
        assert forbidden not in raw_json


def test_block_releases_are_rendered_before_every_other_tier(tmp_path):
    verdicts = {
        "https://github.com/example/manual": {
            "v2.0.0@2": {
                "classification": "MANUAL_REVIEW",
                "review_rule_ids": ["NATIVE_BINARY"],
                "audited_at": "2026-08-04T12:00:00Z",
            }
        },
        "https://github.com/example/block": {
            "v1.0.0@1": {
                "classification": "BLOCK",
                "blocking_rule_ids": ["MALWARE"],
                "audited_at": "2026-08-04T13:00:00Z",
            }
        },
        "https://github.com/example/pass": {
            "v3.0.0@3": {
                "classification": "PASS",
                "audited_at": "2026-08-04T14:00:00Z",
            }
        },
    }

    generate_json.write_audit_outputs(verdicts, "report-only", tmp_path)

    payload = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    html = (tmp_path / "audit.html").read_text(encoding="utf-8")
    assert [release["classification"] for release in payload["releases"]] == [
        "BLOCK",
        "MANUAL_REVIEW",
        "PASS",
    ]
    assert html.index("https://github.com/example/block") < html.index(
        "https://github.com/example/manual"
    )


def test_enforcement_copy_reflects_policy_mode(tmp_path):
    report_only = tmp_path / "report-only"
    enforced = tmp_path / "enforced"

    generate_json.write_audit_outputs({}, "report-only", report_only)
    generate_json.write_audit_outputs({}, "enforce", enforced)

    report_only_html = (report_only / "audit.html").read_text(encoding="utf-8")
    enforced_html = (enforced / "audit.html").read_text(encoding="utf-8")
    assert "No releases are currently excluded" in report_only_html
    assert "Releases with a BLOCK verdict are excluded" not in report_only_html
    assert "Releases with a BLOCK verdict are excluded" in enforced_html
    assert "No releases are currently excluded" not in enforced_html


def test_missing_verdict_store_does_not_break_catalog_generation(tmp_path):
    assert not (tmp_path / "security-verdicts.json").exists()

    _run_minimal_generator(tmp_path)

    public = tmp_path / "public"
    assert json.loads((public / "plugins.json").read_text(encoding="utf-8"))
    assert json.loads((public / "testing_plugins.json").read_text(encoding="utf-8"))
    assert (public / "audit.html").is_file()
    assert json.loads((public / "audit.json").read_text(encoding="utf-8")) == {
        "enforcement_mode": "report-only",
        "releases": [],
    }


def test_generator_uses_policy_mode_for_published_audit(tmp_path):
    _run_minimal_generator(tmp_path, policy_mode="enforce")

    payload = json.loads((tmp_path / "public/audit.json").read_text(encoding="utf-8"))
    html = (tmp_path / "public/audit.html").read_text(encoding="utf-8")
    assert payload["enforcement_mode"] == "enforce"
    assert "Releases with a BLOCK verdict are excluded" in html
