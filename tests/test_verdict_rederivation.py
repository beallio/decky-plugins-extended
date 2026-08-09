import copy
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import audit_plugins as ap
import generate_json

REPOSITORY = "https://github.com/owner/plugin"
BLOCKABLE_RULES = {"ARCHIVE_TRAVERSAL", "MALWARE"}
ARTIFACT_HASH = "a" * 64


def _release(tag="v1.0.0", asset_id=1, artifact_hash=ARTIFACT_HASH):
    return {
        "tag_name": tag,
        "prerelease": False,
        "published_at": "2026-08-04T12:00:00Z",
        "assets": [
            {
                "id": asset_id,
                "name": "plugin.zip",
                "browser_download_url": (
                    f"https://github.com/owner/plugin/releases/download/{tag}/plugin.zip"
                ),
                "digest": f"sha256:{artifact_hash}",
            }
        ],
    }


def _stored_verdict(classification="BLOCK", blocking_rule_ids=None):
    entry = {
        "classification": classification,
        "artifact_sha256": ARTIFACT_HASH,
        "audit_context_hash": "old-policy-context",
        "audited_at": "2026-08-04T12:00:00Z",
    }
    if blocking_rule_ids is not None:
        entry["blocking_rule_ids"] = blocking_rule_ids
    return {REPOSITORY: {"v1.0.0@1": entry}}


@pytest.mark.parametrize(
    ("classification", "blocking_rule_ids", "expected"),
    [
        ("BLOCK", ["SHELL_CURL_PIPE"], "MANUAL_REVIEW"),
        ("BLOCK", ["ARCHIVE_TRAVERSAL"], "BLOCK"),
        ("BLOCK", ["SHELL_CURL_PIPE", "ARCHIVE_TRAVERSAL"], "BLOCK"),
        ("MANUAL_REVIEW", ["MALWARE"], "MANUAL_REVIEW"),
        ("BLOCK", [], "MANUAL_REVIEW"),
        ("BLOCK", None, "MANUAL_REVIEW"),
    ],
)
def test_configured_release_rederivation_only_demotes_stored_blocks(
    classification, blocking_rule_ids, expected
):
    result = ap.classification_for(
        REPOSITORY,
        _release(),
        _stored_verdict(classification, blocking_rule_ids),
        BLOCKABLE_RULES,
        current_artifact_sha256=ARTIFACT_HASH,
    )

    assert result.effective_classification == expected
    assert result.audit_classification == classification
    assert result.blocking_rule_ids == (blocking_rule_ids or [])


def test_fresh_audit_report_classification_is_not_rederived():
    report = ap.AuditReport(
        audit_timestamp="2026-08-04T12:00:00Z",
        repository=REPOSITORY,
        release="v1.0.0",
        release_id="v1.0.0@1",
        artifact_sha256=ARTIFACT_HASH,
        audit_context_hash="current-policy-context",
        final_classification="BLOCK",
        findings=[],
    )

    result = ap.classification_for(REPOSITORY, report, {}, set())

    assert result.effective_classification == "BLOCK"
    assert result.audit_classification == "BLOCK"


@pytest.mark.parametrize(
    ("classification", "blocking_rule_ids", "expected"),
    [
        ("BLOCK", ["SHELL_CURL_PIPE"], False),
        ("BLOCK", ["ARCHIVE_TRAVERSAL"], True),
        ("BLOCK", ["SHELL_CURL_PIPE", "ARCHIVE_TRAVERSAL"], True),
        ("MANUAL_REVIEW", ["MALWARE"], False),
        ("BLOCK", [], False),
        ("BLOCK", None, False),
    ],
)
def test_upstream_release_rederivation_only_demotes_stored_blocks(
    classification, blocking_rule_ids, expected
):
    verdicts = _stored_verdict(classification, blocking_rule_ids)
    version = {
        "name": "1.0.0",
        "hash": ARTIFACT_HASH,
        "artifact": (
            "https://github.com/owner/plugin/releases/download/v1.0.0/plugin.zip"
        ),
    }

    assert (
        generate_json.catalog_version_is_blocked(
            version,
            verdicts,
            BLOCKABLE_RULES,
            release=_release(),
            current_artifact_sha256=ARTIFACT_HASH,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("asset_id", "expected"),
    [
        (1, False),
        (2, True),
    ],
)
def test_upstream_release_uses_exact_current_asset_identity(asset_id, expected):
    nonblocking_entry = _stored_verdict("MANUAL_REVIEW", ["MALWARE"])[REPOSITORY][
        "v1.0.0@1"
    ]
    blockable_entry = _stored_verdict("BLOCK", ["ARCHIVE_TRAVERSAL"])[REPOSITORY][
        "v1.0.0@1"
    ]
    verdicts = {
        REPOSITORY: {
            "v1.0.0@1": nonblocking_entry,
            "v1.0.0@2": blockable_entry,
        }
    }
    version = {
        "name": "1.0.0",
        "hash": ARTIFACT_HASH,
        "artifact": (
            "https://github.com/owner/plugin/releases/download/v1.0.0/plugin.zip"
        ),
    }

    assert (
        generate_json.catalog_version_is_blocked(
            version,
            verdicts,
            BLOCKABLE_RULES,
            release=_release(asset_id=asset_id),
            current_artifact_sha256=ARTIFACT_HASH,
        )
        is expected
    )


def test_upstream_demotion_log_names_release_and_rule_ids_without_evidence(capsys):
    verdicts = _stored_verdict("BLOCK", ["SHELL_CURL_PIPE"])
    verdicts[REPOSITORY]["v1.0.0@1"]["evidence"] = "PRIVATE-EVIDENCE"
    version = {
        "name": "1.0.0",
        "hash": ARTIFACT_HASH,
        "artifact": (
            "https://github.com/owner/plugin/releases/download/v1.0.0/plugin.zip"
        ),
    }

    assert not generate_json.catalog_version_is_blocked(
        version,
        verdicts,
        BLOCKABLE_RULES,
        release=_release(),
        current_artifact_sha256=ARTIFACT_HASH,
    )

    output = capsys.readouterr().out
    assert "owner/plugin" in output
    assert "v1.0.0" in output
    assert "SHELL_CURL_PIPE" in output
    assert "not currently blockable" in output
    assert "PRIVATE-EVIDENCE" not in output


def test_committed_verdicts_follow_current_blocking_policy():
    repository_root = Path(ap.__file__).parent
    verdicts = json.loads(
        (repository_root / "security-verdicts.json").read_text(encoding="utf-8")
    )
    policy = ap.load_policy(str(repository_root / "security-policy.yml"))
    evaluated = []

    for repository, releases in verdicts.items():
        for release_id, entry in releases.items():
            tag, asset_id = release_id.rsplit("@", 1)
            release = _release(tag, int(asset_id), entry["artifact_sha256"])
            release["assets"][0]["browser_download_url"] = (
                f"{repository}/releases/download/{tag}/plugin.zip"
            )
            result = ap.classification_for(
                repository,
                release,
                verdicts,
                policy["blockable_rules"],
                current_artifact_sha256=entry["artifact_sha256"],
            )
            evaluated.append((repository, release_id, entry, result))

    assert evaluated, "the committed verdict store should not be empty"
    for repository, release_id, entry, result in evaluated:
        assert result.audit_classification == entry["classification"], (
            repository,
            release_id,
        )
        if entry["classification"] == "BLOCK":
            has_blockable_rule = bool(
                set(entry.get("blocking_rule_ids") or [])
                & set(policy["blockable_rules"])
            )
            assert (result.effective_classification == "BLOCK") is has_blockable_rule, (
                repository,
                release_id,
            )


def _run_generator(monkeypatch, tmp_path, verdicts):
    releases_by_repository = {}
    names_by_repository = {}
    for repository, release_verdicts in verdicts.items():
        repository_name = repository.rstrip("/").rsplit("/", 1)[-1]
        names_by_repository[repository_name] = repository_name
        releases = []
        for release_id, entry in release_verdicts.items():
            tag, asset_id = release_id.rsplit("@", 1)
            release = _release(tag, int(asset_id), entry["artifact_sha256"])
            release["assets"][0]["browser_download_url"] = (
                f"{repository}/releases/download/{tag}/plugin.zip"
            )
            releases.append(release)
        releases_by_repository[repository_name] = releases

    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {
            "default_branch": "main",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-08-04T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        generate_json,
        "get_package_json",
        lambda _owner, repository_name, _branch: {
            "name": names_by_repository[repository_name],
            "author": "Fixture Owner",
        },
    )
    monkeypatch.setattr(
        generate_json,
        "get_plugin_json",
        lambda _owner, repository_name, _branch: {
            "name": names_by_repository[repository_name]
        },
    )
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda _owner, repository_name: copy.deepcopy(
            releases_by_repository[repository_name]
        ),
    )
    monkeypatch.setattr(
        generate_json,
        "load_verdicts",
        lambda: copy.deepcopy(verdicts),
    )
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {
            "enforcement": {"mode": "enforce"},
            "blockable_rules": sorted(BLOCKABLE_RULES),
        },
    )
    (tmp_path / "additional_plugins.txt").write_text(
        "\n".join(verdicts) + "\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    generate_json.main()

    stable = json.loads((tmp_path / "public/plugins.json").read_text(encoding="utf-8"))
    testing = json.loads(
        (tmp_path / "public/testing_plugins.json").read_text(encoding="utf-8")
    )
    return stable, testing


def test_generator_keeps_stale_blocks_and_logs_policy_disagreement(
    monkeypatch, tmp_path, capsys
):
    repository_root = Path(ap.__file__).parent
    committed = json.loads(
        (repository_root / "security-verdicts.json").read_text(encoding="utf-8")
    )
    stale_blocks = {
        repository: {
            release_id: copy.deepcopy(entry)
            for release_id, entry in releases.items()
            if entry.get("classification") == "BLOCK"
            and not set(entry.get("blocking_rule_ids") or []) & BLOCKABLE_RULES
        }
        for repository, releases in committed.items()
        if any(
            entry.get("classification") == "BLOCK"
            and not set(entry.get("blocking_rule_ids") or []) & BLOCKABLE_RULES
            for entry in releases.values()
        )
    }
    if not stale_blocks:
        stale_blocks = _stored_verdict("BLOCK", ["SHELL_CURL_PIPE"])
    expected_demotion_count = sum(
        1
        for releases in stale_blocks.values()
        for entry in releases.values()
        if entry.get("classification") == "BLOCK"
        and not set(entry.get("blocking_rule_ids") or []) & BLOCKABLE_RULES
    )
    secret_evidence = "PRIVATE-EVIDENCE-MUST-NOT-APPEAR"
    next(iter(next(iter(stale_blocks.values())).values()))["evidence"] = secret_evidence

    stable, testing = _run_generator(monkeypatch, tmp_path, stale_blocks)

    expected_names = {
        repository.rstrip("/").rsplit("/", 1)[-1] for repository in stale_blocks
    }
    assert {plugin["name"] for plugin in stable} == expected_names
    assert {plugin["name"] for plugin in testing} == expected_names
    output = capsys.readouterr().out
    assert output.count("[policy-demotion]") == expected_demotion_count
    for repository, releases in stale_blocks.items():
        plugin_name = repository.rstrip("/").rsplit("/", 1)[-1]
        assert plugin_name in output
        for release_id, entry in releases.items():
            assert release_id.rsplit("@", 1)[0] in output
            for rule_id in entry["blocking_rule_ids"]:
                assert rule_id in output
    assert "not currently blockable" in output
    assert secret_evidence not in output


def test_generator_surfaces_block_without_recorded_rule_ids(
    monkeypatch, tmp_path, capsys
):
    verdicts = _stored_verdict("BLOCK", [])

    stable, testing = _run_generator(monkeypatch, tmp_path, verdicts)

    assert stable[0]["name"] == "plugin"
    assert testing[0]["name"] == "plugin"
    output = capsys.readouterr().out
    assert "[policy-demotion]" in output
    assert "no blocking rule IDs were recorded" in output


def test_public_audit_shows_effective_and_stored_classifications(tmp_path):
    verdicts = {
        REPOSITORY: {
            "v1.0.0@1": _stored_verdict("BLOCK", ["SHELL_CURL_PIPE"])[REPOSITORY][
                "v1.0.0@1"
            ],
            "v2.0.0@2": {
                **_stored_verdict("BLOCK", ["ARCHIVE_TRAVERSAL"])[REPOSITORY][
                    "v1.0.0@1"
                ],
                "artifact_sha256": "b" * 64,
            },
        }
    }

    generate_json.write_audit_outputs(
        verdicts,
        "report-only",
        tmp_path,
        blockable_rules=BLOCKABLE_RULES,
    )

    payload = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    html = (tmp_path / "audit.html").read_text(encoding="utf-8")
    by_release = {release["release"]: release for release in payload["releases"]}
    assert by_release["v1.0.0@1"]["classification"] == "MANUAL_REVIEW"
    assert by_release["v1.0.0@1"]["stored_classification"] == "BLOCK"
    assert by_release["v2.0.0@2"]["classification"] == "BLOCK"
    assert by_release["v2.0.0@2"]["stored_classification"] == "BLOCK"
    assert "Effective classification" in html
    assert "Stored verdict: BLOCK" in html
    assert "predates the current policy" in html
    assert "SHELL_CURL_PIPE" in html
