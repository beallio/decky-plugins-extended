import copy
import json
import math
import stat
import zipfile
from pathlib import Path

import pytest

import audit_plugins as ap

STRUCTURAL_RULE_IDS = {
    "MALWARE",
    "ARCHIVE_TRAVERSAL",
    "ARCHIVE_ESCAPE_SYMLINK",
    "ARCHIVE_BOMB_RATIO",
    "ARCHIVE_BOMB_SIZE",
    "ARCHIVE_SETUID_FILE",
    "ARCHIVE_DEVICE_FILE",
    "ARCHIVE_NAMED_PIPE",
    "ARCHIVE_FILE_COUNT_EXCEEDED",
    "ARCHIVE_SINGLE_FILE_TOO_LARGE",
}

INCIDENT_FIXTURES = {
    "SHELL_CURL_PIPE": lambda: ap.scan_text_content(
        "curl https://example.com/setup.sh | bash\n", "install.sh", ".sh"
    ),
    "DESTRUCTIVE_RM_RF": lambda: ap.scan_text_content(
        "os.system('rm -rf /etc')\n", "main.py", ".py"
    ),
    "DESTRUCTIVE_RM_RF_SHELL": lambda: ap.scan_text_content(
        "rm -rf /etc\n", "uninstall.sh", ".sh"
    ),
    "SECRET_PRIVATE_KEY_HEADER": lambda: ap.scan_for_secrets(
        "-----BEGIN PRIVATE KEY-----\n", "vendor/key.py"
    ),
    "SECRET_PASSWORD_LITERAL": lambda: ap.scan_for_secrets(
        'password = "correct horse battery"\n', "README-example.py"
    ),
    "SECRET_GENERIC_API_KEY": lambda: ap.scan_for_secrets(
        'api_key = "aB3dE5gH7jK9mN1pQ3rS"\n', "config.py"
    ),
}


def _apply_policy(findings, policy=None):
    policy = policy or ap._default_policy()
    ap.apply_rule_classification_policy(findings, policy)
    return ap.classify_findings(findings)[0]


def _finding(rule_id, classification="BLOCK"):
    return ap.Finding(
        rule_id=rule_id,
        severity="critical",
        classification=classification,
        path="fixture",
        line=1,
        message="fixture",
        evidence="",
        scanner="fixture",
    )


def test_default_policy_names_only_structural_blockable_rules():
    assert set(ap._default_policy()["blockable_rules"]) == STRUCTURAL_RULE_IDS

    repository_policy = ap.load_policy("security-policy.yml")
    assert set(repository_policy["blockable_rules"]) == STRUCTURAL_RULE_IDS
    assert "ARCHIVE_DUPLICATE_PATH" not in repository_policy["blockable_rules"]
    assert "CORRUPT_ARCHIVE" not in repository_policy["blockable_rules"]
    assert "INVALID_PLUGIN_JSON" not in repository_policy["blockable_rules"]


def test_unknown_blockable_rule_is_rejected(tmp_path):
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "version: '1'\nblockable_rules:\n  - ARCHIVE_TRAVERSLA\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ARCHIVE_TRAVERSLA"):
        ap.load_policy(str(policy_path))


def test_all_incident_rules_remain_findings_but_are_capped_at_manual_review():
    incident_findings = []
    for rule_id, make_findings in INCIDENT_FIXTURES.items():
        matches = [finding for finding in make_findings() if finding.rule_id == rule_id]
        assert len(matches) == 1, rule_id
        assert matches[0].classification == "BLOCK", rule_id
        incident_findings.extend(matches)

    observed_rule_ids = {finding.rule_id for finding in incident_findings}
    assert observed_rule_ids == set(INCIDENT_FIXTURES)
    assert _apply_policy(incident_findings) == "MANUAL_REVIEW"
    assert {finding.rule_id for finding in incident_findings} == observed_rule_ids
    assert all(
        finding.classification == "MANUAL_REVIEW" for finding in incident_findings
    )


def test_overrides_run_before_cap_and_can_only_lower_the_structural_ceiling():
    policy = ap._default_policy()
    policy["rule_classifications"] = {
        "ARCHIVE_TRAVERSAL": "PASS_WITH_WARNINGS",
        "SHELL_CURL_PIPE": "BLOCK",
    }
    findings = [
        _finding("ARCHIVE_TRAVERSAL"),
        _finding("SHELL_CURL_PIPE", "PASS_WITH_WARNINGS"),
    ]

    assert _apply_policy(findings, policy) == "MANUAL_REVIEW"
    assert findings[0].classification == "PASS_WITH_WARNINGS"
    assert findings[1].classification == "MANUAL_REVIEW"


def test_archive_traversal_and_setuid_members_still_block(tmp_path):
    traversal_zip = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal_zip, "w") as archive:
        archive.writestr("../escape", "payload")

    setuid_zip = tmp_path / "setuid.zip"
    with zipfile.ZipFile(setuid_zip, "w") as archive:
        info = zipfile.ZipInfo("plugin/helper")
        info.external_attr = (stat.S_IFREG | 0o4755) << 16
        archive.writestr(info, b"#!/bin/sh\nid\n")

    for archive_path, expected_rule in (
        (traversal_zip, "ARCHIVE_TRAVERSAL"),
        (setuid_zip, "ARCHIVE_SETUID_FILE"),
    ):
        _stats, findings = ap.inspect_zip(str(archive_path))
        selected = [f for f in findings if f.rule_id == expected_rule]
        assert len(selected) == 1
        assert _apply_policy(selected) == "BLOCK"
        assert selected[0].classification == "BLOCK"


def test_traversal_remains_block_with_required_scanners_unavailable():
    policy = ap.load_policy("security-policy.yml")
    findings = [_finding("ARCHIVE_TRAVERSAL")]
    ap.apply_rule_classification_policy(findings, policy)
    statuses = [
        ap.ScannerStatus(name=name, status="unavailable")
        for name in ("clamav", "trivy", "semgrep", "source-artifact-diff")
    ]

    classification, _score = ap.classify_findings(
        findings, scanner_statuses=statuses, policy=policy
    )

    assert classification == "BLOCK"


def test_simulated_clamav_signature_still_blocks(monkeypatch, tmp_path):
    monkeypatch.setattr(ap.shutil, "which", lambda _command: "/usr/bin/clamscan")
    monkeypatch.setattr(
        ap,
        "_run_scanner",
        lambda _command, _name: (
            False,
            f"{tmp_path}/eicar.txt: Eicar-Test-Signature FOUND\n",
            "",
        ),
    )

    status, findings = ap.run_clamav(str(tmp_path), ap._default_policy())

    assert status.status == "found_issue"
    assert [finding.rule_id for finding in findings] == ["MALWARE"]
    assert _apply_policy(findings) == "BLOCK"


def _verdict(classification, *, block=(), review=(), warning=()):
    return {
        "classification": classification,
        "blocking_rule_ids": list(block),
        "review_rule_ids": list(review),
        "warning_rule_ids": list(warning),
        "artifact_sha256": "a" * 64,
        "audit_context_hash": "context",
        "audited_at": "2026-08-04T00:00:00Z",
    }


def test_rarity_ranking_uses_distinct_rules_and_changes_no_classification():
    verdicts = {
        "https://github.com/example/a": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON", "RARE", "RARE"))
        },
        "https://github.com/example/b": {
            "v1@2": _verdict("MANUAL_REVIEW", review=("COMMON",))
        },
        "https://github.com/example/c": {"v1@3": _verdict("PASS")},
    }
    original = copy.deepcopy(verdicts)

    ranked = ap.rank_review_queue(verdicts)

    assert verdicts == original
    assert [entry.repository for entry in ranked] == [
        "https://github.com/example/a",
        "https://github.com/example/b",
        "https://github.com/example/c",
    ]
    assert ranked[0].score == pytest.approx(math.log(3 / 2) + math.log(3))
    assert ranked[1].score == pytest.approx(math.log(3 / 2))
    assert ranked[2].score == 0
    assert ranked[0].rarest_rules[0] == ("RARE", 1)
    assert all(
        record["classification"] == original[repository][release_id]["classification"]
        for repository, releases in verdicts.items()
        for release_id, record in releases.items()
    )


def test_rarity_stays_out_of_deterministic_verdict_store():
    verdict_path = Path(ap.__file__).with_name("security-verdicts.json")
    before = verdict_path.read_bytes()
    verdicts = json.loads(before)

    first = ap.rank_review_queue(verdicts)
    second = ap.rank_review_queue(verdicts)

    assert first == second
    assert verdict_path.read_bytes() == before
    assert all(
        "rarity_score" not in record
        for releases in verdicts.values()
        for record in releases.values()
    )


def test_ranking_orders_rare_rules_above_common_ones():
    """Rarity ranking must order by unusualness, not by finding count.

    This deliberately asserts the property rather than a snapshot of the live
    corpus. An earlier version pinned the exact top three and their scores, and
    broke the first time a scheduled audit changed the corpus - rarity is
    corpus-relative, so any fixed expectation is guaranteed to rot.
    """
    # Both flagged releases carry exactly two rules, so only rarity differs.
    # COMMON_A and COMMON_B each appear in three releases; UNIQUE in one.
    verdicts = {
        "https://github.com/example/one-rare": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON_A", "UNIQUE"))
        },
        "https://github.com/example/all-common": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON_A", "COMMON_B"))
        },
        "https://github.com/example/also-common": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON_A", "COMMON_B"))
        },
        "https://github.com/example/third-common": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON_A", "COMMON_B"))
        },
        "https://github.com/example/clean": {"v1@1": _verdict("PASS")},
    }
    ranked = ap.rank_review_queue(verdicts)
    names = [entry.repository.rsplit("/", 1)[-1] for entry in ranked]

    assert names[0] == "one-rare", (
        "a release carrying a unique rule must outrank one carrying more common rules"
    )
    assert names[-1] == "clean"
    assert ranked[-1].score == 0
    assert ranked[0].score > ranked[1].score


def test_committed_corpus_ranks_and_is_ordered():
    """The real store must rank without error and be sorted descending."""
    verdict_path = Path(ap.__file__).with_name("security-verdicts.json")
    ranked = ap.rank_review_queue(json.loads(verdict_path.read_text()))

    assert ranked, "the committed corpus should produce a ranking"
    scores = [entry.score for entry in ranked]
    assert scores == sorted(scores, reverse=True)
    assert min(scores) >= 0


def test_run_summary_surfaces_ranked_releases_and_rarest_rules():
    verdicts = {
        "https://github.com/example/a": {
            "v1@1": _verdict("MANUAL_REVIEW", review=("COMMON", "RARE"))
        },
        "https://github.com/example/b": {
            "v1@2": _verdict("MANUAL_REVIEW", review=("COMMON",))
        },
    }

    summary = ap.generate_run_summary([], verdicts=verdicts)

    assert "Review queue by rarity" in summary
    assert "example/a" in summary
    assert "RARE (1/2)" in summary
    assert "reporting only" in summary
