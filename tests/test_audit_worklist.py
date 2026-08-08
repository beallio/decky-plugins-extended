import json

import pytest

import audit_plugins as ap


def _release(
    tag,
    release_id,
    asset_id,
    published_at=None,
    *,
    prerelease=False,
    draft=False,
    zip_count=1,
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
                "browser_download_url": f"https://example.invalid/{tag}-{offset}.zip",
            }
            for offset in range(zip_count)
        ],
    }


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


def test_four_shards_are_disjoint_and_union_identical():
    items = [
        ap.AuditWorkItem(
            repository="https://github.com/owner/repo",
            release=_release(f"v{index}", index, index * 10),
            repository_metadata={},
        )
        for index in range(1, 33)
    ]

    shards = [ap.select_audit_shard(items, 4, index) for index in range(4)]
    identities = [
        {(item.repository, item.release["id"]) for item in shard} for shard in shards
    ]

    assert set.union(*identities) == {
        (item.repository, item.release["id"]) for item in items
    }
    assert sum(len(identity) for identity in identities) == len(items)
    assert all(
        identities[left].isdisjoint(identities[right])
        for left in range(4)
        for right in range(left + 1, 4)
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
    }

    assert ap.resume_identity_matches(expected, expected)
    for field in expected:
        mutated = dict(expected)
        mutated[field] = "different"
        assert not ap.resume_identity_matches(mutated, expected), field


def test_aggregation_rejects_duplicate_and_conflicting_release_keys(tmp_path):
    report = ap.AuditReport(
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_sha256="a" * 64,
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
        "artifact_sha256": "a" * 64,
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
