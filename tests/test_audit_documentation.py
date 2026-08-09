import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_documents_authoritative_local_and_ci_gates():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "python -m unittest discover" not in readme
    assert "uv run ruff check ." in readme
    assert "uv run ruff format --check ." in readme
    assert "GITHUB_TOKEN=test-token uv run pytest -q" in readme
    assert "actionlint v1.7.12" in readme
    assert "Semgrep 1.132.0" in readme


def test_readme_documents_current_identity_and_outcome_contract():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for contract in (
        "enforcement.mode: enforce",
        "CURRENT",
        "STALE_HASH",
        "UNKNOWN",
        "exit 4",
        "Exit 1",
        "--latest-only",
        "--shard-count 14",
        "67,108,864 bytes",
        "268,435,456 bytes",
    ):
        assert contract in readme


def test_current_gating_overview_supersedes_historical_rollout_text():
    overview = (ROOT / "docs/audit-gating-overview.md").read_text(encoding="utf-8")

    assert "Current implementation state (2026-08-08)" in overview
    assert "supported but inactive" in overview
    assert "fourteen disjoint shards" in overview
    assert "Safe sibling outputs publish before exit 4" in overview


def test_capacity_contract_uses_fourteen_shard_projection_and_preserves_blocker():
    plan = (
        ROOT
        / "docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md"
    ).read_text(encoding="utf-8")
    evidence = json.loads(
        (
            ROOT
            / "docs/agent_conversations/2026-08-08_audit-fourteen-shard-capacity-projection.json"
        ).read_text(encoding="utf-8")
    )

    assert "maximum fourteen-shard wall-time estimate" in plan
    assert "Do not require the sequential unsharded cold scan" in plan
    assert evidence["source_blocker"]["path"].endswith(
        "2026-08-08_audit-live-corpus-capacity-blocker.json"
    )
    assert evidence["snapshot_inputs"]["production_shard_count"] == 14
    assert evidence["snapshot_inputs"]["repeated_baseline_enumeration_requests"] == 1162
    balance = evidence["fourteen_shard_assignment"]["release_count_by_shard_index"]
    assert balance == [34, 30, 48, 32, 50, 38, 40, 42, 42, 47, 39, 44, 41, 52]
    assert sum(balance) == evidence["snapshot_inputs"]["eligible_release_count"]
    timings = evidence["observed_release_timings"]
    assert timings["sample_count"] == 161
    assert timings["mean_seconds"] == 14.796891
    assert timings["p95_seconds"] == 18.541324
    projection = evidence["maximum_shard_projection"]
    assert projection["conservative_p95_rate_minutes"] < 22
    assert projection["pull_request_headroom_seconds"] > 0
    boundary = evidence["verification_boundary"]
    assert not boundary["full_corpus_rerun_performed"]
    assert (
        boundary["hosted_runner_concurrency_and_api_behavior"] == "DEFERRED_VALIDATION"
    )


def test_capacity_evidence_keeps_unexecuted_warm_and_source_inventory_work_open():
    plan = (
        ROOT
        / "docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md"
    ).read_text(encoding="utf-8")
    evidence = json.loads(
        (
            ROOT
            / "docs/agent_conversations/2026-08-08_audit-fourteen-shard-capacity-projection.json"
        ).read_text(encoding="utf-8")
    )

    normalized_plan = " ".join(plan.split())
    assert "cold/warm corpus budgets are verified locally" not in normalized_plan
    assert "warm run and warm zero-work assertions were not executed" in normalized_plan
    assert (
        "complete source-archive size inventory remains an open acceptance requirement"
        in normalized_plan
    )

    blocker_path = evidence["source_blocker"]["path"]
    uncertainties = evidence["open_uncertainties"]
    warm = uncertainties["warm_run_and_zero_work_assertions"]
    assert warm["status"] == "DEFERRED_NOT_EXECUTED"
    assert warm["verified"] is False
    assert warm["blocker_path"] == blocker_path
    source_inventory = uncertainties["complete_source_archive_size_inventory"]
    assert source_inventory["status"] == "INCOMPLETE_ACCEPTANCE_REQUIREMENT_OPEN"
    assert source_inventory["verified"] is False
    assert source_inventory["blocker_path"] == blocker_path
    assert source_inventory["acceptance_requirement_open"] is True
