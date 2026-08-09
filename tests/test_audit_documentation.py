import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_INVENTORY_PROOF_PATH = (
    ROOT
    / "docs/agent_conversations/2026-08-08_audit-source-archive-size-inventory-proof.json"
)
CAPACITY_PROJECTION_PATH = (
    ROOT
    / "docs/agent_conversations/2026-08-08_audit-fourteen-shard-capacity-projection.json"
)
PLAN_PATH = (
    ROOT / "docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md"
)
OVERVIEW_PATH = ROOT / "docs/audit-gating-overview.md"
README_PATH = ROOT / "README.md"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_readme_documents_authoritative_local_and_ci_gates():
    readme = README_PATH.read_text(encoding="utf-8")

    assert "python -m unittest discover" not in readme
    assert "uv run ruff check ." in readme
    assert "uv run ruff format --check ." in readme
    assert "GITHUB_TOKEN=test-token uv run pytest -q" in readme
    assert "actionlint v1.7.12" in readme
    assert "Semgrep 1.132.0" in readme


def test_readme_documents_current_identity_and_outcome_contract():
    readme = README_PATH.read_text(encoding="utf-8")

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


def test_source_inventory_proof_is_complete_and_self_consistent():
    proof = _read_json(SOURCE_INVENTORY_PROOF_PATH)
    projection = _read_json(CAPACITY_PROJECTION_PATH)

    assert proof["reviewed_commit"] == "0dd6649277fd8384934251bb3840e3db92419772"
    assert proof["policy_checksum"] == proof["policy_identity"]["policy_checksum"]
    assert proof["policy_identity"]["downloads"]["source_max_bytes"] == 268435456
    assert proof["policy_identity"]["downloads"]["release_max_bytes"] == 67108864
    assert proof["policy_identity"]["downloads"]["connect_timeout_seconds"] == 10
    assert proof["policy_identity"]["downloads"]["read_timeout_seconds"] == 60
    assert proof["policy_identity"]["downloads"]["chunk_size_bytes"] == 1048576

    assert proof["corpus"]["eligible_release_count"] == 579
    assert proof["corpus"]["unique_commit_count"] == 555
    assert proof["timing"]["checkpoint_elapsed_seconds"] > 0
    assert proof["timing"]["run_elapsed_seconds"] > 0
    assert proof["timing"]["run_completed_at"] >= proof["timing"]["run_started_at"]

    assert proof["download_metrics"]["physical_download_call_count"] == 555
    assert proof["download_metrics"]["physical_download_success_count"] == 555
    assert proof["download_metrics"]["physical_download_error_count"] == 0
    assert proof["download_metrics"]["physical_download_limit_violation_count"] == 0

    assert proof["inventory_summary"]["mapped_release_count"] == 579
    assert (
        proof["inventory_summary"]["physical_source_bytes"]
        == proof["download_metrics"]["physical_download_bytes"]
    )
    assert (
        proof["inventory_summary"]["mapped_release_bytes"]
        == proof["download_metrics"]["mapped_release_bytes"]
    )
    assert proof["inventory_summary"]["physical_stream_count"] == 555
    assert proof["inventory_summary"]["alias_count"] == 24
    assert proof["inventory_summary"]["limit_violation_count"] == 0
    assert proof["inventory_summary"].get("over_limit_count", 0) == 0

    assert len(proof["release_records"]) == 579
    assert len(proof["tag_commit_records"]) == 579
    assert len(proof["source_commit_inventory"]) == 555

    assert proof["request_metrics"]["run"]["bounded_download_calls"] == 555
    cumulative = proof["request_metrics"]["cumulative"]
    assert cumulative["api_request_count"] > 0
    assert cumulative["source_download_request_count"] > 0
    assert (
        cumulative["api_request_count"] >= cumulative["source_download_request_count"]
    )
    assert cumulative["run_elapsed_seconds"] >= proof["timing"]["run_elapsed_seconds"]

    source_inventory = projection["open_uncertainties"][
        "complete_source_archive_size_inventory"
    ]
    assert source_inventory["status"] == "PASS_COMPLETE_SOURCE_ARCHIVE_SIZE_INVENTORY"
    assert str(SOURCE_INVENTORY_PROOF_PATH).endswith(source_inventory["blocker_path"])


def test_current_gating_overview_supersedes_historical_rollout_text():
    overview = OVERVIEW_PATH.read_text(encoding="utf-8")

    assert "Current implementation state (2026-08-08)" in overview
    assert "supported but inactive" in overview
    assert "fourteen disjoint shards" in overview
    assert "Safe sibling outputs publish before exit 4" in overview


def test_capacity_contract_uses_fourteen_shard_projection_and_preserves_blocker():
    plan = PLAN_PATH.read_text(encoding="utf-8")
    evidence = _read_json(CAPACITY_PROJECTION_PATH)

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
    plan = PLAN_PATH.read_text(encoding="utf-8")
    evidence = _read_json(CAPACITY_PROJECTION_PATH)

    normalized_plan = " ".join(plan.split())
    assert "cold/warm corpus budgets are verified locally" not in normalized_plan
    assert "warm run and warm zero-work assertions were not executed" in normalized_plan
    assert "source-archive size inventory is now" in normalized_plan.lower()

    blocker_path = evidence["source_blocker"]["path"]
    uncertainties = evidence["open_uncertainties"]
    warm = uncertainties["warm_run_and_zero_work_assertions"]
    assert warm["status"] == "DEFERRED_NOT_EXECUTED"
    assert warm["verified"] is False
    assert warm["blocker_path"] == blocker_path
    source_inventory = uncertainties["complete_source_archive_size_inventory"]
    assert source_inventory["status"] == "PASS_COMPLETE_SOURCE_ARCHIVE_SIZE_INVENTORY"
    assert source_inventory["verified"] is True
    assert source_inventory["acceptance_requirement_open"] is False
    assert (
        source_inventory["blocker_path"]
        == "docs/agent_conversations/2026-08-08_audit-source-archive-size-inventory-proof.json"
    )
