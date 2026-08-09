import hashlib
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
SECURITY_POLICY_PATH = ROOT / "security-policy.yml"


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
    release_records = proof["release_records"]
    tag_commit_records = proof["tag_commit_records"]
    source_commit_inventory = proof["source_commit_inventory"]

    assert proof["reviewed_commit"] == "0dd6649277fd8384934251bb3840e3db92419772"
    assert (
        proof["inventory_summary"]["mapped_release_count"]
        == proof["corpus"]["eligible_release_count"]
        == len(release_records)
        == 579
    )
    assert proof["corpus"]["unique_commit_count"] == len(source_commit_inventory) == 555
    assert len(tag_commit_records) == proof["corpus"]["eligible_release_count"] == 579

    policy_checksum = hashlib.sha256(SECURITY_POLICY_PATH.read_bytes()).hexdigest()
    assert proof["policy_checksum"] == policy_checksum
    assert proof["policy_identity"]["policy_checksum"] == policy_checksum
    assert proof["policy_identity"]["policy_path"] == "security-policy.yml"

    import yaml as _yaml

    policy = _yaml.safe_load(SECURITY_POLICY_PATH.read_text(encoding="utf-8"))
    assert proof["policy_identity"]["downloads"] == policy["downloads"]

    download_records = [
        record
        for record in release_records
        if record["source_download_status"] == "downloaded"
    ]
    cached_records = [
        record
        for record in release_records
        if record["source_download_status"] == "cached"
    ]
    assert len(download_records) + len(cached_records) == len(release_records)
    assert (
        len(download_records)
        == proof["download_metrics"]["physical_download_call_count"]
    )
    assert (
        len(download_records)
        == proof["request_metrics"]["run"]["bounded_download_calls"]
        == proof["request_metrics"]["cumulative"]["bounded_download_call_count"]
    )
    assert (
        len(cached_records)
        == proof["inventory_summary"]["alias_count"]
        == proof["inventory_summary"]["cached_release_count"]
        == 24
    )

    source_error_records = [
        record for record in release_records if record["source_error"]
    ]
    assert source_error_records == []
    assert proof["download_metrics"]["physical_download_error_count"] == 0
    assert proof["download_metrics"]["physical_download_success_count"] == len(
        download_records
    )
    assert proof["download_metrics"]["physical_download_limit_violation_count"] == 0
    assert proof["inventory_summary"]["release_errors"] == []
    assert proof["inventory_summary"]["repo_errors"] == []
    assert proof["inventory_summary"]["limit_violation_count"] == 0
    assert proof["inventory_summary"]["over_limit_records"] == []
    assert proof["inventory_summary"].get("over_limit_count", 0) == 0

    run_metrics = proof["request_metrics"]["run"]
    cumulative_metrics = proof["request_metrics"]["cumulative"]
    assert run_metrics["bounded_download_successes"] == len(download_records)
    assert cumulative_metrics["bounded_download_success_count"] == len(download_records)
    assert (
        run_metrics["bounded_download_errors"]
        == cumulative_metrics["bounded_download_error_count"]
        == 0
    )
    assert (
        run_metrics["bounded_download_limit_violations"]
        == cumulative_metrics["bounded_download_limit_violation_count"]
        == 0
    )

    source_inventory_request_count = len(source_commit_inventory)
    source_inventory_source_bytes = sum(
        record["source_bytes"] for record in source_commit_inventory
    )
    assert (
        source_inventory_request_count
        == 555
        == proof["inventory_summary"]["physical_stream_count"]
    )
    assert (
        run_metrics["source_download_request_count"] == source_inventory_request_count
    )
    assert (
        cumulative_metrics["source_download_request_count"]
        == source_inventory_request_count
    )
    assert run_metrics["source_download_error_count"] == 0
    assert cumulative_metrics["source_download_error_count"] == 0
    assert (
        source_inventory_source_bytes
        == proof["inventory_summary"]["physical_source_bytes"]
    )

    physical_download_bytes = sum(record["source_bytes"] for record in download_records)
    mapped_release_bytes = sum(record["source_bytes"] for record in release_records)
    assert (
        proof["inventory_summary"]["physical_source_bytes"]
        == physical_download_bytes
        == proof["download_metrics"]["physical_download_bytes"]
    )
    assert (
        proof["inventory_summary"]["mapped_release_bytes"]
        == mapped_release_bytes
        == proof["download_metrics"]["mapped_release_bytes"]
    )

    source_limit_bytes = proof["policy_identity"]["downloads"]["source_max_bytes"]
    assert source_limit_bytes == 268435456
    assert proof["policy_identity"]["downloads"]["release_max_bytes"] == 67108864
    assert proof["policy_identity"]["downloads"]["connect_timeout_seconds"] == 10
    assert proof["policy_identity"]["downloads"]["read_timeout_seconds"] == 60
    assert proof["policy_identity"]["downloads"]["chunk_size_bytes"] == 1048576
    assert all(
        record["source_bytes"] <= source_limit_bytes for record in release_records
    )

    source_bytes_by_release_id = {
        record["release_id"]: record["source_bytes"] for record in release_records
    }
    assert len(source_bytes_by_release_id) == len(release_records)
    assert (
        max(source_bytes_by_release_id.values())
        == proof["inventory_summary"]["maximum_bytes"]
    )
    max_size_record = max(release_records, key=lambda record: record["source_bytes"])
    assert (
        proof["inventory_summary"]["maximum_bytes_identity"]
        == f"{max_size_record['repository']}:{max_size_record['release_id']}"
    )

    repo_commit_from_releases = {
        (record["repository"], record["source_commit_sha"])
        for record in release_records
    }
    repo_commit_from_inventory = {
        (record["repository"], record["source_commit_sha"])
        for record in source_commit_inventory
    }
    assert repo_commit_from_releases == repo_commit_from_inventory

    release_by_id = {record["release_id"]: record for record in release_records}
    tag_commit_by_id = {record["release_id"]: record for record in tag_commit_records}
    assert set(release_by_id.keys()) == set(tag_commit_by_id.keys())
    for release_id, release_record in release_by_id.items():
        tag_commit_record = tag_commit_by_id[release_id]
        tag, asset_id = release_id.split("@", 1)
        assert tag
        assert asset_id
        assert asset_id.isdigit()
        assert release_record["asset_id"] == asset_id
        assert release_record["asset_id"].isdigit()
        assert release_record["github_release_id"].isdigit()
        assert (
            release_record["github_release_id"]
            == tag_commit_record["github_release_id"]
        )
        assert release_record["repository"] == tag_commit_record["repository"]
        assert (
            release_record["source_commit_sha"]
            == tag_commit_record["source_commit_sha"]
        )
        assert tag_commit_record["tag_name"]
        assert tag_commit_record["source_url"]

    assert all(char in "0123456789abcdef" for char in proof["corpus"]["corpus_digest"])
    assert all(
        char in "0123456789abcdef" for char in proof["corpus"]["inventory_digest"]
    )
    assert len(proof["corpus"]["corpus_digest"]) == 64
    assert len(proof["corpus"]["inventory_digest"]) == 64

    assert proof["timing"]["checkpoint_elapsed_seconds"] > 0
    assert proof["timing"]["run_elapsed_seconds"] > 0
    assert proof["timing"]["run_completed_at"] >= proof["timing"]["run_started_at"]
    assert (
        cumulative_metrics["run_elapsed_seconds"]
        >= proof["timing"]["run_elapsed_seconds"]
    )

    assert cumulative_metrics["api_request_count"] > 0
    assert cumulative_metrics["source_download_request_count"] > 0
    assert (
        cumulative_metrics["api_request_count"]
        >= cumulative_metrics["source_download_request_count"]
    )
    assert (
        proof["request_metrics"]["run"]["api_request_count"]
        == cumulative_metrics["api_request_count"]
        == 1323
    )
    assert (
        proof["request_metrics"]["run"]["api_error_count"]
        == cumulative_metrics["api_error_count"]
        == 0
    )
    assert run_metrics["bounded_download_bytes_streamed"] == physical_download_bytes
    assert (
        cumulative_metrics["bounded_download_bytes_streamed"] == physical_download_bytes
    )

    assert proof["result"] == "PASS_COMPLETE_SOURCE_ARCHIVE_SIZE_INVENTORY"

    assert proof["request_metrics"]["run"]["bounded_download_calls"] == 555
    assert cumulative_metrics["api_request_count"] > 0
    assert cumulative_metrics["source_download_request_count"] > 0
    assert (
        cumulative_metrics["api_request_count"]
        >= cumulative_metrics["source_download_request_count"]
    )
    assert (
        cumulative_metrics["run_elapsed_seconds"]
        >= proof["timing"]["run_elapsed_seconds"]
    )

    source_inventory = projection["open_uncertainties"][
        "complete_source_archive_size_inventory"
    ]
    assert source_inventory["status"] == proof["result"]
    assert source_inventory["verified"] is True
    assert source_inventory["acceptance_requirement_open"] is False
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
