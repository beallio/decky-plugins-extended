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
        "--shard-count 4",
        "67,108,864 bytes",
        "268,435,456 bytes",
    ):
        assert contract in readme


def test_current_gating_overview_supersedes_historical_rollout_text():
    overview = (ROOT / "docs/audit-gating-overview.md").read_text(encoding="utf-8")

    assert "Current implementation state (2026-08-08)" in overview
    assert "supported but inactive" in overview
    assert "four disjoint shards" in overview
    assert "Safe sibling outputs publish before exit 4" in overview
