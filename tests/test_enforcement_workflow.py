"""Enforcement must never withhold the verdicts that produced it.

Under `enforcement.mode: enforce` the audit CLI exits 2 for BLOCK and 3 for
MANUAL_REVIEW. If those exits fail the scheduled audit step, the publish step
that rewrites security-verdicts.json is skipped and the store freezes at
whatever it held before -- the stale-verdict condition enforcement depends on
the store not being in. These tests execute the workflow's own shell blocks.
"""

import json
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import audit_plugins as ap

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCHEDULED = WORKFLOWS / "scheduled-security-audit.yml"
PULL_REQUEST = WORKFLOWS / "plugin-security-audit.yml"
PRODUCTION_SHARD_COUNT = 14


def _run_block(workflow: Path, step_name: str) -> str:
    """Return the shell body of one named workflow step."""
    text = workflow.read_text(encoding="utf-8")
    step = text.split(f"      - name: {step_name}\n", maxsplit=1)[1]
    body = step.split("        run: |\n", maxsplit=1)[1]
    for terminator in ("\n      - name:", "\n        timeout-minutes:"):
        body = body.split(terminator, maxsplit=1)[0]
    return textwrap.dedent(body)


def _step_if(workflow: Path, step_name: str) -> str:
    """Return the exact `if` expression attached to one workflow step."""
    text = workflow.read_text(encoding="utf-8")
    step = text.split(f"      - name: {step_name}\n", maxsplit=1)[1]
    step = step.split("\n      - name:", maxsplit=1)[0]
    for line in step.splitlines():
        if line.startswith("        if: "):
            return line.removeprefix("        if: ")
    raise AssertionError(f"workflow step has no if condition: {step_name}")


def _bash(script: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    environment = os.environ.copy()
    environment.update(env)
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
    )


def _stub_uv(tmp_path: Path, exit_code: int) -> Path:
    """A `uv` that reports a given audit exit code instead of auditing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "uv"
    stub.write_text(
        f"#!/usr/bin/env bash\necho 'stub audit run'\nexit {exit_code}\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return bin_dir


def _run_audit_step(
    tmp_path: Path, exit_code: int, workflow: Path = SCHEDULED
) -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = _stub_uv(tmp_path, exit_code)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    step_name = (
        "Run isolated audit shard"
        if workflow == PULL_REQUEST
        else "Run audit on all configured repositories"
    )
    result = _bash(
        _run_block(workflow, step_name).replace("${{ matrix.shard_index }}", "0"),
        tmp_path,
        {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(outputs),
            "AUDIT_MODE": "all",
            "BASE_REF": "origin/dev",
        },
    )
    return result, outputs.read_text(encoding="utf-8")


def _run_smoke_step(
    tmp_path: Path, exit_code: int
) -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = _stub_uv(tmp_path, exit_code)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    result = _bash(
        _run_block(PULL_REQUEST, "Run fast single-release smoke audit"),
        tmp_path,
        {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(outputs),
        },
    )
    return result, outputs.read_text(encoding="utf-8")


def _run_aggregate_step(
    tmp_path: Path, exit_code: int, workflow: Path = PULL_REQUEST
) -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = _stub_uv(tmp_path, exit_code)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    _write_shard_artifacts(tmp_path)
    result = _bash(
        _run_block(workflow, "Aggregate safe shard reports and deltas"),
        tmp_path,
        {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(outputs),
        },
    )
    return result, outputs.read_text(encoding="utf-8")


def _write_shard_artifacts(tmp_path: Path, count: int = PRODUCTION_SHARD_COUNT):
    for index in range(count):
        shard = tmp_path / "shard-artifacts" / f"shard-{index}"
        shard.mkdir(parents=True)
        (shard / "audit-exit.txt").write_text("0\n", encoding="utf-8")
        (shard / "security-report.json").write_text("{}\n", encoding="utf-8")
        (shard / "security-verdict-delta.json").write_text("{}\n", encoding="utf-8")


def _run_real_aggregate_step(
    tmp_path: Path, workflow: Path = PULL_REQUEST
) -> tuple[subprocess.CompletedProcess, str, Path]:
    outputs = tmp_path / "real_github_output"
    outputs.write_text("", encoding="utf-8")
    aggregate_output = tmp_path / "aggregate-output"
    script = _run_block(workflow, "Aggregate safe shard reports and deltas")
    script = script.replace("shard-artifacts", str(tmp_path / "shard-artifacts"))
    script = script.replace("security-reports", str(aggregate_output))
    script = script.replace(
        "uv run python audit_plugins.py",
        f"{shlex.quote(sys.executable)} {shlex.quote(str(ROOT / 'audit_plugins.py'))}",
    )
    result = _bash(
        script,
        ROOT,
        {"GITHUB_OUTPUT": str(outputs)},
    )
    return result, outputs.read_text(encoding="utf-8"), aggregate_output


def _run_executable_empty_shards(tmp_path: Path) -> list[Path]:
    shard_paths = []
    for index in range(PRODUCTION_SHARD_COUNT):
        shard = tmp_path / "shard-artifacts" / f"shard-{index}"
        shard.mkdir(parents=True)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "audit_plugins.py"),
                "--changed",
                "--base-ref",
                "HEAD",
                "--shard-count",
                str(PRODUCTION_SHARD_COUNT),
                "--shard-index",
                str(index),
                "--output-dir",
                str(shard),
                "--verdict-delta",
                str(shard / "security-verdict-delta.json"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        (shard / "audit-exit.txt").write_text("0\n", encoding="utf-8")
        shard_paths.append(shard)
    return shard_paths


@pytest.mark.parametrize("audit_exit", [0, 2, 3, 4])
def test_audit_step_lets_publication_proceed_for_audit_results(tmp_path, audit_exit):
    result, outputs = _run_audit_step(tmp_path, audit_exit)

    assert result.returncode == 0, result.stderr
    assert f"audit_exit={audit_exit}" in outputs
    assert "publishable=true" in outputs


def test_audit_step_records_internal_error_for_the_aggregate_guard(tmp_path):
    result, outputs = _run_audit_step(tmp_path, 1)

    assert result.returncode == 0
    assert "audit_exit=1" in outputs
    assert "publishable=false" in outputs


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
def test_shard_step_rejects_unexpected_exit_without_publishable_output(
    tmp_path, workflow
):
    result, outputs = _run_audit_step(tmp_path, 7, workflow)

    assert result.returncode == 1
    assert "audit_exit=7" in outputs
    assert "publishable=false" in outputs


@pytest.mark.parametrize("audit_exit", [0, 2, 3, 4])
def test_smoke_step_marks_only_safe_results_publishable(tmp_path, audit_exit):
    result, outputs = _run_smoke_step(tmp_path, audit_exit)

    assert result.returncode == 0, result.stderr
    assert f"audit_exit={audit_exit}" in outputs
    assert "publishable=true" in outputs


@pytest.mark.parametrize("audit_exit", [1, 7, 130])
def test_smoke_step_rejects_unsafe_results(tmp_path, audit_exit):
    result, outputs = _run_smoke_step(tmp_path, audit_exit)

    assert result.returncode == audit_exit
    assert f"audit_exit={audit_exit}" in outputs
    assert "publishable=false" in outputs


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
@pytest.mark.parametrize("audit_exit", [0, 2, 3, 4])
def test_aggregate_step_marks_only_safe_results_publishable(
    tmp_path, workflow, audit_exit
):
    result, outputs = _run_aggregate_step(tmp_path, audit_exit, workflow)

    assert result.returncode == 0, result.stderr
    assert f"audit_exit={audit_exit}" in outputs
    assert "publishable=true" in outputs


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
@pytest.mark.parametrize("audit_exit", [1, 7])
def test_aggregate_step_rejects_unsafe_results(tmp_path, workflow, audit_exit):
    result, outputs = _run_aggregate_step(tmp_path, audit_exit, workflow)

    assert result.returncode == audit_exit
    assert f"audit_exit={audit_exit}" in outputs
    assert "publishable=false" in outputs


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
def test_workflow_aggregates_fourteen_executable_empty_shards(tmp_path, workflow):
    tracked_verdict_path = ROOT / "security-verdicts.json"
    tracked_verdict_bytes = tracked_verdict_path.read_bytes()
    shards = _run_executable_empty_shards(tmp_path)

    assert len({(shard / "security-report.json").read_bytes() for shard in shards}) == 1
    assert len({(shard / "security-report.md").read_bytes() for shard in shards}) == 1
    assert all(
        (shard / "security-verdict-delta.json").read_text(encoding="utf-8") == "{}\n"
        for shard in shards
    )

    result, outputs, aggregate_output = _run_real_aggregate_step(tmp_path, workflow)

    assert result.returncode == 0, result.stderr
    assert "audit_exit=0" in outputs
    assert "publishable=true" in outputs
    assert (aggregate_output / "security-report.json").read_bytes() == (
        shards[0] / "security-report.json"
    ).read_bytes()
    assert (aggregate_output / "security-report.md").read_bytes() == (
        shards[0] / "security-report.md"
    ).read_bytes()
    assert (aggregate_output / "security-verdict-delta.json").read_text(
        encoding="utf-8"
    ) == "{}\n"
    assert tracked_verdict_path.read_bytes() == tracked_verdict_bytes


def test_workflow_aggregation_merges_one_delta_with_thirteen_empty_shards(tmp_path):
    shards = _run_executable_empty_shards(tmp_path)
    report = ap.AuditReport(
        audit_timestamp="2026-08-08T00:00:00Z",
        repository="https://github.com/owner/repo",
        release="v1",
        release_id="v1@10",
        github_release_id="1",
        asset_id="10",
        artifact_sha256="a" * 64,
        artifact_url="https://example.invalid/v1.zip",
        identity_status="CURRENT",
        resolved_tag_commit_sha="commit",
        audit_context_hash="context",
        final_classification="PASS",
        completion_status="completed",
    )
    report_payload = {
        "schema_version": ap.AUDIT_SCHEMA_VERSION,
        "policy_version": ap.POLICY_VERSION,
        "generated_at": report.audit_timestamp,
        "report_count": 1,
        "reports": [ap._report_to_dict(report)],
    }
    expected_delta = ap._verdict_delta_from_reports([report])
    (shards[13] / "security-report.json").write_text(
        json.dumps(report_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (shards[13] / "security-verdict-delta.json").write_text(
        json.dumps(expected_delta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result, outputs, aggregate_output = _run_real_aggregate_step(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "audit_exit=0" in outputs
    aggregate_report = json.loads(
        (aggregate_output / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate_report["report_count"] == 1
    assert [item["release_id"] for item in aggregate_report["reports"]] == ["v1@10"]
    assert (
        json.loads(
            (aggregate_output / "security-verdict-delta.json").read_text(
                encoding="utf-8"
            )
        )
        == expected_delta
    )


@pytest.mark.parametrize(
    ("workflow", "step_name", "condition"),
    [
        (
            PULL_REQUEST,
            "Upload isolated shard evidence",
            "always() && steps.audit.outputs.publishable == 'true'",
        ),
        (
            PULL_REQUEST,
            "Upload aggregate audit evidence",
            "always() && steps.aggregate.outputs.publishable == 'true'",
        ),
        (
            PULL_REQUEST,
            "Upload smoke audit report",
            "always() && steps.smoke.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Save audit cache",
            "always() && steps.audit.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Upload isolated scheduled evidence",
            "always() && steps.audit.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Merge publishable verdict delta",
            "steps.aggregate.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Snapshot published verdicts",
            "steps.aggregate.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Publish updated verdicts",
            "steps.aggregate.outputs.publishable == 'true'",
        ),
        (
            SCHEDULED,
            "Upload aggregate scheduled evidence",
            "always() && steps.aggregate.outputs.publishable == 'true'",
        ),
    ],
)
def test_publication_steps_require_executed_publishable_output(
    workflow, step_name, condition
):
    actual = _step_if(workflow, step_name)

    assert actual == condition


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
def test_aggregate_guard_rejects_nonzero_shard_run_global_error_before_publication(
    tmp_path, workflow
):
    _write_shard_artifacts(tmp_path)
    (tmp_path / "shard-artifacts/shard-7/audit-exit.txt").write_text(
        "1\n", encoding="utf-8"
    )

    result = _bash(
        _run_block(workflow, "Aggregate safe shard reports and deltas"),
        tmp_path,
        {},
    )

    assert result.returncode == 1
    assert not (tmp_path / "security-reports").exists()


@pytest.mark.parametrize("workflow", [PULL_REQUEST, SCHEDULED])
@pytest.mark.parametrize(
    "artifact_name",
    ["audit-exit.txt", "security-report.json", "security-verdict-delta.json"],
)
def test_aggregate_guard_requires_all_fourteen_artifacts(
    tmp_path, workflow, artifact_name
):
    _write_shard_artifacts(tmp_path)
    (tmp_path / "shard-artifacts" / "shard-13" / artifact_name).unlink()

    result = _bash(
        _run_block(workflow, "Aggregate safe shard reports and deltas"),
        tmp_path,
        {},
    )

    assert result.returncode == 1


def _run_enforcement_step(tmp_path: Path, audit_exit: str):
    return _bash(
        _run_block(SCHEDULED, "Enforcement result"),
        tmp_path,
        {"AUDIT_EXIT": audit_exit},
    )


def test_enforcement_result_fails_the_job_on_block(tmp_path):
    result = _run_enforcement_step(tmp_path, "2")

    assert result.returncode == 2
    assert "::error::" in result.stdout


def test_enforcement_result_warns_but_passes_on_manual_review(tmp_path):
    result = _run_enforcement_step(tmp_path, "3")

    assert result.returncode == 0, result.stderr
    assert "::warning::" in result.stdout
    assert "::error::" not in result.stdout


def test_enforcement_result_fails_on_publishable_release_incompleteness(tmp_path):
    result = _run_enforcement_step(tmp_path, "4")

    assert result.returncode == 4
    assert "::error::" in result.stdout


def test_enforcement_result_passes_when_clean(tmp_path):
    result = _run_enforcement_step(tmp_path, "0")

    assert result.returncode == 0, result.stderr
    assert "::error::" not in result.stdout
    assert "::warning::" not in result.stdout


def test_enforcement_result_fails_on_an_unrecognised_exit_code(tmp_path):
    result = _run_enforcement_step(tmp_path, "7")

    assert result.returncode == 1
    assert "::error::" in result.stdout


def test_verdicts_are_published_before_the_enforcement_verdict_is_applied():
    text = SCHEDULED.read_text(encoding="utf-8")

    assert text.index(
        "      - name: Run audit on all configured repositories\n"
    ) < text.index("      - name: Publish updated verdicts\n")
    assert text.index("      - name: Publish updated verdicts\n") < text.index(
        "      - name: Enforcement result\n"
    )


def test_pull_request_audit_still_fails_on_enforcement_exit_codes():
    """The PR audit is the gate for newly added plugins and must stay strict."""
    text = (WORKFLOWS / "plugin-security-audit.yml").read_text(encoding="utf-8")

    assert "Apply PR enforcement result after publication" in text
    assert '2) echo "::error::Audit produced BLOCK findings."; exit 2' in text
    assert '3) echo "::error::Audit produced MANUAL_REVIEW findings."; exit 3' in text
    assert (
        '4) echo "::error::Audit has publishable release-local incompleteness."; exit 4'
        in text
    )
