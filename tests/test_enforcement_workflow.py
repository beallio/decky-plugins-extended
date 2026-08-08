"""Enforcement must never withhold the verdicts that produced it.

Under `enforcement.mode: enforce` the audit CLI exits 2 for BLOCK and 3 for
MANUAL_REVIEW. If those exits fail the scheduled audit step, the publish step
that rewrites security-verdicts.json is skipped and the store freezes at
whatever it held before -- the stale-verdict condition enforcement depends on
the store not being in. These tests execute the workflow's own shell blocks.
"""

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCHEDULED = WORKFLOWS / "scheduled-security-audit.yml"


def _run_block(workflow: Path, step_name: str) -> str:
    """Return the shell body of one named workflow step."""
    text = workflow.read_text(encoding="utf-8")
    step = text.split(f"      - name: {step_name}\n", maxsplit=1)[1]
    body = step.split("        run: |\n", maxsplit=1)[1]
    for terminator in ("\n      - name:", "\n        timeout-minutes:"):
        body = body.split(terminator, maxsplit=1)[0]
    return textwrap.dedent(body)


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
    tmp_path: Path, exit_code: int
) -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = _stub_uv(tmp_path, exit_code)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    result = _bash(
        _run_block(SCHEDULED, "Run audit on all configured repositories"),
        tmp_path,
        {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(outputs),
        },
    )
    return result, outputs.read_text(encoding="utf-8")


@pytest.mark.parametrize("audit_exit", [0, 2, 3, 4])
def test_audit_step_lets_publication_proceed_for_audit_results(tmp_path, audit_exit):
    result, outputs = _run_audit_step(tmp_path, audit_exit)

    assert result.returncode == 0, result.stderr
    assert f"audit_exit={audit_exit}" in outputs


def test_audit_step_records_internal_error_for_the_aggregate_guard(tmp_path):
    result, outputs = _run_audit_step(tmp_path, 1)

    # Every shard must upload its exit record so the aggregate job can reject
    # exit 1 before merging or publishing any delta.
    assert result.returncode == 0
    assert "audit_exit=1" in outputs


def test_aggregate_guard_rejects_a_run_global_error_before_publication(tmp_path):
    artifacts = tmp_path / "shard-artifacts"
    for index in range(4):
        shard = artifacts / f"shard-{index}"
        shard.mkdir(parents=True)
        (shard / "audit-exit.txt").write_text("1\n", encoding="utf-8")

    result = _bash(
        _run_block(SCHEDULED, "Aggregate safe shard reports and deltas"),
        tmp_path,
        {},
    )

    assert result.returncode == 1
    assert "no verdicts will be published" in result.stdout


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
