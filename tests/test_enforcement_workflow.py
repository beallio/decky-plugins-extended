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
import audit_worklist

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
            "WORKLIST_FINGERPRINT": "a" * 64,
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
        (shard / "shard-manifest.json").write_text("{}\n", encoding="utf-8")


def _prepare_empty_worklist(tmp_path: Path) -> tuple[Path, str]:
    worklist_path = tmp_path / "audit-worklist" / "worklist.json"
    fingerprint, _document = audit_worklist.prepare_audit_worklist(
        worklist_path,
        source_revision="a" * 40,
        selection_mode="none",
        repository_urls=[],
        shard_count=PRODUCTION_SHARD_COUNT,
        latest_only=False,
        release_fetcher=lambda *_args: [],
        metadata_fetcher=lambda *_args: {},
        tag_resolver=lambda *_args: {},
    )
    return worklist_path, fingerprint


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
        "audit-worklist/worklist.json",
        str(tmp_path / "audit-worklist" / "worklist.json"),
    )
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
    worklist_path, fingerprint = _prepare_empty_worklist(tmp_path)
    shard_paths = []
    for index in range(PRODUCTION_SHARD_COUNT):
        shard = tmp_path / "shard-artifacts" / f"shard-{index}"
        shard.mkdir(parents=True)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "audit_plugins.py"),
                "--worklist",
                str(worklist_path),
                "--expected-worklist-fingerprint",
                fingerprint,
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


def test_workflow_aggregation_enforces_coverage_and_merges_shard_deltas(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    _write_coverage_shards(tmp_path, plan)
    for index in range(PRODUCTION_SHARD_COUNT):
        (tmp_path / "shard-artifacts" / f"shard-{index}" / "audit-exit.txt").write_text(
            "0\n", encoding="utf-8"
        )

    result, outputs, aggregate_output = _run_real_aggregate_step(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "audit_exit=0" in outputs
    aggregate_report = json.loads(
        (aggregate_output / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate_report["report_count"] == 3
    assert sorted(item["release_id"] for item in aggregate_report["reports"]) == [
        "v1@10",
        "v1@30",
        "v2@20",
    ]
    assert json.loads(
        (aggregate_output / "security-verdict-delta.json").read_text(encoding="utf-8")
    ) == ap._verdict_delta_from_reports(
        [report for shard in plan for report in shard["reports"]]
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
    [
        "audit-exit.txt",
        "security-report.json",
        "security-verdict-delta.json",
        "shard-manifest.json",
    ],
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


# ---------------------------------------------------------------------------
# Task 5 -- aggregate coverage must be proven against the prepared worklist
# ---------------------------------------------------------------------------

COVERAGE_SOURCE_REVISION = "a" * 40


def _coverage_release(tag: str, release_id: int, asset_id: int, owner: str, repo: str):
    return {
        "id": release_id,
        "tag_name": tag,
        "published_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
        "prerelease": False,
        "draft": False,
        "assets": [
            {
                "id": asset_id,
                "name": f"plugin-{tag}.zip",
                "browser_download_url": (
                    f"https://github.com/{owner}/{repo}"
                    f"/releases/download/{tag}/plugin-{tag}.zip"
                ),
                "digest": f"sha256:{'a' * 64}",
            }
        ],
    }


def _prepare_coverage_worklist(
    tmp_path: Path, *, empty: bool = False, repository_error: bool = False
):
    """Prepare one real multi-repository (or empty) worklist document."""
    releases = {
        ("owner", "repo"): [
            _coverage_release("v2", 2, 20, "owner", "repo"),
            _coverage_release("v1", 1, 10, "owner", "repo"),
        ],
        ("owner", "other"): [_coverage_release("v1", 3, 30, "owner", "other")],
        ("owner", "renamed"): [_coverage_release("v1", 4, 40, "owner", "renamed")],
    }
    worklist_path = tmp_path / "audit-worklist" / "worklist.json"
    worklist_path.parent.mkdir()
    fingerprint, _document = audit_worklist.prepare_audit_worklist(
        worklist_path,
        source_revision=COVERAGE_SOURCE_REVISION,
        selection_mode="none" if empty else "all",
        repository_urls=[]
        if empty
        else [
            "https://github.com/owner/other",
            "https://github.com/owner/repo",
            *(["https://github.com/owner/renamed"] if repository_error else []),
        ],
        shard_count=PRODUCTION_SHARD_COUNT,
        latest_only=False,
        release_fetcher=lambda owner, repo: releases[(owner, repo)],
        metadata_fetcher=lambda owner, repo: {
            "full_name": "owner/redirected"
            if repository_error and (owner, repo) == ("owner", "renamed")
            else f"{owner}/{repo}",
            "archived": False,
        },
        tag_resolver=lambda owner, repo, *_args: {"v1": "f" * 40, "v2": "e" * 40},
        api_deadline_seconds=8,
    )
    return worklist_path, fingerprint


def _coverage_report(
    item,
    *,
    classification: str = "PASS",
    completion_status: str = "completed",
):
    identity = audit_worklist.worklist_identity(item)
    return ap.AuditReport(
        audit_timestamp="2026-08-18T00:00:00Z",
        repository=identity["repository"],
        release=item["tag_name"],
        release_id=f"{item['tag_name']}@{identity['asset_id']}",
        github_release_id=identity["github_release_id"],
        asset_id=identity["asset_id"],
        artifact_sha256="b" * 64,
        artifact_url=item["asset_url"],
        identity_status="CURRENT",
        resolved_tag_commit_sha=item["resolved_source_commit_sha"],
        audit_context_hash="c" * 64,
        final_classification=classification,
        completion_status=completion_status,
    )


def _coverage_shard_plan(worklist_path: Path):
    """Describe the fourteen shard artifacts a compliant run would upload."""
    document = audit_worklist.load_worklist_document(worklist_path)
    payload = document["payload"]
    plan = []
    for index in range(payload["shard_count"]):
        items = audit_worklist.select_worklist_shard(payload, index)
        plan.append(
            {
                "directory": f"shard-{index}",
                "shard_index": index,
                "shard_count": payload["shard_count"],
                "worklist_fingerprint": document["fingerprint"],
                "source_revision": payload["source_revision"],
                "reports": [_coverage_report(item) for item in items],
                "assigned": [audit_worklist.worklist_identity(item) for item in items],
            }
        )
    return document, plan


def _write_coverage_shards(tmp_path: Path, plan):
    """Materialize each shard's report, delta, and byte-bound manifest."""
    artifacts = {"reports": [], "deltas": [], "manifests": []}
    for shard in plan:
        directory = tmp_path / "shard-artifacts" / shard["directory"]
        directory.mkdir(parents=True, exist_ok=True)
        report_json = directory / "security-report.json"
        report_markdown = directory / "security-report.md"
        verdict_delta = directory / "security-verdict-delta.json"
        progress = directory / "progress.json"

        reports = shard["reports"]
        report_json.write_text(
            json.dumps(
                {
                    "schema_version": ap.AUDIT_SCHEMA_VERSION,
                    "policy_version": ap.POLICY_VERSION,
                    "generated_at": "2026-08-18T00:00:00Z",
                    "report_count": len(reports),
                    "reports": [ap._report_to_dict(report) for report in reports],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        report_markdown.write_text("# shard\n", encoding="utf-8")
        verdict_delta.write_text(
            json.dumps(
                shard.get("delta", ap._verdict_delta_from_reports(reports)),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        progress.write_text("{}\n", encoding="utf-8")

        report_identities = shard.get(
            "report_identities",
            [ap._report_manifest_identity(report) for report in reports],
        )
        manifest = {
            "schema_version": ap._SHARD_MANIFEST_SCHEMA_VERSION,
            "worklist_fingerprint": shard["worklist_fingerprint"],
            "source_revision": shard["source_revision"],
            "shard_count": shard["shard_count"],
            "shard_index": shard["shard_index"],
            "assigned_identities": shard["assigned"],
            "attempted_identities": shard.get("attempted", report_identities),
            "report_identities": report_identities,
            "artifacts": ap._worker_artifact_bindings(
                {
                    "progress": progress,
                    "report_json": report_json,
                    "report_markdown": report_markdown,
                    "verdict_delta": verdict_delta,
                }
            ),
        }
        manifest_path = directory / "shard-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

        artifacts["reports"].append(str(report_json))
        artifacts["deltas"].append(str(verdict_delta))
        artifacts["manifests"].append(str(manifest_path))
    return artifacts


def _coverage_argv(
    worklist_path,
    artifacts,
    output_dir: Path,
    *,
    include_worklist: bool = True,
    include_manifests: bool = True,
):
    argv = [
        "--aggregate-reports",
        *artifacts["reports"],
        "--aggregate-verdict-deltas",
        *artifacts["deltas"],
    ]
    if include_manifests:
        argv += ["--aggregate-shard-manifests", *artifacts["manifests"]]
    if include_worklist:
        argv += ["--expected-worklist", str(worklist_path)]
    argv += [
        "--output-dir",
        str(output_dir),
        "--verdict-delta",
        str(output_dir / "security-verdict-delta.json"),
    ]
    return argv


def _aggregate_coverage(tmp_path: Path, plan, worklist_path, **kwargs):
    artifacts = _write_coverage_shards(tmp_path, plan)
    output_dir = tmp_path / "security-reports"
    exit_code = ap.main(_coverage_argv(worklist_path, artifacts, output_dir, **kwargs))
    return exit_code, output_dir, artifacts


def test_aggregate_accepts_exact_worklist_coverage(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 0
    aggregate = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate["report_count"] == 3
    assert sorted(item["release_id"] for item in aggregate["reports"]) == [
        "v1@10",
        "v1@30",
        "v2@20",
    ]
    delta = json.loads(
        (output_dir / "security-verdict-delta.json").read_text(encoding="utf-8")
    )
    assert sorted(delta) == [
        "https://github.com/owner/other",
        "https://github.com/owner/repo",
    ]


def test_aggregate_accepts_a_valid_empty_worklist(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path, empty=True)
    document, plan = _coverage_shard_plan(worklist_path)

    assert document["payload"]["items"] == []
    assert all(shard["assigned"] == [] for shard in plan)

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 0
    aggregate = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate["report_count"] == 0
    assert (output_dir / "security-verdict-delta.json").read_text(
        encoding="utf-8"
    ) == "{}\n"


def test_aggregate_counts_release_local_incomplete_reports_as_covered(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    failed = payload["items"][0]
    failed_index = audit_worklist.shard_index_for_worklist_item(
        failed, payload["shard_count"]
    )
    plan[failed_index]["reports"] = [
        _coverage_report(
            failed,
            classification="AUDIT_ERROR",
            completion_status="incomplete",
        )
    ]

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 4
    aggregate = json.loads(
        (output_dir / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate["report_count"] == 3


def test_aggregate_workflow_surfaces_repository_error_and_publishes_siblings(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(
        tmp_path, repository_error=True
    )
    _document, plan = _coverage_shard_plan(worklist_path)
    _write_coverage_shards(tmp_path, plan)
    for index in range(PRODUCTION_SHARD_COUNT):
        (tmp_path / "shard-artifacts" / f"shard-{index}" / "audit-exit.txt").write_text(
            "0\n", encoding="utf-8"
        )

    result, outputs, aggregate_output = _run_real_aggregate_step(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "audit_exit=4" in outputs
    assert "publishable=true" in outputs
    aggregate = json.loads(
        (aggregate_output / "security-report.json").read_text(encoding="utf-8")
    )
    assert aggregate["report_count"] == 4
    repository_error = next(
        report
        for report in aggregate["reports"]
        if report["repository"] == "https://github.com/owner/renamed"
    )
    assert repository_error["final_classification"] == "AUDIT_ERROR"
    assert repository_error["completion_status"] == "incomplete"
    assert repository_error["error_scope"] == "repository"
    assert not repository_error["release_id"]
    delta = json.loads(
        (aggregate_output / "security-verdict-delta.json").read_text(encoding="utf-8")
    )
    assert "https://github.com/owner/renamed" not in delta
    assert sorted(delta) == [
        "https://github.com/owner/other",
        "https://github.com/owner/repo",
    ]


def test_repository_error_cannot_mask_missing_worklist_release_identity(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(
        tmp_path, repository_error=True
    )
    document, plan = _coverage_shard_plan(worklist_path)
    missing_item = document["payload"]["items"][0]
    missing_index = audit_worklist.shard_index_for_worklist_item(
        missing_item, document["payload"]["shard_count"]
    )
    plan[missing_index]["reports"] = [
        report
        for report in plan[missing_index]["reports"]
        if ap._report_manifest_identity(report)
        != audit_worklist.worklist_identity(missing_item)
    ]

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_fourteen_artifacts_missing_one_expected_identity(tmp_path):
    """The gap the artifact-count guard cannot see: complete shards, absent work."""
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    dropped = payload["items"][0]
    dropped_index = audit_worklist.shard_index_for_worklist_item(
        dropped, payload["shard_count"]
    )
    dropped_identity = audit_worklist.worklist_identity(dropped)
    shard = plan[dropped_index]
    shard["reports"] = [
        report
        for report in shard["reports"]
        if ap._report_manifest_identity(report) != dropped_identity
    ]

    exit_code, output_dir, artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert len(artifacts["reports"]) == PRODUCTION_SHARD_COUNT
    assert len(artifacts["manifests"]) == PRODUCTION_SHARD_COUNT
    assert not output_dir.exists()


def test_aggregate_rejects_an_identity_absent_from_the_worklist(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    extra_item = dict(payload["items"][0])
    extra_item["release_id"] = "9001"
    extra_item["asset_id"] = "9002"
    extra_index = audit_worklist.shard_index_for_worklist_item(
        extra_item, payload["shard_count"]
    )
    shard = plan[extra_index]
    shard["reports"] = [*shard["reports"], _coverage_report(extra_item)]
    shard["assigned"] = [
        *shard["assigned"],
        audit_worklist.worklist_identity(extra_item),
    ]

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_manifest_claiming_an_identity_absent_from_its_report(
    tmp_path,
):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    item = payload["items"][0]
    index = audit_worklist.shard_index_for_worklist_item(item, payload["shard_count"])
    shard = plan[index]
    shard["report_identities"] = [
        ap._report_manifest_identity(r) for r in shard["reports"]
    ]
    shard["reports"] = []

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_report_identity_absent_from_its_manifest(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    item = payload["items"][0]
    index = audit_worklist.shard_index_for_worklist_item(item, payload["shard_count"])
    shard = plan[index]
    shard["report_identities"] = []
    shard["attempted"] = []

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_duplicated_shard_index(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    plan[13] = {**plan[0], "directory": "shard-13"}

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_manifest_holding_another_shards_assignment(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    item = payload["items"][0]
    populated = audit_worklist.shard_index_for_worklist_item(
        item, payload["shard_count"]
    )
    empty = next(index for index, shard in enumerate(plan) if not shard["assigned"])
    plan[empty]["assigned"] = list(plan[populated]["assigned"])

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_shard_count_below_the_worklist(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan[:-1], worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_mismatched_worklist_fingerprint(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    plan[7]["worklist_fingerprint"] = "d" * 64

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_mismatched_source_revision(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    plan[7]["source_revision"] = "c" * 40

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_tampered_worklist_payload(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    tampered = json.loads(worklist_path.read_text(encoding="utf-8"))
    tampered["payload"]["items"][0]["release_id"] = 424242
    worklist_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_missing_producer_artifact(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    worklist_path.unlink()

    exit_code, output_dir, _artifacts = _aggregate_coverage(
        tmp_path, plan, worklist_path
    )

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_a_missing_shard_manifest(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    artifacts = _write_coverage_shards(tmp_path, plan)
    Path(artifacts["manifests"][11]).unlink()
    output_dir = tmp_path / "security-reports"

    exit_code = ap.main(_coverage_argv(worklist_path, artifacts, output_dir))

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_rejects_report_bytes_not_bound_to_their_manifest(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    artifacts = _write_coverage_shards(tmp_path, plan)
    tampered = Path(artifacts["reports"][0])
    tampered.write_text(
        tampered.read_text(encoding="utf-8").replace(
            '"report_count"', '"report_count" '
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "security-reports"

    exit_code = ap.main(_coverage_argv(worklist_path, artifacts, output_dir))

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_coverage_arguments_are_required_together(tmp_path):
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    artifacts = _write_coverage_shards(tmp_path, plan)
    output_dir = tmp_path / "security-reports"

    with pytest.raises(SystemExit):
        ap.main(
            _coverage_argv(
                worklist_path, artifacts, output_dir, include_manifests=False
            )
        )
    with pytest.raises(SystemExit):
        ap.main(
            _coverage_argv(worklist_path, artifacts, output_dir, include_worklist=False)
        )
    assert not output_dir.exists()


def test_aggregate_coverage_arguments_are_rejected_outside_aggregate_mode(tmp_path):
    worklist_path, fingerprint = _prepare_coverage_worklist(tmp_path)

    with pytest.raises(SystemExit):
        ap.main(
            [
                "--all",
                "--expected-worklist",
                str(worklist_path),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )
    with pytest.raises(SystemExit):
        ap.main(
            [
                "--worklist",
                str(worklist_path),
                "--expected-worklist-fingerprint",
                fingerprint,
                "--shard-count",
                str(PRODUCTION_SHARD_COUNT),
                "--shard-index",
                "0",
                "--aggregate-shard-manifests",
                str(tmp_path / "shard-manifest.json"),
                "--output-dir",
                str(tmp_path / "out"),
            ]
        )


def _rebind_shard_manifest(manifest_path: str) -> None:
    """Re-sign a manifest's byte bindings after a deliberate report edit."""
    path = Path(manifest_path)
    directory = path.parent
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["artifacts"] = ap._worker_artifact_bindings(
        {
            "progress": directory / "progress.json",
            "report_json": directory / "security-report.json",
            "report_markdown": directory / "security-report.md",
            "verdict_delta": directory / "security-verdict-delta.json",
        }
    )
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_aggregate_rejects_an_identity_incomplete_shard_report(tmp_path):
    """An incomplete record without a full identity cannot count as coverage."""
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    document, plan = _coverage_shard_plan(worklist_path)
    payload = document["payload"]
    item = payload["items"][0]
    index = audit_worklist.shard_index_for_worklist_item(item, payload["shard_count"])
    plan[index]["reports"] = [
        _coverage_report(
            item, classification="AUDIT_ERROR", completion_status="incomplete"
        )
    ]
    artifacts = _write_coverage_shards(tmp_path, plan)

    report_path = Path(artifacts["reports"][index])
    stored = json.loads(report_path.read_text(encoding="utf-8"))
    stored["reports"][0]["asset_id"] = ""
    report_path.write_text(
        json.dumps(stored, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _rebind_shard_manifest(artifacts["manifests"][index])

    output_dir = tmp_path / "security-reports"
    exit_code = ap.main(_coverage_argv(worklist_path, artifacts, output_dir))

    assert exit_code == 1
    assert not output_dir.exists()


def test_aggregate_coverage_is_enforced_by_the_real_command_line(tmp_path):
    """Drive the installed CLI, not just the in-process entry point."""
    worklist_path, _fingerprint = _prepare_coverage_worklist(tmp_path)
    _document, plan = _coverage_shard_plan(worklist_path)
    artifacts = _write_coverage_shards(tmp_path, plan)
    output_dir = tmp_path / "security-reports"
    argv = [
        sys.executable,
        str(ROOT / "audit_plugins.py"),
        *_coverage_argv(worklist_path, artifacts, output_dir),
    ]

    accepted = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)

    assert accepted.returncode == 0, accepted.stderr
    assert (output_dir / "security-report.json").is_file()

    dropped_output = tmp_path / "rejected-reports"
    rejected = subprocess.run(
        [
            *argv[:2],
            *_coverage_argv(
                worklist_path,
                {**artifacts, "manifests": artifacts["manifests"][:-1]},
                dropped_output,
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert rejected.returncode == 1
    assert "Shard aggregation failed" in rejected.stderr
    assert not dropped_output.exists()
