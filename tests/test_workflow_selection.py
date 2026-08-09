"""Exercise the PR workflow's audit-mode shell step against real diff paths."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "plugin-security-audit.yml"
SCHEDULED_WORKFLOW = ROOT / ".github" / "workflows" / "scheduled-security-audit.yml"


def _step_body(step_name: str) -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split(f"      - name: {step_name}\n", maxsplit=1)[1]
    body = step.split("        run: |\n", maxsplit=1)[1]
    lines = []
    for line in body.splitlines():
        if not line.strip():
            lines.append("")
        elif line.startswith("          "):
            lines.append(line.removeprefix("          "))
        else:
            break
    return "\n".join(lines)


def _fake_git(tmp_path: Path, changed_paths: list[str]) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    git = bin_dir / "git"
    git.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" >> "$FAKE_GIT_LOG"\n'
        "if [[ $1 == rev-parse ]]; then\n"
        '  [[ -n "$AVAILABLE_GIT_REF" '
        '&& "${*: -1}" == "${AVAILABLE_GIT_REF}^{commit}" ]]\n'
        "  exit\n"
        "fi\n"
        "if [[ $1 == diff ]]; then\n"
        + "  printf '%s\\n' "
        + " ".join(repr(path) for path in changed_paths)
        + "\n  exit 0\nfi\n"
        + "echo unexpected git invocation >&2\nexit 1\n",
        encoding="utf-8",
    )
    git.chmod(0o755)
    return bin_dir


def _read_outputs(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", maxsplit=1)
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def _run_selection(
    tmp_path: Path,
    changed_paths: list[str],
    *,
    event_name: str,
    dispatch_mode: str,
    available_git_ref: str,
) -> tuple[subprocess.CompletedProcess[str], dict[str, str], Path]:
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    git_log = tmp_path / "git-log"
    bin_dir = _fake_git(tmp_path, changed_paths)
    environment = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_BASE_REF": "dev",
        "EVENT_NAME": event_name,
        "DISPATCH_MODE": dispatch_mode,
        "GITHUB_OUTPUT": str(output),
        "FAKE_GIT_LOG": str(git_log),
        "AVAILABLE_GIT_REF": available_git_ref,
    }
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _step_body("Determine audit mode"),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    return result, _read_outputs(output), git_log


def _run_audit_shard(
    tmp_path: Path, *, audit_mode: str, base_ref: str
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    uv_args = tmp_path / "uv-args"
    uv = bin_dir / "uv"
    uv.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "$@" > "$FAKE_UV_ARGS"\nexit 0\n',
        encoding="utf-8",
    )
    uv.chmod(0o755)
    output = tmp_path / "shard-output"
    output.write_text("", encoding="utf-8")
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _step_body("Run isolated audit shard").replace(
                "${{ matrix.shard_index }}", "0"
            ),
        ],
        cwd=tmp_path,
        env=os.environ
        | {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_OUTPUT": str(output),
            "FAKE_UV_ARGS": str(uv_args),
            "AUDIT_MODE": audit_mode,
            "BASE_REF": base_ref,
        },
        capture_output=True,
        text=True,
    )
    return result, uv_args.read_text(encoding="utf-8").splitlines()


def _run_selection_summary(
    tmp_path: Path, outputs: dict[str, str]
) -> tuple[subprocess.CompletedProcess[str], str]:
    summary = tmp_path / "step-summary"
    script = _step_body("Record audit selection summary")
    script = script.replace("${{ matrix.shard_index }}", "0")
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            script,
        ],
        cwd=tmp_path,
        env=os.environ
        | {
            "GITHUB_STEP_SUMMARY": str(summary),
            "SELECTED_AUDIT_MODE": outputs["audit_mode"],
            "SELECTED_BASE_REF": outputs["base_ref"],
            "SELECTION_SUMMARY_STATE": outputs["summary_state"],
        },
        capture_output=True,
        text=True,
    )
    return result, summary.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("changed_paths", "expected_mode"),
    [
        pytest.param(["audit_plugins.py"], "all", id="audit-only"),
        pytest.param(["generate_json.py"], "all", id="generator-only"),
        pytest.param(["check_for_updates.py"], "all", id="update-checker-only"),
        pytest.param(["plugin_release_utils.py"], "all", id="release-utility-only"),
        pytest.param(["security-policy.yml"], "all", id="policy-only"),
        pytest.param(["security-allowlist.yml"], "all", id="allowlist-only"),
        pytest.param(["security-verdicts.json"], "all", id="verdict-store-only"),
        pytest.param(["semgrep-rules.yml"], "all", id="semgrep-rule-only"),
        pytest.param(["pyproject.toml"], "all", id="dependency-manifest-only"),
        pytest.param(["uv.lock"], "all", id="lockfile-only"),
        pytest.param(
            [".github/workflows/scheduled-security-audit.yml"],
            "all",
            id="workflow-only",
        ),
        pytest.param(
            [".github/workflows/plugin-security-audit.yml"],
            "all",
            id="selector-only",
        ),
        pytest.param(
            ["scripts/orchestration-hooks/quality-gates"],
            "all",
            id="quality-gate-only",
        ),
        pytest.param(["tests/test_catalog_gate.py"], "all", id="test-only"),
        pytest.param(["additional_plugins.txt"], "changed", id="plugin-list-only"),
        pytest.param(
            ["additional_plugins.txt", "semgrep-rules.yml"],
            "all",
            id="mixed-plugin-list-security",
        ),
        pytest.param(["README.md"], "none", id="unrelated-only"),
    ],
)
def test_workflow_executes_selector_for_required_path_classes(
    tmp_path: Path, changed_paths: list[str], expected_mode: str
):
    result, outputs, _git_log = _run_selection(
        tmp_path,
        changed_paths,
        event_name="pull_request",
        dispatch_mode="",
        available_git_ref="origin/dev",
    )

    assert result.returncode == 0, result.stderr
    assert outputs["audit_mode"] == expected_mode
    assert outputs["base_ref"] == ("" if expected_mode == "all" else "origin/dev")


@pytest.mark.parametrize(
    (
        "event_name",
        "dispatch_mode",
        "changed_paths",
        "available_git_ref",
        "expected_mode",
        "expected_base_ref",
    ),
    [
        pytest.param(
            "pull_request",
            "",
            ["additional_plugins.txt"],
            "origin/dev",
            "changed",
            "origin/dev",
            id="pull-request-changed",
        ),
        pytest.param(
            "workflow_dispatch",
            "changed",
            [],
            "HEAD~1",
            "changed",
            "HEAD~1",
            id="dispatch-changed",
        ),
        pytest.param(
            "workflow_dispatch",
            "all",
            [],
            "",
            "all",
            "",
            id="dispatch-all",
        ),
    ],
)
def test_workflow_executes_selection_shard_and_summary_with_real_base_ref(
    tmp_path: Path,
    event_name: str,
    dispatch_mode: str,
    changed_paths: list[str],
    available_git_ref: str,
    expected_mode: str,
    expected_base_ref: str,
):
    selection, outputs, git_log = _run_selection(
        tmp_path,
        changed_paths,
        event_name=event_name,
        dispatch_mode=dispatch_mode,
        available_git_ref=available_git_ref,
    )

    assert selection.returncode == 0, selection.stderr
    assert outputs["audit_mode"] == expected_mode
    assert outputs["base_ref"] == expected_base_ref

    shard, shard_args = _run_audit_shard(
        tmp_path, audit_mode=expected_mode, base_ref=expected_base_ref
    )
    assert shard.returncode == 0, shard.stderr
    if expected_mode == "all":
        assert "--all" in shard_args
        assert "--base-ref" not in shard_args
        assert not git_log.exists()
    else:
        base_index = shard_args.index("--base-ref")
        assert shard_args[base_index + 1] == expected_base_ref

    summary_result, summary = _run_selection_summary(tmp_path, outputs)
    assert summary_result.returncode == 0, summary_result.stderr
    assert f"Mode: {expected_mode}" in summary
    assert f"Base ref: {expected_base_ref or 'not required'}" in summary


def test_dispatch_changed_mode_fails_when_head_parent_is_unavailable(tmp_path: Path):
    result, outputs, git_log = _run_selection(
        tmp_path,
        [],
        event_name="workflow_dispatch",
        dispatch_mode="changed",
        available_git_ref="",
    )

    assert result.returncode != 0
    assert "dispatch changed-mode base HEAD~1 is unavailable" in result.stdout
    assert outputs == {}
    assert "rev-parse --verify --quiet HEAD~1^{commit}" in git_log.read_text(
        encoding="utf-8"
    )


def test_full_corpus_is_fourteen_isolated_shards_with_expected_artifact_names():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    scheduled = SCHEDULED_WORKFLOW.read_text(encoding="utf-8")
    matrix = "shard_index: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]"

    audit_shards = workflow.split("  audit-shards:\n", maxsplit=1)[1].split(
        "\n  aggregate-audit:", maxsplit=1
    )[0]
    assert "fetch-depth: 0" in audit_shards
    assert matrix in workflow
    assert matrix in scheduled
    assert "--shard-count 14" in workflow
    assert "--shard-count 14" in scheduled
    assert '--shard-index "${{ matrix.shard_index }}"' in workflow
    assert '--shard-index "$SHARD_INDEX"' in scheduled
    assert "Security Audit (shard ${{ matrix.shard_index }}/14)" in workflow
    assert "Scheduled Audit (shard ${{ matrix.shard_index }}/14)" in scheduled
    assert "Shard ${{ matrix.shard_index }} of 14" in workflow
    assert "security-audit-shard-${{ matrix.shard_index }}-of-14" in workflow
    assert "scheduled-security-audit-shard-${{ matrix.shard_index }}-of-14" in scheduled
    assert "shard-${SHARD_INDEX}-of-14" in scheduled
    assert "${#exit_files[@]} == 14" in workflow
    assert "${#reports[@]} == 14 && ${#deltas[@]} == 14" in workflow
    assert "${#exit_files[@]} == 14" in scheduled
    assert "${#reports[@]} == 14 && ${#deltas[@]} == 14" in scheduled
    assert "--aggregate-reports" in workflow
    assert "--aggregate-verdict-deltas" in workflow


def test_workflow_executes_exact_security_node_collection_gate(tmp_path: Path):
    environment = os.environ | {"RUNNER_TEMP": str(tmp_path)}

    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _step_body(
                "Assert CI collection includes exact security regression node IDs"
            ),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (
        "tests/test_workflow_selection.py::"
        "test_workflow_executes_selector_for_required_path_classes[audit-only]"
    ) in result.stdout
    assert "tests collected" in result.stdout
