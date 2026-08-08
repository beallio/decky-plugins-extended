"""Exercise the PR workflow's audit-mode shell step against real diff paths."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "plugin-security-audit.yml"


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
    bin_dir.mkdir()
    git = bin_dir / "git"
    git.write_text(
        "#!/usr/bin/env bash\n"
        "if [[ $1 == diff ]]; then\n"
        + "  printf '%s\\n' "
        + " ".join(repr(path) for path in changed_paths)
        + "\n  exit 0\nfi\n"
        + "echo unexpected git invocation >&2\nexit 1\n",
        encoding="utf-8",
    )
    git.chmod(0o755)
    return bin_dir


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
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    bin_dir = _fake_git(tmp_path, changed_paths)
    environment = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_BASE_REF": "dev",
        "EVENT_NAME": "pull_request",
        "DISPATCH_MODE": "",
        "GITHUB_OUTPUT": str(output),
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

    assert result.returncode == 0, result.stderr
    assert f"audit_mode={expected_mode}" in output.read_text(encoding="utf-8")


def test_full_corpus_is_four_isolated_shards():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "shard_index: [0, 1, 2, 3]" in workflow
    assert "--shard-count 4" in workflow
    assert '--shard-index "${{ matrix.shard_index }}"' in workflow
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
