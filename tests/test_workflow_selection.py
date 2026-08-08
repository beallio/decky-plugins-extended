"""Exercise the PR workflow's audit-mode shell step against real diff paths."""

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "plugin-security-audit.yml"


def _step_body(step_name: str) -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split(f"      - name: {step_name}\n", maxsplit=1)[1]
    body = step.split("        run: |\n", maxsplit=1)[1]
    return textwrap.dedent(body.split("\n      - name:", maxsplit=1)[0])


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
        (["additional_plugins.txt"], "changed"),
        (["generate_json.py"], "all"),
        (["additional_plugins.txt", "semgrep-rules.yml"], "all"),
        (["README.md"], "none"),
    ],
)
def test_workflow_executes_selector_for_representative_diffs(
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
