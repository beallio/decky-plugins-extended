import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled-security-audit.yml"


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def _publish_script() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    publish_step = workflow.split(
        "      - name: Publish updated verdicts\n", maxsplit=1
    )[1]
    run_block = publish_step.split("        run: |\n", maxsplit=1)[1]
    run_block = run_block.split("\n      - name:", maxsplit=1)[0]
    return textwrap.dedent(run_block)


def _init_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    origin = tmp_path / "origin.git"
    origin.mkdir()
    subprocess.run(
        ["git", "init", "--bare", "--initial-branch=main"],
        cwd=origin,
        check=True,
        capture_output=True,
        text=True,
    )

    seed = tmp_path / "seed"
    subprocess.run(
        ["git", "clone", str(origin), str(seed)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(seed, "config", "user.name", "fixture")
    _git(seed, "config", "user.email", "fixture@example.invalid")
    (seed / "security-verdicts.json").write_text("{}\n", encoding="utf-8")
    (seed / "runner-noise.txt").write_text("clean\n", encoding="utf-8")
    _git(seed, "add", "security-verdicts.json", "runner-noise.txt")
    _git(seed, "commit", "-m", "seed")
    _git(seed, "push", "origin", "main")

    audit = tmp_path / "audit"
    subprocess.run(
        ["git", "clone", str(origin), str(audit)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(audit, "config", "user.name", "fixture")
    _git(audit, "config", "user.email", "fixture@example.invalid")

    before = tmp_path / "security-verdicts-before.json"
    before.write_text("{}\n", encoding="utf-8")
    return origin, audit, before


def _change_verdicts(repository: Path) -> None:
    verdicts = {
        "owner/plugin": {
            "v1.0.0@1": {
                "artifact_sha256": "a" * 64,
                "classification": "PASS",
            }
        }
    }
    (repository / "security-verdicts.json").write_text(
        json.dumps(verdicts, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _run_publish(
    repository: Path,
    before: Path,
    tmp_path: Path,
    *,
    path_prefix: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "BEFORE_VERDICTS": str(before),
            "GITHUB_REF_NAME": "main",
            "XDG_CACHE_HOME": str(tmp_path / "uv-cache"),
        }
    )
    if path_prefix is not None:
        environment["PATH"] = f"{path_prefix}:{environment['PATH']}"
    if extra_env is not None:
        environment.update(extra_env)

    return subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            _publish_script(),
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
    )


def test_publish_succeeds_with_unstaged_runner_noise(tmp_path):
    origin, audit, before = _init_fixture(tmp_path)
    _change_verdicts(audit)
    (audit / "runner-noise.txt").write_text("runner-only output\n", encoding="utf-8")

    result = _run_publish(audit, before, tmp_path)

    assert result.returncode == 0, result.stderr
    assert _git(origin, "show", "main:security-verdicts.json").stdout == (
        audit / "security-verdicts.json"
    ).read_text(encoding="utf-8")


def test_publish_commit_remains_narrowly_staged(tmp_path):
    origin, audit, before = _init_fixture(tmp_path)
    _change_verdicts(audit)
    (audit / "runner-noise.txt").write_text("must not publish\n", encoding="utf-8")

    result = _run_publish(audit, before, tmp_path)

    assert result.returncode == 0, result.stderr
    changed_paths = _git(
        origin,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "main",
    ).stdout.splitlines()
    assert changed_paths == ["security-verdicts.json"]


def test_unchanged_verdicts_create_no_commit(tmp_path):
    origin, audit, before = _init_fixture(tmp_path)
    original_head = _git(origin, "rev-parse", "main").stdout.strip()
    (audit / "runner-noise.txt").write_text("runner-only output\n", encoding="utf-8")

    result = _run_publish(audit, before, tmp_path)

    assert result.returncode == 0, result.stderr
    assert "No verdict changes to publish." in result.stdout
    assert _git(origin, "rev-parse", "main").stdout.strip() == original_head


def test_publish_rebases_and_retries_once_after_losing_race(tmp_path):
    origin, audit, before = _init_fixture(tmp_path)
    _change_verdicts(audit)

    competitor = tmp_path / "competitor"
    subprocess.run(
        ["git", "clone", str(origin), str(competitor)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git(competitor, "config", "user.name", "competitor")
    _git(competitor, "config", "user.email", "competitor@example.invalid")
    (competitor / "competing-change.txt").write_text("keep me\n", encoding="utf-8")
    _git(competitor, "add", "competing-change.txt")
    _git(competitor, "commit", "-m", "competing update")

    wrapper_dir = tmp_path / "wrapper"
    wrapper_dir.mkdir()
    wrapper = wrapper_dir / "git"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "push" && ! -e "$RACE_FLAG" ]]; then
  touch "$RACE_FLAG"
  "$REAL_GIT" -C "$RACE_REPOSITORY" push origin main
fi
exec "$REAL_GIT" "$@"
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)

    result = _run_publish(
        audit,
        before,
        tmp_path,
        path_prefix=wrapper_dir,
        extra_env={
            "RACE_FLAG": str(tmp_path / "race-triggered"),
            "RACE_REPOSITORY": str(competitor),
            "REAL_GIT": shutil.which("git") or "git",
        },
    )

    assert result.returncode == 0, result.stderr
    assert "Initial verdict push raced with another update" in result.stdout
    assert _git(origin, "show", "main:competing-change.txt").stdout == "keep me\n"
    subjects = _git(origin, "log", "--format=%s", "main").stdout.splitlines()
    assert "competing update" in subjects
    assert "chore(security): publish 1 changed verdicts" in subjects


def test_failed_commit_preserves_modified_verdicts(tmp_path):
    _, audit, before = _init_fixture(tmp_path)
    _change_verdicts(audit)
    modified_verdicts = (audit / "security-verdicts.json").read_text(encoding="utf-8")

    wrapper_dir = tmp_path / "wrapper"
    wrapper_dir.mkdir()
    wrapper = wrapper_dir / "git"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "commit" ]]; then
  echo "forced commit failure" >&2
  exit 42
fi
exec "$REAL_GIT" "$@"
""",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)

    result = _run_publish(
        audit,
        before,
        tmp_path,
        path_prefix=wrapper_dir,
        extra_env={"REAL_GIT": shutil.which("git") or "git"},
    )

    assert result.returncode == 42
    assert "forced commit failure" in result.stderr
    assert (audit / "security-verdicts.json").read_text(
        encoding="utf-8"
    ) == modified_verdicts


def test_dirty_tree_diagnostic_prints_only_status_and_paths(tmp_path):
    _, audit, before = _init_fixture(tmp_path)
    _change_verdicts(audit)
    secret_content = "third-party source contents must not leak"
    (audit / "runner-noise.txt").write_text(secret_content, encoding="utf-8")

    result = _run_publish(audit, before, tmp_path)

    assert result.returncode == 0, result.stderr
    assert " M runner-noise.txt" in result.stdout
    assert secret_content not in result.stdout
    assert secret_content not in result.stderr
