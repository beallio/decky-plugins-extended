"""Executable contract tests for the fail-closed scanner bootstrap script."""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-security-scanners"
EXPECTED_FINGERPRINT = "825AD9036F7C850E6A6FED4935B8ACA44FD9CA9F"


def _write_executable(path: Path, text: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + text, encoding="utf-8")
    path.chmod(0o755)


def _fake_environment(tmp_path: Path, **overrides: str) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    command_log = tmp_path / "commands.log"
    fake_bin = tmp_path / "semgrep-bin"
    fake_bin.mkdir(exist_ok=True)
    clamav_db = tmp_path / "clamav" / "main.cvd"
    clamav_db.parent.mkdir(exist_ok=True)
    clamav_db.write_text("database", encoding="utf-8")

    _write_executable(
        bin_dir / "timeout",
        """
printf '%s\\n' "timeout $*" >> "$FAKE_COMMAND_LOG"
[[ "$1" == "--foreground" ]] && shift
duration="$1"
shift
if [[ "${FAKE_TIMEOUT_MATCH:-}" != "" && "$*" == *"${FAKE_TIMEOUT_MATCH}"* ]]; then
  exit "${FAKE_TIMEOUT_STATUS:-124}"
fi
exec "$@"
""",
    )
    _write_executable(
        bin_dir / "sudo",
        """
printf '%s\\n' "sudo $*" >> "$FAKE_COMMAND_LOG"
[[ "$1" == "-n" ]] && shift
exec "$@"
""",
    )
    _write_executable(
        bin_dir / "wget",
        """
printf '%s\\n' "wget $*" >> "$FAKE_COMMAND_LOG"
[[ "${FAKE_WGET_STATUS:-0}" == 0 ]] || exit "$FAKE_WGET_STATUS"
if [[ -n "${FAKE_WGET_FAIL_ONCE_PATH:-}" && ! -e "$FAKE_WGET_FAIL_ONCE_PATH" ]]; then
  : > "$FAKE_WGET_FAIL_ONCE_PATH"
  exit 1
fi
while (( $# )); do
  if [[ "$1" == "-O" ]]; then
    printf 'key' > "$2"
    break
  fi
  shift
done
""",
    )
    _write_executable(
        bin_dir / "gpg",
        f"""
printf '%s\\n' "gpg $*" >> "$FAKE_COMMAND_LOG"
if [[ "$*" == *"--show-keys"* ]]; then
  printf 'fpr:::::::::{EXPECTED_FINGERPRINT}:\\n'
  exit 0
fi
while (( $# )); do
  if [[ "$1" == "--output" ]]; then
    : > "$2"
    exit 0
  fi
  shift
done
""",
    )
    _write_executable(
        bin_dir / "uv",
        """
printf '%s\\n' "uv $*" >> "$FAKE_COMMAND_LOG"
if [[ "$1" == "tool" && "$2" == "dir" ]]; then
  printf '%s\\n' "$FAKE_SEMGREP_BIN"
fi
""",
    )
    _write_executable(
        bin_dir / "semgrep",
        'printf "%s\\n" "${FAKE_SEMGREP_VERSION:-1.132.0}"\n',
    )
    for name in (
        "apt-get",
        "systemctl",
        "freshclam",
        "trivy",
        "clamscan",
        "lsb_release",
    ):
        _write_executable(
            bin_dir / name,
            f'printf \'%s\\n\' "{name} $*" >> "$FAKE_COMMAND_LOG"\n',
        )
    _write_executable(
        bin_dir / "ls",
        """
[[ "${FAKE_CLAMAV_DB_MISSING:-0}" == 0 ]] || exit 2
printf '%s\\n' "$*" >> "$FAKE_COMMAND_LOG"
""",
    )
    _write_executable(
        bin_dir / "install",
        'source="${@: -2:1}"\ndestination="${@: -1}"\ncp "$source" "$destination"\n',
    )

    environment = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_COMMAND_LOG": str(command_log),
        "FAKE_SEMGREP_BIN": str(fake_bin),
        "GITHUB_PATH": str(tmp_path / "github-path"),
        "TRIVY_KEYRING_PATH": str(tmp_path / "trivy.gpg"),
        "TRIVY_SOURCE_LIST_PATH": str(tmp_path / "trivy.list"),
        "CLAMAV_DB_GLOB": str(clamav_db),
    }
    environment.update(overrides)
    return environment


def _run_bootstrap(
    tmp_path: Path, **overrides: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=_fake_environment(tmp_path, **overrides),
        capture_output=True,
        text=True,
    )


def test_scanner_bootstrap_happy_path(tmp_path):
    result = _run_bootstrap(tmp_path)

    assert SCRIPT.is_file()
    assert os.access(SCRIPT, os.X_OK)
    assert result.returncode == 0, result.stderr
    assert "phase=install base packages start=" in result.stdout
    assert "phase=verify Semgrep version end=" in result.stdout
    assert (tmp_path / "github-path").read_text(encoding="utf-8").strip()


def test_scanner_bootstrap_timeout_fails_named_phase(tmp_path):
    result = _run_bootstrap(
        tmp_path,
        FAKE_TIMEOUT_MATCH="freshclam",
        FAKE_TIMEOUT_STATUS="124",
    )

    assert result.returncode != 0
    assert "phase=refresh ClamAV database status=124" in result.stderr


def test_scanner_bootstrap_key_failure_is_not_masked(tmp_path):
    result = _run_bootstrap(tmp_path, FAKE_WGET_STATUS="1")

    assert result.returncode != 0
    assert "phase=download Trivy signing key status=1" in result.stderr
    assert "install Trivy" not in result.stdout


def test_scanner_bootstrap_retries_one_transient_key_download_failure(tmp_path):
    retry_marker = tmp_path / "key-download-retried"
    result = _run_bootstrap(
        tmp_path,
        FAKE_WGET_FAIL_ONCE_PATH=str(retry_marker),
    )

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    assert sum(line.startswith("wget ") for line in commands.splitlines()) == 2


def test_scanner_bootstrap_rejects_wrong_semgrep_version_and_missing_database(tmp_path):
    wrong_version = _run_bootstrap(tmp_path, FAKE_SEMGREP_VERSION="1.131.0")
    missing_database = _run_bootstrap(tmp_path, FAKE_CLAMAV_DB_MISSING="1")

    assert wrong_version.returncode != 0
    assert "expected Semgrep 1.132.0" in wrong_version.stderr
    assert missing_database.returncode != 0
    assert "verify ClamAV database" in missing_database.stderr
