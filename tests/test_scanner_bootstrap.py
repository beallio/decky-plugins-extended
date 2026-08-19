"""Executable contract tests for the fail-closed scanner bootstrap script."""

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-security-scanners"
EXPECTED_FINGERPRINT = "825AD9036F7C850E6A6FED4935B8ACA44FD9CA9F"


def _write_executable(
    path: Path, text: str, *, interpreter: str = "/usr/bin/env bash"
) -> None:
    path.write_text(f"#!{interpreter}\nset -euo pipefail\n" + text, encoding="utf-8")
    path.chmod(0o755)


def _fake_environment(
    tmp_path: Path, *, real_timeout: bool = False, **overrides: str
) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    command_log = tmp_path / "commands.log"
    fake_bin = tmp_path / "semgrep-bin"
    fake_bin.mkdir(exist_ok=True)
    clamav_db = tmp_path / "clamav" / "main.cvd"
    clamav_db.parent.mkdir(exist_ok=True)
    clamav_db.write_text("database", encoding="utf-8")

    if not real_timeout:
        _write_executable(
            bin_dir / "timeout",
            """
printf '%s\\n' "timeout $*" >> "$FAKE_COMMAND_LOG"
while [[ "$1" == --kill-after=* ]]; do
  shift
done
[[ "$1" == "--foreground" ]] && shift
duration="$1"
shift
if [[ "${FAKE_TIMEOUT_MATCH:-}" != "" && "$*" == *"${FAKE_TIMEOUT_MATCH}"* ]]; then
  if [[ -n "${FAKE_TIMEOUT_MINIMUM_SECONDS:-}" ]]; then
    duration_seconds="${duration%s}"
    if (( duration_seconds < FAKE_TIMEOUT_MINIMUM_SECONDS )); then
      exit 124
    fi
    exec "$@"
  fi
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
    _write_executable(
        bin_dir / "fuser",
        'printf \'%s\\n\' "fuser $*" >> "$FAKE_COMMAND_LOG"\nexit 1\n',
    )
    _write_executable(
        bin_dir / "dpkg-query",
        """
printf '%s\\n' "dpkg-query $*" >> "$FAKE_COMMAND_LOG"
printf '%s\\n' "${FAKE_DPKG_QUERY_STATE:-not-installed}"
""",
    )
    for name in (
        "apt-get",
        "systemctl",
        "freshclam",
        "trivy",
        "clamscan",
        "lsb_release",
    ):
        output = f'printf \'%s\\n\' "{name} $*" >> "$FAKE_COMMAND_LOG"\n'
        if name == "lsb_release":
            output += "printf '%s\\n' 'jammy'\n"
        _write_executable(
            bin_dir / name,
            output,
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
        "CLAMAV_DB_GLOB": str(clamav_db.parent / "*.c?d"),
    }
    environment.update(overrides)
    if overrides.get("FAKE_CLAMAV_DB_MISSING") == "1":
        clamav_db.unlink()
    return environment


def _run_bootstrap(
    tmp_path: Path,
    *,
    script: Path = SCRIPT,
    real_timeout: bool = False,
    environment: dict[str, str] | None = None,
    **overrides: str,
) -> subprocess.CompletedProcess[str]:
    if environment is None:
        environment = _fake_environment(
            tmp_path, real_timeout=real_timeout, **overrides
        )
    command = ["bash", str(script)]
    if real_timeout:
        command = ["setsid", "--wait", *command]
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )


def _script_with_short_timeouts(tmp_path: Path, **constants: float | int) -> Path:
    script = tmp_path / "install-security-scanners"
    text = SCRIPT.read_text(encoding="utf-8")
    allocation_aliases = {
        "BASE_APT_TIMEOUT_SECONDS": (
            "BASE_APT_MINIMUM_SECONDS",
            "BASE_APT_MAXIMUM_SECONDS",
        ),
        "DPKG_FRONTEND_LOCK_WAIT_TIMEOUT_SECONDS": (
            "WAIT_FOR_DPKG_FRONTEND_LOCK_MINIMUM_SECONDS",
            "WAIT_FOR_DPKG_FRONTEND_LOCK_MAXIMUM_SECONDS",
        ),
    }
    for name, value in constants.items():
        if name in allocation_aliases and allocation_aliases[name][0] in text:
            minimum_name, maximum_name = allocation_aliases[name]
            for allocation_name in (minimum_name, maximum_name):
                text, replacements = re.subn(
                    rf"^{re.escape(allocation_name)}=.*$",
                    f"{allocation_name}={value}",
                    text,
                    count=1,
                    flags=re.MULTILINE,
                )
                assert replacements == 1, f"missing {allocation_name} assignment"
            continue
        text, replacements = re.subn(
            rf"^{re.escape(name)}=.*$",
            f"{name}={value}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        assert replacements == 1, f"missing {name} assignment"
    _write_executable(script, text.removeprefix("#!/usr/bin/env bash\n"))
    return script


def _wait_for_process_exit(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def _terminate_process(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    _wait_for_process_exit(pid, 2)


def _integer_script_constant(name: str) -> int:
    match = re.search(rf"^{re.escape(name)}=(\d+)$", SCRIPT.read_text(), re.MULTILINE)
    assert match, f"missing integer {name} assignment"
    return int(match.group(1))


def _integer_script_constant_from(script: Path, name: str) -> int:
    match = re.search(
        rf"^{re.escape(name)}=(\d+)$", script.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert match, f"missing integer {name} assignment"
    return int(match.group(1))


def _script_with_expired_bootstrap_budget(tmp_path: Path) -> Path:
    script = tmp_path / "install-security-scanners"
    text, replacements = re.subn(
        r'^bootstrap_started_seconds="\$SECONDS"$',
        "bootstrap_started_seconds=$((SECONDS - BOOTSTRAP_TIMEOUT_SECONDS))",
        SCRIPT.read_text(encoding="utf-8"),
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1, "missing bootstrap start-time assignment"
    _write_executable(script, text.removeprefix("#!/usr/bin/env bash\n"))
    return script


def _script_with_tiny_allocation_budget(tmp_path: Path) -> Path:
    """Create a short wall-clock allocation scenario for the reserve contract."""

    script = tmp_path / "install-security-scanners"
    text = SCRIPT.read_text(encoding="utf-8")
    text, replacements = re.subn(
        r"^BOOTSTRAP_TIMEOUT_SECONDS=.*$",
        "BOOTSTRAP_TIMEOUT_SECONDS=25",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1, "missing bootstrap timeout assignment"
    text, replacements = re.subn(
        r"^PHASE_TIMEOUT_KILL_GRACE_SECONDS=.*$",
        "PHASE_TIMEOUT_KILL_GRACE_SECONDS=0",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1, "missing phase kill grace assignment"

    if "BASE_APT_MINIMUM_SECONDS=" not in text:
        text, replacements = re.subn(
            r"^BASE_APT_TIMEOUT_SECONDS=.*$",
            "BASE_APT_TIMEOUT_SECONDS=1",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        assert replacements == 1, "missing fixed base APT timeout assignment"
    else:
        text, minimum_replacements = re.subn(
            r"^([A-Z_]+_MINIMUM_SECONDS)=.*$",
            r"\1=1",
            text,
            flags=re.MULTILINE,
        )
        text, maximum_replacements = re.subn(
            r"^([A-Z_]+_MAXIMUM_SECONDS)=.*$",
            r"\1=8",
            text,
            flags=re.MULTILINE,
        )
        assert minimum_replacements > 0, "missing declared phase minimums"
        assert maximum_replacements > 0, "missing declared phase maximums"

    _write_executable(script, text.removeprefix("#!/usr/bin/env bash\n"))
    return script


def _phase_timeout_seconds(output: str, phase: str) -> int:
    matches = re.findall(
        rf"^phase={re.escape(phase)} start=.* timeout=(\d+)s ",
        output,
        re.MULTILINE,
    )
    assert matches, f"no allocation logged for {phase}"
    return int(matches[-1])


def test_scanner_bootstrap_allows_apt_phase_to_use_remaining_budget(tmp_path):
    result = _run_bootstrap(
        tmp_path,
        FAKE_TIMEOUT_MATCH="apt-get",
        FAKE_TIMEOUT_MINIMUM_SECONDS="91",
    )

    assert result.returncode == 0, result.stderr
    assert "phase=install base packages end=" in result.stdout


def test_scanner_bootstrap_long_early_phase_reserves_later_minimums(tmp_path):
    real_timeout = shutil.which("timeout")
    assert real_timeout, "timeout is required for this test"
    first_attempt = tmp_path / "long-apt-attempt"
    script = _script_with_tiny_allocation_budget(tmp_path)
    script_text, replacements = re.subn(
        r"^NETWORK_ATTEMPTS=.*$",
        "NETWORK_ATTEMPTS=1",
        script.read_text(encoding="utf-8"),
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1, "missing network attempt assignment"
    _write_executable(script, script_text.removeprefix("#!/usr/bin/env bash\n"))
    environment = _fake_environment(tmp_path)
    _write_executable(
        tmp_path / "bin" / "timeout",
        'printf \'%s\\n\' "timeout $*" >> "$FAKE_COMMAND_LOG"\nexec "$REAL_TIMEOUT" "$@"\n',
    )
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* && ! -e "$FAKE_LONG_APT_ATTEMPT" ]]; then
  : > "$FAKE_LONG_APT_ATTEMPT"
  exec /bin/sleep 6
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    result = _run_bootstrap(
        tmp_path,
        script=script,
        environment=environment
        | {"FAKE_LONG_APT_ATTEMPT": str(first_attempt), "REAL_TIMEOUT": real_timeout},
    )

    assert result.returncode == 0, result.stderr
    assert first_attempt.exists()
    assert "phase=refresh ClamAV database end=" in result.stdout
    assert _phase_timeout_seconds(result.stdout, "refresh ClamAV database") >= (
        _integer_script_constant_from(script, "FRESHCLAM_MINIMUM_SECONDS")
    )


def test_scanner_bootstrap_reports_budget_exhaustion_distinct_from_timeout(tmp_path):
    result = _run_bootstrap(
        tmp_path,
        script=_script_with_expired_bootstrap_budget(tmp_path),
    )

    assert result.returncode != 0
    assert "bootstrap budget exhausted" in result.stderr
    assert "status=124 failed" not in result.stderr


def test_scanner_bootstrap_does_not_start_an_unfunded_retry(tmp_path):
    real_timeout = shutil.which("timeout")
    assert real_timeout, "timeout is required for this test"
    first_attempt = tmp_path / "failed-apt-attempt"
    script = _script_with_tiny_allocation_budget(tmp_path)
    environment = _fake_environment(tmp_path)
    _write_executable(
        tmp_path / "bin" / "timeout",
        'exec "$REAL_TIMEOUT" "$@"\n',
    )
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* && ! -e "$FAKE_FAILED_APT_ATTEMPT" ]]; then
  : > "$FAKE_FAILED_APT_ATTEMPT"
  exec /bin/bash -c "sleep 6; exit 1"
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    result = _run_bootstrap(
        tmp_path,
        script=script,
        environment=environment
        | {"FAKE_FAILED_APT_ATTEMPT": str(first_attempt), "REAL_TIMEOUT": real_timeout},
    )

    assert result.returncode == 125
    assert first_attempt.exists()
    assert result.stdout.count("phase=install base packages start=") == 1
    assert "bootstrap budget exhausted" in result.stderr


def test_scanner_bootstrap_splits_retryable_phase_budget_across_attempts(tmp_path):
    """A timed-out first APT attempt leaves a useful allocation for its retry."""

    real_timeout = shutil.which("timeout")
    assert real_timeout, "timeout is required for this test"
    first_attempt = tmp_path / "first-apt-attempt"
    script = _script_with_tiny_allocation_budget(tmp_path)
    script_text, replacements = re.subn(
        r"^APT_RETRY_BACKOFF_SECONDS=.*$",
        "APT_RETRY_BACKOFF_SECONDS=2",
        script.read_text(encoding="utf-8"),
        count=1,
        flags=re.MULTILINE,
    )
    assert replacements == 1, "missing APT retry backoff assignment"
    _write_executable(script, script_text.removeprefix("#!/usr/bin/env bash\n"))

    environment = _fake_environment(tmp_path)
    _write_executable(
        tmp_path / "bin" / "timeout",
        'exec "$REAL_TIMEOUT" "$@"\n',
    )
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* && ! -e "$FAKE_FIRST_APT_ATTEMPT" ]]; then
  : > "$FAKE_FIRST_APT_ATTEMPT"
  exec /bin/sleep 10
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    result = _run_bootstrap(
        tmp_path,
        script=script,
        environment=environment
        | {
            "FAKE_FIRST_APT_ATTEMPT": str(first_attempt),
            "REAL_TIMEOUT": real_timeout,
        },
    )

    timeouts = re.findall(
        r"^phase=install base packages start=.* timeout=(\d+)s ",
        result.stdout,
        re.MULTILINE,
    )
    assert result.returncode == 0, result.stderr
    assert first_attempt.exists()
    assert len(timeouts) == 2
    assert int(timeouts[0]) < _integer_script_constant_from(
        script, "BASE_APT_MAXIMUM_SECONDS"
    )
    assert int(timeouts[1]) > _integer_script_constant_from(
        script, "BASE_APT_MINIMUM_SECONDS"
    )


def test_scanner_bootstrap_declares_consistent_budget_reserves(tmp_path):
    result = _run_bootstrap(tmp_path)
    match = re.search(
        r"bootstrap-budget full-cold-path=(\d+) fixed-overhead=(\d+) total=(\d+) budget=(\d+)",
        result.stdout,
    )

    assert result.returncode == 0, result.stderr
    assert match, result.stdout
    full_cold_path, fixed_overhead, total, budget = map(int, match.groups())
    assert full_cold_path + fixed_overhead == total
    assert total <= budget


def test_scanner_bootstrap_skips_already_present_base_packages(tmp_path):
    result = _run_bootstrap(tmp_path, FAKE_DPKG_QUERY_STATE="installed")

    assert result.returncode == 0, result.stderr
    command_lines = (tmp_path / "commands.log").read_text(encoding="utf-8").splitlines()
    assert "phase=install base packages outcome=skipped" in result.stdout
    assert not any(
        line.startswith("apt-get ") and "clamav" in line for line in command_lines
    )
    full_index_updates = [
        line
        for line in command_lines
        if line.startswith("apt-get ")
        and " update" in line
        and "Dir::Etc::sourcelist=" not in line
    ]
    assert full_index_updates
    trivy_install = next(
        index
        for index, line in enumerate(command_lines)
        if line.startswith("apt-get ")
        and "install -y --no-install-recommends trivy" in line
    )
    assert command_lines.index(full_index_updates[0]) < trivy_install


def test_scanner_bootstrap_refreshes_only_the_trivy_source_after_configuration(
    tmp_path,
):
    result = _run_bootstrap(tmp_path)

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    trivy_updates = [
        line
        for line in commands.splitlines()
        if line.startswith("apt-get ")
        and " update" in line
        and "Dir::Etc::sourcelist=" in line
    ]
    assert trivy_updates
    assert all("Dir::Etc::sourceparts=-" in line for line in trivy_updates)
    assert all(str(tmp_path / "trivy.list") in line for line in trivy_updates)


def test_scanner_bootstrap_happy_path(tmp_path):
    result = _run_bootstrap(tmp_path)

    assert SCRIPT.is_file()
    assert os.access(SCRIPT, os.X_OK)
    assert result.returncode == 0, result.stderr
    assert "dpkg frontend lock check failed" not in result.stderr
    assert "phase=install base packages start=" in result.stdout
    assert "phase=verify Semgrep version end=" in result.stdout
    assert (tmp_path / "github-path").read_text(encoding="utf-8").strip()
    assert f"signed-by={tmp_path / 'trivy.gpg'}" in (tmp_path / "trivy.list").read_text(
        encoding="utf-8"
    )


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


def test_scanner_bootstrap_reaps_timeout_grandchildren_with_real_timeout(tmp_path):
    assert shutil.which("timeout", path=os.environ["PATH"])
    assert shutil.which("setsid", path=os.environ["PATH"])
    grandchild_pid_file = tmp_path / "grandchild.pid"
    script = _script_with_short_timeouts(
        tmp_path,
        NETWORK_ATTEMPTS=1,
        BASE_APT_TIMEOUT_SECONDS=1,
        PHASE_TIMEOUT_KILL_GRACE_SECONDS=1,
    )
    environment = _fake_environment(tmp_path, real_timeout=True)
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* ]]; then
  trap 'exit 143' TERM
  /bin/bash -c 'bash -c "trap \"\" TERM; exec sleep 2" </dev/null >/dev/null 2>&1 & child="$!"; printf "%s\\n" "$child" > "$FAKE_GRANDCHILD_PID_FILE"; wait "$child"' </dev/null >/dev/null 2>&1 &
  wait "$!"
  exit 0
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    pid = None
    try:
        result = _run_bootstrap(
            tmp_path,
            script=script,
            environment=environment
            | {"FAKE_GRANDCHILD_PID_FILE": str(grandchild_pid_file)},
        )
        assert result.returncode != 0
        assert "phase=install base packages status=124" in result.stderr
        assert grandchild_pid_file.exists(), result.stdout + result.stderr
        pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
        assert _wait_for_process_exit(pid, 0.5), result.stderr
    finally:
        if pid is not None:
            _terminate_process(pid)


def test_scanner_bootstrap_reserves_supervisor_cleanup_margin(tmp_path):
    assert shutil.which("timeout", path=os.environ["PATH"])
    assert shutil.which("setsid", path=os.environ["PATH"])
    grandchild_pid_file = tmp_path / "grandchild.pid"
    script = _script_with_short_timeouts(
        tmp_path,
        NETWORK_ATTEMPTS=1,
        BASE_APT_TIMEOUT_SECONDS=1,
        PHASE_TIMEOUT_KILL_GRACE_SECONDS=4,
    )
    environment = _fake_environment(tmp_path, real_timeout=True)
    _write_executable(
        tmp_path / "bin" / "sleep",
        """
if [[ "$1" == "4" ]]; then
  exec /bin/sleep 6
fi
exec /bin/sleep "$@"
""",
    )
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* ]]; then
  trap 'exit 143' TERM
  /bin/bash -c 'bash -c "trap \\\"\\\" TERM; exec sleep 20" </dev/null >/dev/null 2>&1 & child="$!"; printf "%s\\n" "$child" > "$FAKE_GRANDCHILD_PID_FILE"; wait "$child"' </dev/null >/dev/null 2>&1 &
  wait "$!"
  exit 0
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    pid = None
    try:
        result = _run_bootstrap(
            tmp_path,
            script=script,
            environment=environment
            | {"FAKE_GRANDCHILD_PID_FILE": str(grandchild_pid_file)},
        )
        assert result.returncode != 0
        assert grandchild_pid_file.exists(), result.stdout + result.stderr
        pid = int(grandchild_pid_file.read_text(encoding="utf-8"))
        assert _wait_for_process_exit(pid, 0.5), result.stderr
    finally:
        if pid is not None:
            _terminate_process(pid)


def test_scanner_bootstrap_retries_timeout_then_continues_with_real_timeout(tmp_path):
    assert shutil.which("timeout", path=os.environ["PATH"])
    assert shutil.which("setsid", path=os.environ["PATH"])
    retry_marker = tmp_path / "apt-retried"
    script = _script_with_short_timeouts(
        tmp_path,
        BASE_APT_TIMEOUT_SECONDS=1,
        RETRY_BACKOFF_SECONDS=0,
        APT_RETRY_BACKOFF_SECONDS=0,
        PHASE_TIMEOUT_KILL_GRACE_SECONDS=1,
    )
    environment = _fake_environment(tmp_path, real_timeout=True)
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* && ! -e "$FAKE_APT_RETRY_MARKER" ]]; then
  : > "$FAKE_APT_RETRY_MARKER"
  trap 'exit 143' TERM
  /bin/bash -c 'exec sleep 2' </dev/null >/dev/null 2>&1 &
  wait "$!"
  exit 0
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )

    result = _run_bootstrap(
        tmp_path,
        script=script,
        environment=environment | {"FAKE_APT_RETRY_MARKER": str(retry_marker)},
    )

    assert result.returncode == 0, result.stderr
    assert retry_marker.exists()
    assert result.stdout.count("phase=install base packages start=") == 2
    assert "phase=download Trivy signing key end=" in result.stdout


def test_scanner_bootstrap_waits_for_dpkg_lock_before_apt_retry(tmp_path):
    assert shutil.which("timeout", path=os.environ["PATH"])
    assert shutil.which("setsid", path=os.environ["PATH"])
    first_attempt = tmp_path / "first-apt-attempt"
    lock_active = tmp_path / "dpkg-lock-active"
    lock_released = tmp_path / "dpkg-lock-released"
    script = _script_with_short_timeouts(
        tmp_path,
        BASE_APT_TIMEOUT_SECONDS=1,
        RETRY_BACKOFF_SECONDS=0,
        APT_RETRY_BACKOFF_SECONDS=0,
        PHASE_TIMEOUT_KILL_GRACE_SECONDS=1,
    )
    environment = _fake_environment(tmp_path, real_timeout=True)
    _write_executable(
        tmp_path / "bin" / "bash",
        """
if [[ "$1" == "-o" && "$2" == "pipefail" && "$3" == "-c" && "$4" == *"install -y --no-install-recommends"* && ! -e "$FAKE_APT_FIRST_ATTEMPT" ]]; then
  : > "$FAKE_APT_FIRST_ATTEMPT"
  : > "$FAKE_DPKG_LOCK_ACTIVE"
  trap 'exit 143' TERM
  /bin/bash -c 'exec sleep 2' </dev/null >/dev/null 2>&1 &
  wait "$!"
  exit 0
fi
exec /bin/bash "$@"
""",
        interpreter="/bin/bash",
    )
    _write_executable(
        tmp_path / "bin" / "apt-get",
        """
if [[ "$*" == *" update" ]] && [[ -e "$FAKE_DPKG_LOCK_ACTIVE" ]] && [[ ! -e "$FAKE_DPKG_LOCK_RELEASED" ]]; then
  printf '%s\\n' 'E: Could not get lock /var/lib/dpkg/lock-frontend.' >&2
  exit 100
fi
printf '%s\\n' "apt-get $*" >> "$FAKE_COMMAND_LOG"
""",
    )
    _write_executable(
        tmp_path / "bin" / "fuser",
        """
printf '%s\\n' "fuser $*" >> "$FAKE_COMMAND_LOG"
if [[ -e "$FAKE_DPKG_LOCK_ACTIVE" && ! -e "$FAKE_DPKG_LOCK_RELEASED" ]]; then
  exit 0
fi
exit 1
""",
    )
    release_lock = subprocess.Popen(
        [
            "bash",
            "-c",
            'while [[ ! -e "$1" ]]; do sleep 0.01; done; sleep 0.5; : > "$2"',
            "bash",
            str(lock_active),
            str(lock_released),
        ]
    )
    try:
        result = _run_bootstrap(
            tmp_path,
            script=script,
            environment=environment
            | {
                "FAKE_APT_FIRST_ATTEMPT": str(first_attempt),
                "FAKE_DPKG_LOCK_ACTIVE": str(lock_active),
                "FAKE_DPKG_LOCK_RELEASED": str(lock_released),
            },
        )
    finally:
        release_lock.wait(timeout=3)

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    assert any(line.startswith("fuser ") for line in commands.splitlines())
    assert "Could not get lock" not in result.stderr


def test_scanner_bootstrap_fails_closed_when_dpkg_lock_does_not_clear(tmp_path):
    assert shutil.which("timeout", path=os.environ["PATH"])
    assert shutil.which("setsid", path=os.environ["PATH"])
    script = _script_with_short_timeouts(
        tmp_path,
        DPKG_FRONTEND_LOCK_WAIT_TIMEOUT_SECONDS=1,
        PHASE_TIMEOUT_KILL_GRACE_SECONDS=1,
    )
    environment = _fake_environment(tmp_path, real_timeout=True)
    _write_executable(
        tmp_path / "bin" / "fuser",
        'printf \'%s\\n\' "fuser $*" >> "$FAKE_COMMAND_LOG"\nexit 0\n',
    )

    result = _run_bootstrap(
        tmp_path,
        script=script,
        environment=environment,
    )

    assert result.returncode != 0
    assert "phase=wait for dpkg frontend lock (/var/lib/dpkg/lock-frontend)" in (
        result.stderr
    )
    assert "status=124" in result.stderr


def test_scanner_bootstrap_fails_closed_without_fuser(tmp_path):
    environment = _fake_environment(tmp_path)
    bin_dir = tmp_path / "bin"
    (bin_dir / "fuser").unlink()
    for command in ("bash", "cp", "date", "grep", "mktemp", "rm", "tee"):
        location = shutil.which(command)
        assert location, f"{command} is required for this test"
        (bin_dir / command).symlink_to(location)
    environment["PATH"] = str(bin_dir)
    assert shutil.which("fuser", path=environment["PATH"]) is None

    result = _run_bootstrap(tmp_path, environment=environment)

    assert result.returncode != 0
    assert "dpkg frontend lock check requires fuser" in result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    assert not any(line.startswith("apt-get ") for line in commands.splitlines())


def test_scanner_bootstrap_does_not_retry_non_idempotent_service_stop(tmp_path):
    environment = _fake_environment(tmp_path)
    _write_executable(
        tmp_path / "bin" / "systemctl",
        'printf \'%s\\n\' "systemctl $*" >> "$FAKE_COMMAND_LOG"\nexit 1\n',
    )

    result = _run_bootstrap(tmp_path, environment=environment)

    assert result.returncode == 0, result.stderr
    commands = (tmp_path / "commands.log").read_text(encoding="utf-8")
    assert sum(line.startswith("systemctl ") for line in commands.splitlines()) == 1
    assert "warning: could not stop clamav-freshclam" in result.stderr


def test_scanner_bootstrap_enforces_documented_total_budget():
    source = SCRIPT.read_text(encoding="utf-8")

    assert _integer_script_constant("BOOTSTRAP_TIMEOUT_SECONDS") == 600
    assert _integer_script_constant("BASE_APT_MAXIMUM_SECONDS") > 90
    assert _integer_script_constant("TRIVY_APT_MAXIMUM_SECONDS") > 90
    assert "timeout --foreground" not in source
    assert "PHASE_RESERVE_SECONDS" in source
    header = "\n".join(source.splitlines()[4:28])
    for name in (
        "PHASE_TIMEOUT_KILL_GRACE_SECONDS",
        "PHASE_TIMEOUT_TEARDOWN_SECONDS",
        "APT_RETRY_BACKOFF_SECONDS",
        "RETRY_BACKOFF_SECONDS",
    ):
        assert name in header


def test_scanner_bootstrap_rejects_wrong_semgrep_version_and_missing_database(tmp_path):
    wrong_version = _run_bootstrap(tmp_path, FAKE_SEMGREP_VERSION="1.131.0")
    missing_database = _run_bootstrap(tmp_path, FAKE_CLAMAV_DB_MISSING="1")

    assert wrong_version.returncode != 0
    assert "expected Semgrep 1.132.0" in wrong_version.stderr
    assert missing_database.returncode != 0
    assert "verify ClamAV database" in missing_database.stderr
