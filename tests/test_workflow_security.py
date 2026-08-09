import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"^[^\s]+@[0-9a-f]{40}$")


class WorkflowSecurityTests(unittest.TestCase):
    def test_all_actions_are_pinned_to_full_commit_shas(self):
        unpinned = []

        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            for line_number, line in enumerate(
                workflow.read_text().splitlines(), start=1
            ):
                stripped = line.strip()
                if not stripped.startswith("uses: "):
                    continue

                action = stripped.removeprefix("uses: ")
                if not SHA_PIN.fullmatch(action):
                    unpinned.append(f"{workflow.name}:{line_number}: {action}")

        self.assertEqual([], unpinned)

    def test_no_secret_is_interpolated_directly_into_a_run_command(self):
        unsafe = []

        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            lines = workflow.read_text().splitlines()
            for index, line in enumerate(lines):
                stripped = line.lstrip()
                if not stripped.startswith("run:"):
                    continue

                run_indent = len(line) - len(stripped)
                command_lines = [line]
                for continuation in lines[index + 1 :]:
                    if not continuation.strip():
                        command_lines.append(continuation)
                        continue
                    continuation_indent = len(continuation) - len(continuation.lstrip())
                    if continuation_indent <= run_indent:
                        break
                    command_lines.append(continuation)

                if "${{ secrets." in "\n".join(command_lines):
                    unsafe.append(f"{workflow.name}:{index + 1}")

        self.assertEqual([], unsafe)

    def test_scheduled_audit_cache_key_covers_scanner_inputs_not_verdict_output(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        cache_key_command = next(
            line for line in workflow.splitlines() if "POLICY_HASH=$(sha256sum" in line
        )

        for scanner_input in (
            "security-policy.yml",
            "security-allowlist.yml",
            "semgrep-rules.yml",
            "audit_plugins.py",
            "plugin_release_utils.py",
            "pyproject.toml",
            "uv.lock",
        ):
            self.assertIn(scanner_input, cache_key_command)
        self.assertNotIn("security-verdicts.json", cache_key_command)

    def test_scheduled_audit_uses_central_verdict_delta_merge_cli(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        self.assertIn(
            "uv run python audit_plugins.py \\\n"
            "            --merge-verdict-delta security-reports/security-verdict-delta.json \\\n"
            "            --verdict-store security-verdicts.json",
            workflow,
        )
        self.assertNotIn(
            "verdicts.setdefault(repository, {}).update(releases)", workflow
        )

    def test_scheduled_audit_installs_and_verifies_semgrep(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        self.assertIn(
            "uv tool install --python 3.12 --with setuptools==70.3.0 semgrep==1.132.0",
            workflow,
        )
        self.assertIn('echo "$SEMGREP_BIN_DIR" >> "$GITHUB_PATH"', workflow)
        self.assertIn("semgrep --version --disable-version-check", workflow)

    def test_scheduled_audit_publishes_only_changed_verdict_store(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()
        scheduled_job = workflow.split("  scheduled-audit:\n", maxsplit=1)[1]

        self.assertIn("    permissions:\n      contents: write", scheduled_job)
        self.assertIn(
            "git diff --quiet -- security-verdicts.json",
            scheduled_job,
        )
        self.assertIn("git add -- security-verdicts.json", scheduled_job)
        self.assertNotIn("git add -A", scheduled_job)
        self.assertIn("${changed_count} changed verdicts", scheduled_job)
        self.assertIn("git status --porcelain", scheduled_job)
        self.assertEqual(1, scheduled_job.count("git reset --hard HEAD"))
        self.assertLess(
            scheduled_job.index('git commit -m "chore(security): publish'),
            scheduled_job.index("git status --porcelain"),
        )
        self.assertLess(
            scheduled_job.index("git status --porcelain"),
            scheduled_job.index("git reset --hard HEAD"),
        )
        self.assertLess(
            scheduled_job.index("git reset --hard HEAD"),
            scheduled_job.index('git pull --rebase origin "$GITHUB_REF_NAME"'),
        )
        self.assertEqual(
            2,
            scheduled_job.count('git pull --rebase origin "$GITHUB_REF_NAME"'),
        )
        self.assertEqual(
            2,
            scheduled_job.count('git push origin "HEAD:${GITHUB_REF_NAME}"'),
        )


if __name__ == "__main__":
    unittest.main()
