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

    def test_scheduled_audit_cache_key_covers_the_allowlist(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        cache_key_command = next(
            line for line in workflow.splitlines() if "POLICY_HASH=$(sha256sum" in line
        )

        self.assertIn("security-allowlist.yml", cache_key_command)


if __name__ == "__main__":
    unittest.main()
