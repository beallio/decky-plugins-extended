import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_PIN = re.compile(r"^[^\s]+@[0-9a-f]{40}$")


class WorkflowSecurityTests(unittest.TestCase):
    @staticmethod
    def _job_body(workflow: str, job_name: str) -> str:
        match = re.search(
            rf"^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
            workflow,
            flags=re.MULTILINE | re.DOTALL,
        )
        if match is None:
            raise AssertionError(f"Workflow job is missing: {job_name}")
        return match.group("body")

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
            "audit_worklist.py",
            "scripts/install-security-scanners",
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

    def test_workflows_use_one_checked_in_scanner_bootstrap(self):
        plugin_workflow = (WORKFLOWS / "plugin-security-audit.yml").read_text()
        scheduled_workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        for workflow in (plugin_workflow, scheduled_workflow):
            self.assertNotIn("sudo apt-get", workflow)
            self.assertNotIn("semgrep --version --disable-version-check", workflow)
        self.assertEqual(
            3,
            (plugin_workflow + scheduled_workflow).count(
                "run: scripts/install-security-scanners"
            ),
        )
        self.assertEqual(
            3,
            (plugin_workflow + scheduled_workflow).count("timeout-minutes: 12"),
        )

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

    def test_worklists_are_prepared_once_and_workers_are_api_free(self):
        workflows = (
            (
                "plugin-security-audit.yml",
                "audit-shards",
                "aggregate-audit",
            ),
            (
                "scheduled-security-audit.yml",
                "scheduled-audit",
                "aggregate-and-publish",
            ),
        )
        for workflow_name, worker_name, aggregate_name in workflows:
            workflow = (WORKFLOWS / workflow_name).read_text()
            producer = self._job_body(workflow, "prepare-audit-worklist")
            worker = self._job_body(workflow, worker_name)
            aggregate = self._job_body(workflow, aggregate_name)

            self.assertIn("timeout-minutes: 10", producer)
            self.assertIn("--prepare-worklist audit-worklist/worklist.json", producer)
            self.assertIn("--api-deadline-seconds 480", producer)
            self.assertIn("worklist_fingerprint=", producer)
            self.assertIn("name: prepared-audit-worklist", producer)
            self.assertIn("GITHUB_TOKEN:", producer)

            self.assertIn("needs: prepare-audit-worklist", worker)
            self.assertIn("persist-credentials: false", worker)
            self.assertIn("name: prepared-audit-worklist", worker)
            self.assertIn("--worklist audit-worklist/worklist.json", worker)
            self.assertIn("--expected-worklist-fingerprint", worker)
            self.assertNotIn("GITHUB_TOKEN:", worker)
            self.assertNotIn("GH_TOKEN:", worker)
            self.assertNotIn("--all", worker)
            self.assertNotIn("--changed", worker)

            self.assertIn("needs: [prepare-audit-worklist", aggregate)
            self.assertIn("needs.prepare-audit-worklist.result", aggregate)
            self.assertIn("name: prepared-audit-worklist", aggregate)
            self.assertIn("--expected-worklist audit-worklist/worklist.json", aggregate)
            self.assertIn("--aggregate-shard-manifests", aggregate)

    def test_workflow_workers_and_aggregate_cannot_bypass_a_failed_producer(self):
        for workflow_name, worker_name, aggregate_name in (
            ("plugin-security-audit.yml", "audit-shards", "aggregate-audit"),
            (
                "scheduled-security-audit.yml",
                "scheduled-audit",
                "aggregate-and-publish",
            ),
        ):
            workflow = (WORKFLOWS / workflow_name).read_text()
            worker = self._job_body(workflow, worker_name)
            aggregate = self._job_body(workflow, aggregate_name)

            self.assertNotIn("\n    if: always()", worker)
            self.assertIn("if: always()", aggregate)
            self.assertIn("Require prepared worklist success", aggregate)
            self.assertIn("not successful; refusing aggregation", aggregate)


if __name__ == "__main__":
    unittest.main()
