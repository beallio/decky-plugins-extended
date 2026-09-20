import os
import re
import subprocess
import tempfile
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

    @staticmethod
    def _scanner_package_cache_key_outputs(
        job: str, *, image_os: str, image_version: str
    ) -> dict[str, str]:
        step_match = re.search(
            r"^      - name: Compute scanner package cache key\n"
            r"(?P<body>.*?)(?=^      - name:|\Z)",
            job,
            flags=re.MULTILINE | re.DOTALL,
        )
        if step_match is None:
            raise AssertionError("scanner package cache key step is missing")
        step_lines = step_match.group(0).splitlines()
        script = "\n".join(line.removeprefix("          ") for line in step_lines[3:])

        with tempfile.TemporaryDirectory() as temporary_directory:
            github_output = Path(temporary_directory) / "github-output"
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                cwd=ROOT,
                env=os.environ
                | {
                    "GITHUB_OUTPUT": str(github_output),
                    "ImageOS": image_os,
                    "ImageVersion": image_version,
                },
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise AssertionError(result.stderr)
            return dict(
                line.split("=", maxsplit=1)
                for line in github_output.read_text().splitlines()
            )

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

    def test_scheduled_worker_prefetches_and_preserves_resumable_checkpoint(self):
        scheduled_workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()
        pull_request_workflow = (WORKFLOWS / "plugin-security-audit.yml").read_text()
        scheduled_job = self._job_body(scheduled_workflow, "scheduled-audit")
        prefetch = scheduled_job.split(
            "      - name: Prefetch Trivy vulnerability database\n", maxsplit=1
        )[1].split("\n      - name:", maxsplit=1)[0]
        audit = scheduled_job.split(
            "      - name: Run audit on all configured repositories\n", maxsplit=1
        )[1].split("\n      - name:", maxsplit=1)[0]
        restore = scheduled_job.split(
            "      - name: Restore audit cache\n", maxsplit=1
        )[1].split("\n      - name:", maxsplit=1)[0]
        checkpoint_save = scheduled_job.split(
            "      - name: Save audit cache\n", maxsplit=1
        )[1].split("\n      - name:", maxsplit=1)[0]

        self.assertIn("\n    timeout-minutes: 90\n", scheduled_job)
        self.assertIn("trivy image --download-db-only", prefetch)
        self.assertIn("timeout-minutes: 5", prefetch)
        self.assertNotIn("continue-on-error", prefetch)
        self.assertIn("::error::Trivy vulnerability database prefetch failed", prefetch)
        self.assertIn("timeout-minutes: 60", audit)
        self.assertLess(
            scheduled_job.index("name: Install required security scanners"),
            scheduled_job.index("name: Prefetch Trivy vulnerability database"),
        )
        self.assertLess(
            scheduled_job.index("name: Prefetch Trivy vulnerability database"),
            scheduled_job.index("name: Run audit on all configured repositories"),
        )
        for cache_step in (restore, checkpoint_save):
            self.assertIn(
                "path: |\n            .audit-cache\n            security-reports",
                cache_step,
            )
        self.assertIn("if: always() && !cancelled()", checkpoint_save)
        self.assertIn("${{ github.run_attempt }}", scheduled_job)
        self.assertNotIn("download-db-only", pull_request_workflow)
        self.assertNotIn("timeout-minutes: 90", pull_request_workflow)

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

    def test_scanner_package_cache_is_restored_before_each_bootstrap(self):
        expected_jobs = (
            ("plugin-security-audit.yml", "audit-shards"),
            ("plugin-security-audit.yml", "smoke-audit"),
            ("scheduled-security-audit.yml", "scheduled-audit"),
        )
        for workflow_name, job_name in expected_jobs:
            workflow = (WORKFLOWS / workflow_name).read_text()
            job = self._job_body(workflow, job_name)

            self.assertIn("name: Compute scanner package cache key", job)
            self.assertIn("name: Restore scanner package cache", job)
            self.assertIn("path: .scanner-package-cache/apt-archives", job)
            self.assertIn(
                "key: ${{ steps.scanner-package-cache-key.outputs.key }}", job
            )
            self.assertIn(
                "${{ steps.scanner-package-cache-key.outputs.restore_key }}", job
            )
            self.assertIn("continue-on-error: true", job)
            self.assertLess(
                job.index("name: Restore scanner package cache"),
                job.index("name: Install required security scanners"),
            )

    def test_scanner_package_cache_key_covers_runner_os_packages_and_bootstrap(self):
        expected_jobs = (
            ("plugin-security-audit.yml", "audit-shards"),
            ("plugin-security-audit.yml", "smoke-audit"),
            ("scheduled-security-audit.yml", "scheduled-audit"),
        )
        base_packages = "wget apt-transport-https gnupg lsb-release clamav"
        for workflow_name, job_name in expected_jobs:
            workflow = (WORKFLOWS / workflow_name).read_text()
            job = self._job_body(workflow, job_name)

            self.assertIn('runner_os="${ImageOS:?}"', job)
            self.assertNotIn("ImageVersion", job)
            self.assertNotIn("runner_image=", job)
            self.assertIn(f'base_packages="{base_packages}"', job)
            self.assertIn("sha256sum scripts/install-security-scanners", job)
            self.assertIn("printf '%s' \"$base_packages\" | sha256sum", job)
            self.assertIn(
                "key=scanner-package-cache-v1-${runner_os}-${package_set_hash}-${bootstrap_hash}",
                job,
            )
            self.assertIn("restore_key=scanner-package-cache-v1-${runner_os}-", job)
            first_shard_outputs = self._scanner_package_cache_key_outputs(
                job,
                image_os="ubuntu24",
                image_version="ubuntu24-20260810.271.1",
            )
            second_shard_outputs = self._scanner_package_cache_key_outputs(
                job,
                image_os="ubuntu24",
                image_version="ubuntu24-20260816.277.1",
            )
            self.assertEqual(first_shard_outputs["key"], second_shard_outputs["key"])
            self.assertEqual(
                first_shard_outputs["restore_key"], second_shard_outputs["restore_key"]
            )

    def test_scanner_package_cache_save_is_best_effort_and_allows_any_shard(self):
        plugin_workflow = (WORKFLOWS / "plugin-security-audit.yml").read_text()
        scheduled_workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()

        for workflow, job_name in (
            (plugin_workflow, "audit-shards"),
            (plugin_workflow, "smoke-audit"),
            (scheduled_workflow, "scheduled-audit"),
        ):
            job = self._job_body(workflow, job_name)
            self.assertIn("name: Save scanner package cache", job)
            self.assertIn(
                "actions/cache/save@5a3ec84eff668545956fd18022155c47e93e2684", job
            )
            self.assertIn("continue-on-error: true", job)
            self.assertLess(
                job.index("name: Install required security scanners"),
                job.index("name: Save scanner package cache"),
            )

        for workflow, job_name in (
            (plugin_workflow, "audit-shards"),
            (scheduled_workflow, "scheduled-audit"),
        ):
            job = self._job_body(workflow, job_name)
            self.assertIn("if: success()", job)
            self.assertNotIn("matrix.shard_index == 0", job)

    def test_scheduled_audit_publishes_only_changed_verdict_store(self):
        workflow = (WORKFLOWS / "scheduled-security-audit.yml").read_text()
        scheduled_job = workflow.split("  scheduled-audit:\n", maxsplit=1)[1]
        publish_step = workflow.split(
            "      - name: Publish updated verdicts\n", maxsplit=1
        )[1].split("\n      - name:", maxsplit=1)[0]

        self.assertIn("    permissions:\n      contents: write", scheduled_job)
        self.assertIn("for attempt in 1 2; do", publish_step)
        self.assertIn('git fetch origin "$GITHUB_REF_NAME"', publish_step)
        self.assertIn(
            'git reset --hard "origin/${GITHUB_REF_NAME}"',
            publish_step,
        )
        self.assertIn(
            "--merge-verdict-delta security-reports/security-verdict-delta.json",
            publish_step,
        )
        self.assertIn("git diff --quiet -- security-verdicts.json", publish_step)
        self.assertIn("git add -- security-verdicts.json", publish_step)
        self.assertNotIn("git add -A", publish_step)
        self.assertIn("${changed_count} changed verdicts", publish_step)
        self.assertIn("git status --porcelain", publish_step)
        self.assertIn('git push origin "HEAD:${GITHUB_REF_NAME}"', publish_step)
        self.assertNotIn("git pull --rebase", publish_step)
        self.assertLess(
            publish_step.index('git reset --hard "origin/${GITHUB_REF_NAME}"'),
            publish_step.index("--merge-verdict-delta"),
        )
        self.assertLess(
            publish_step.index("--merge-verdict-delta"),
            publish_step.index("git diff --quiet -- security-verdicts.json"),
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

    def test_generate_workflow_can_force_a_manual_cloudflare_deploy(self):
        workflow = (WORKFLOWS / "generate.yml").read_text()
        refresh = self._job_body(workflow, "refresh")

        self.assertIn("force_deploy:", workflow)
        self.assertIn("type: boolean", workflow)
        # A run that pushed refreshed catalog data has already triggered
        # Cloudflare through the push itself, so the hook is skipped there.
        self.assertIn(
            "if: steps.publish.outputs.pushed != 'true'"
            " && (inputs.force_deploy == true || steps.check.outputs.changed == 'true')",
            refresh,
        )
        self.assertIn("HOOK: ${{ secrets.CLOUDFLARE_DEPLOY_HOOK }}", refresh)


if __name__ == "__main__":
    unittest.main()
