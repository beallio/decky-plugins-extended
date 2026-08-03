import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import audit_plugins as ap


def _make_zip(members: list[tuple[str, bytes | str, int]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, ext_attr in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = ext_attr
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(info, content)
    return buf.getvalue()


def _regular(name: str, content: str | bytes = "") -> tuple[str, bytes | str, int]:
    return (name, content, 0)


class TestAuditCacheInvalidation(unittest.TestCase):
    def test_cache_prevents_download_on_second_run(self):
        """Verification 2: Pre-download cache check prevents ZIP download on 2nd run."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()

            download_count = 0

            def mock_download(url, dest_path):
                nonlocal download_count
                download_count += 1
                with open(dest_path, "wb") as f:
                    f.write(zip_bytes)
                return zip_sha

            release_data = {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 123,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/p.zip",
                    }
                ],
            }

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("commit123", "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=mock_download),
                patch(
                    "audit_plugins.compare_source_and_artifact",
                    return_value=(
                        {},
                        [],
                        ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                    ),
                ),
            ):
                # 1st run: cache miss, downloads ZIP
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                self.assertEqual(download_count, 1)

                # 2nd run: cache hit, zero downloads
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                self.assertEqual(download_count, 1)

                # Delete cache and 3rd run: downloads again (download_count -> 2)
                shutil.rmtree(cache_dir)
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                self.assertEqual(download_count, 2)

    def test_allowlist_edits_bust_local_cache(self):
        """Verification 4: Editing allowlist invalidates local cache."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions1 = [
                {"repository": "owner/repo", "rule_id": "TEST1", "reason": "test"}
            ]
            exceptions2 = [
                {"repository": "owner/repo", "rule_id": "TEST2", "reason": "test"}
            ]

            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()
            download_count = 0

            def mock_download(url, dest_path):
                nonlocal download_count
                download_count += 1
                with open(dest_path, "wb") as f:
                    f.write(zip_bytes)
                return zip_sha

            release_data = {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 123,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/p.zip",
                    }
                ],
            }

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("commit123", "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=mock_download),
                patch(
                    "audit_plugins.compare_source_and_artifact",
                    return_value=(
                        {},
                        [],
                        ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                    ),
                ),
            ):
                # Run 1: initial audit
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions1,
                    cache_dir=cache_dir,
                )
                self.assertEqual(download_count, 1)

                # Run 2: same exceptions -> cache hit
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions1,
                    cache_dir=cache_dir,
                )
                self.assertEqual(download_count, 1)

                # Run 3: modified exceptions -> cache miss!
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions2,
                    cache_dir=cache_dir,
                )
                self.assertEqual(download_count, 2)

    def test_moved_tag_busts_cache(self):
        """Verification 5: Moving tag to a new commit SHA invalidates local cache."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()
            download_count = 0
            current_commit = "commit_v1"

            def mock_download(url, dest_path):
                nonlocal download_count
                download_count += 1
                with open(dest_path, "wb") as f:
                    f.write(zip_bytes)
                return zip_sha

            def mock_resolve(owner, repo, ref):
                nonlocal current_commit
                return (current_commit, f"tree_{current_commit}", None)

            release_data = {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 123,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/p.zip",
                    }
                ],
            }

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    side_effect=mock_resolve,
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=mock_download),
                patch(
                    "audit_plugins.compare_source_and_artifact",
                    return_value=(
                        {},
                        [],
                        ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                    ),
                ),
            ):
                # Run 1: initial audit at commit_v1
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )
                self.assertEqual(download_count, 1)

                # Run 2: tag moves to commit_v2 -> cache miss!
                current_commit = "commit_v2"
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )
                self.assertEqual(download_count, 2)

    def test_auditor_executes_nothing(self):
        """Verification 6: Auditor static inspection never executes plugin scripts/setup.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            sentinel = os.path.join(tmp_dir, "sentinel.txt")
            malicious_setup = f"import os; os.system('touch {sentinel}')\n"
            malicious_pkg = json.dumps(
                {"name": "malicious", "scripts": {"postinstall": f"touch {sentinel}"}}
            )
            zip_bytes = _make_zip(
                [
                    _regular("setup.py", malicious_setup),
                    _regular("package.json", malicious_pkg),
                    _regular("plugin.json", '{"name":"malicious"}'),
                ]
            )
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()

            release_data = {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 123,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/p.zip",
                    }
                ],
            }

            def mock_download(url, dest_path):
                with open(dest_path, "wb") as f:
                    f.write(zip_bytes)
                return zip_sha

            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("commit123", "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=mock_download),
                patch(
                    "audit_plugins.compare_source_and_artifact",
                    return_value=(
                        {},
                        [],
                        ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                    ),
                ),
            ):
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=os.path.join(tmp_dir, "cache"),
                )

            self.assertFalse(
                os.path.exists(sentinel),
                "Sentinel file was created! Code execution occurred!",
            )

    def test_failed_tag_resolution_returns_error_and_does_not_cache(self):
        """Failed tag resolution returns AUDIT_ERROR and does not cache entries across tags."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            release_v1 = {
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 123,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/v1.zip",
                    }
                ],
            }
            release_v2 = {
                "tag_name": "v2.0.0",
                "assets": [
                    {
                        "id": 456,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/v2.zip",
                    }
                ],
            }

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch(
                    "audit_plugins.get_releases",
                    side_effect=[[release_v1], [release_v2]],
                ),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=(None, None, "boom"),
                ),
            ):
                report1 = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )
                self.assertEqual(report1.final_classification, "AUDIT_ERROR")
                self.assertIn(
                    "Failed to resolve ref v1.0.0 to commit SHA: boom",
                    report1.errors[0],
                )

                report2 = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )
                self.assertEqual(report2.final_classification, "AUDIT_ERROR")
                self.assertIn(
                    "Failed to resolve ref v2.0.0 to commit SHA: boom",
                    report2.errors[0],
                )
                if os.path.exists(cache_dir):
                    self.assertEqual(len(os.listdir(cache_dir)), 0)
