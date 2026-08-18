import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
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


def _scanner_identities(*, clamav_database: object) -> dict:
    return {
        "clamav": {
            "enabled": True,
            "executable": "/usr/bin/clamscan",
            "version": "ClamAV 1.4.3",
            "database": clamav_database,
        },
        "trivy": {"enabled": False},
        "semgrep": {"enabled": False},
    }


class TestAuditCacheInvalidation(unittest.TestCase):
    def test_runtime_identities_capture_real_database_freshness(self):
        policy = {
            "scanners": {
                "clamav": {"enabled": True},
                "trivy": {"enabled": True},
                "semgrep": {"enabled": True},
            }
        }

        def run(command, **_kwargs):
            if command[0].endswith("clamscan"):
                output = "ClamAV 1.4.3/27848/Fri Aug 8 12:00:00 2026"
            elif command[1:] == ["--version"]:
                output = "Version: 0.66.0"
            elif command[0].endswith("trivy"):
                output = json.dumps(
                    {
                        "Version": "0.66.0",
                        "VulnerabilityDB": {
                            "Version": 2,
                            "UpdatedAt": "2026-08-08T12:00:00Z",
                        },
                    }
                )
            else:
                output = "1.132.0"
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        with (
            patch(
                "audit_plugins.shutil.which", side_effect=lambda name: f"/tools/{name}"
            ),
            patch("audit_plugins.subprocess.run", side_effect=run),
        ):
            identities = ap._scanner_runtime_identities(policy)

        self.assertIn("27848", identities["clamav"]["database"])
        self.assertEqual(identities["trivy"]["database"]["Version"], 2)
        self.assertTrue(ap._scanner_database_freshness_available(policy, identities))

    def test_bare_executable_versions_do_not_claim_database_freshness(self):
        policy = {
            "scanners": {
                "clamav": {"enabled": True},
                "trivy": {"enabled": True},
                "semgrep": {"enabled": False},
            }
        }

        with (
            patch(
                "audit_plugins.shutil.which", side_effect=lambda name: f"/tools/{name}"
            ),
            patch(
                "audit_plugins.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0, stdout="Version: 1.0.0", stderr=""
                ),
            ),
        ):
            identities = ap._scanner_runtime_identities(policy)

        self.assertIsNone(identities["clamav"]["database"])
        self.assertIsNone(identities["trivy"]["database"])
        self.assertFalse(ap._scanner_database_freshness_available(policy, identities))

    def test_invalid_trivy_identity_payloads_cannot_authorize_scheduled_cache(self):
        policy = {
            "scanners": {
                "clamav": {"enabled": False},
                "trivy": {"enabled": True},
                "semgrep": {"enabled": False},
            }
        }
        invalid_payloads = {
            "array": "[]",
            "scalar": json.dumps("not-an-object"),
            "missing-database": json.dumps({"Version": "0.66.0"}),
            "missing-freshness-fields": json.dumps({"VulnerabilityDB": {"Version": 2}}),
            "wrong-version-type": json.dumps(
                {
                    "VulnerabilityDB": {
                        "Version": [],
                        "UpdatedAt": "2026-08-08T12:00:00Z",
                    }
                }
            ),
            "wrong-timestamp-type": json.dumps(
                {
                    "VulnerabilityDB": {
                        "Version": 2,
                        "UpdatedAt": 123,
                    }
                }
            ),
            "malformed-json": "{not-json",
        }

        for label, payload in invalid_payloads.items():
            with self.subTest(label=label):

                def run(command, **_kwargs):
                    output = (
                        "Version: 0.66.0" if command[1:] == ["--version"] else payload
                    )
                    return SimpleNamespace(returncode=0, stdout=output, stderr="")

                with (
                    patch("audit_plugins.shutil.which", return_value="/tools/trivy"),
                    patch("audit_plugins.subprocess.run", side_effect=run),
                ):
                    identities = ap._scanner_runtime_identities(policy)

                self.assertEqual(identities["trivy"]["version"], "Version: 0.66.0")
                self.assertIsNone(identities["trivy"]["database"])
                self.assertFalse(
                    ap._scanner_database_freshness_available(policy, identities)
                )

    def test_valid_trivy_identity_authorizes_scheduled_cache_hit(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = ap._default_policy()
            for scanner in policy["scanners"].values():
                scanner["enabled"] = False
                scanner["required"] = False
            policy["scanners"]["trivy"]["enabled"] = True
            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()
            release_data = {
                "id": 123,
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 456,
                        "name": "plugin.zip",
                        "browser_download_url": "https://example.com/plugin.zip",
                        "digest": f"sha256:{zip_sha}",
                    }
                ],
            }
            scanner_identities = {
                "clamav": {"enabled": False},
                "trivy": {
                    "enabled": True,
                    "executable": "/tools/trivy",
                    "version": "Version: 0.66.0",
                    "database": {
                        "Version": 2,
                        "UpdatedAt": "2026-08-08T12:00:00Z",
                    },
                },
                "semgrep": {"enabled": False},
            }
            download_count = 0
            trivy_count = 0

            def download(_url, destination, policy=None):
                self.assertIs(policy, audit_policy)
                nonlocal download_count
                download_count += 1
                Path(destination).write_bytes(zip_bytes)
                return zip_sha

            def trivy(*_args, **_kwargs):
                nonlocal trivy_count
                trivy_count += 1
                return ap.ScannerStatus(name="trivy", status="passed"), []

            audit_policy = policy
            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch.object(
                    ap.audit_source_snapshot,
                    "materialize_source_snapshot",
                    return_value=SimpleNamespace(
                        source_root="/",
                        plugin_json=None,
                        package_json=None,
                    ),
                ),
                patch("audit_plugins.run_trivy", side_effect=trivy),
                patch(
                    "audit_plugins._scanner_runtime_identities",
                    return_value=scanner_identities,
                ),
                patch.dict(os.environ, {"AUDIT_SCHEDULED": "1"}),
            ):
                first = ap.audit_repository(
                    "https://github.com/owner/repo", policy, [], cache_dir=cache_dir
                )
                second = ap.audit_repository(
                    "https://github.com/owner/repo", policy, [], cache_dir=cache_dir
                )

        self.assertEqual(first.final_classification, "PASS")
        self.assertEqual(second.final_classification, "PASS")
        self.assertEqual((download_count, trivy_count), (1, 1))

    def test_context_hash_covers_semgrep_rules_and_scanner_freshness(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            rules = os.path.join(tmp_dir, "semgrep-rules.yml")
            Path(rules).write_text("rules: []\n", encoding="utf-8")
            identities = {
                "semgrep": {"executable": "/bin/semgrep", "version": "1.132.0"},
                "trivy": {
                    "executable": "/bin/trivy",
                    "version": "0.66.0",
                    "database": "2026-08-08T12:00:00Z",
                },
                "clamav": {
                    "executable": "/bin/clamscan",
                    "version": "1.4.3",
                    "database": "27800",
                },
            }
            with patch.object(ap, "SEMGREP_RULES_FILE", rules):
                original = ap.compute_audit_context_hash(
                    {}, [], scanner_identities=identities
                )
                identical = ap.compute_audit_context_hash(
                    {}, [], scanner_identities=identities
                )
                Path(rules).write_text("rules:\n  - id: changed\n", encoding="utf-8")
                rules_changed = ap.compute_audit_context_hash(
                    {}, [], scanner_identities=identities
                )
                scanner_changed = ap.compute_audit_context_hash(
                    {},
                    [],
                    scanner_identities={
                        **identities,
                        "semgrep": {
                            "executable": "/bin/semgrep",
                            "version": "1.133.0",
                        },
                    },
                )
                database_changed = ap.compute_audit_context_hash(
                    {},
                    [],
                    scanner_identities={
                        **identities,
                        "trivy": {
                            **identities["trivy"],
                            "database": "2026-08-08T18:00:00Z",
                        },
                    },
                )

        self.assertEqual(original, identical)
        self.assertNotEqual(original, rules_changed)
        self.assertNotEqual(original, scanner_changed)
        self.assertNotEqual(original, database_changed)

    def test_clamav_database_identity_change_causes_cache_miss(self):
        policy = ap._default_policy()
        context_a = ap.compute_audit_context_hash(
            policy,
            [],
            scanner_identities=_scanner_identities(clamav_database="27848"),
        )
        context_b = ap.compute_audit_context_hash(
            policy,
            [],
            scanner_identities=_scanner_identities(clamav_database="27849"),
        )
        report = ap.AuditReport(
            repository="https://github.com/owner/repo",
            release="v1.0.0",
            release_id="v1.0.0@123",
            artifact_sha256="a" * 64,
            audit_context_hash=context_a,
            resolved_tag_commit_sha="a" * 40,
            final_classification="PASS",
            completion_status="completed",
        )

        with tempfile.TemporaryDirectory() as cache_dir:
            ap.save_cached_report(
                cache_dir, report, report.release_id, context_a, "a" * 40
            )
            matching = ap.load_cached_report(
                cache_dir,
                report.repository,
                report.release_id,
                report.artifact_sha256,
                context_a,
                "a" * 40,
            )
            changed = ap.load_cached_report(
                cache_dir,
                report.repository,
                report.release_id,
                report.artifact_sha256,
                context_b,
                "a" * 40,
            )

        self.assertNotEqual(context_a, context_b)
        self.assertIsNotNone(matching)
        self.assertIsNone(changed)

    def test_scheduled_freshness_bypasses_otherwise_valid_cache(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = ap._default_policy()
            for scanner in policy["scanners"].values():
                scanner["enabled"] = False
                scanner["required"] = False
            policy["scanners"]["clamav"]["enabled"] = True
            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()
            release_data = {
                "id": 123,
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 456,
                        "name": "plugin.zip",
                        "browser_download_url": "https://example.com/plugin.zip",
                        "digest": f"sha256:{zip_sha}",
                    }
                ],
            }
            download_count = 0
            clamav_count = 0

            def download(_url, destination, policy=None):
                self.assertIs(policy, audit_policy)
                nonlocal download_count
                download_count += 1
                Path(destination).write_bytes(zip_bytes)
                return zip_sha

            def clamav(*_args):
                nonlocal clamav_count
                clamav_count += 1
                return ap.ScannerStatus(name="clamav", status="passed"), []

            audit_policy = policy
            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch("audit_plugins.run_clamav", side_effect=clamav),
                patch(
                    "audit_plugins._scanner_runtime_identities",
                    return_value=_scanner_identities(clamav_database=None),
                ),
                patch.dict(os.environ, {"AUDIT_SCHEDULED": "0"}),
            ):
                ap.audit_repository(
                    "https://github.com/owner/repo", policy, [], cache_dir=cache_dir
                )
                ap.audit_repository(
                    "https://github.com/owner/repo", policy, [], cache_dir=cache_dir
                )
                self.assertEqual((download_count, clamav_count), (1, 1))

                with (
                    patch.dict(os.environ, {"AUDIT_SCHEDULED": "1"}),
                    self.assertLogs("audit_plugins", level="WARNING") as logs,
                ):
                    ap.audit_repository(
                        "https://github.com/owner/repo",
                        policy,
                        [],
                        cache_dir=cache_dir,
                    )

            self.assertEqual((download_count, clamav_count), (2, 2))
            self.assertTrue(
                any("cache bypassed" in message for message in logs.output), logs.output
            )

    def test_predownload_index_cannot_redirect_to_another_release(self):
        report = ap.AuditReport(
            repository="https://github.com/owner/repo",
            release="v2.0.0",
            release_id="v2.0.0@2",
            artifact_sha256="a" * 64,
            audit_context_hash="context",
            resolved_tag_commit_sha="commit",
            final_classification="PASS",
        )
        with tempfile.TemporaryDirectory() as cache_dir:
            ap.save_cached_report(cache_dir, report, "v2.0.0@2", "context", "commit")
            index_path = os.path.join(cache_dir, "index.json")
            index = json.loads(Path(index_path).read_text(encoding="utf-8"))
            wrong_key = next(iter(index.values()))["cache_key"]
            requested_index_key = ap._pre_download_index_key(
                report.repository, "v1.0.0@1", "context", "commit"
            )
            index[requested_index_key] = {
                "cache_key": wrong_key,
                "release_id": "v2.0.0@2",
            }
            Path(index_path).write_text(json.dumps(index), encoding="utf-8")

            loaded = ap.load_cached_report_predownload(
                cache_dir,
                report.repository,
                "v1.0.0@1",
                "context",
                "commit",
            )

        self.assertIsNone(loaded)

    def test_digestless_cache_revalidates_bytes_on_second_run(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            zip_bytes = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_bytes).hexdigest()

            download_count = 0

            def mock_download(url, dest_path, policy=None):
                del url, policy
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
                    return_value=("a" * 40, "tree123", None),
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

                # Digestless bytes must be streamed again before the cache is trusted.
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                self.assertEqual(download_count, 2)

                # Delete cache and 3rd run: downloads again.
                shutil.rmtree(cache_dir)
                ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                self.assertEqual(download_count, 3)

    def test_digest_backed_predownload_hit_skips_artifact_and_source_consumers(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = ap._default_policy()
            zip_data = _make_zip(
                [
                    _regular("plugin.json", '{"name":"cache-test"}'),
                    _regular("plugin/main.py", "# hello\n"),
                ]
            )
            zip_sha = hashlib.sha256(zip_data).hexdigest()
            release_data = {
                "id": 123,
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 456,
                        "name": "plugin.zip",
                        "browser_download_url": "http://ex.com/p.zip",
                        "digest": f"sha256:{zip_sha}",
                    }
                ],
            }

            download_count = 0
            materialize_count = 0
            trivy_count = 0
            compare_count = 0

            def download(_url, destination, policy=None):
                del _url, policy
                nonlocal download_count
                download_count += 1
                with open(destination, "wb") as f:
                    f.write(zip_data)
                return zip_sha

            def fake_materialize(_repository, _commit, destination, **_kwargs):
                nonlocal materialize_count
                materialize_count += 1
                return SimpleNamespace(
                    source_root=destination,
                    plugin_json=None,
                    package_json=None,
                )

            def fake_trivy(*_args, source_root=None, **_kwargs):
                del source_root
                nonlocal trivy_count
                trivy_count += 1
                return ap.ScannerStatus(name="trivy", status="passed"), []

            def fake_compare(_extract_dir, _snapshot, ref):
                nonlocal compare_count
                del ref
                compare_count += 1
                return (
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                )

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch(
                    "audit_plugins.get_releases",
                    return_value=[release_data],
                ),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch.object(
                    ap.audit_source_snapshot,
                    "materialize_source_snapshot",
                    side_effect=fake_materialize,
                ),
                patch(
                    "audit_plugins.run_clamav",
                    return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
                ),
                patch("audit_plugins.run_trivy", side_effect=fake_trivy),
                patch(
                    "audit_plugins.run_semgrep",
                    return_value=(
                        ap.ScannerStatus(name="semgrep", status="skipped"),
                        [],
                    ),
                ),
                patch(
                    "audit_plugins.compare_source_and_artifact_from_snapshot",
                    side_effect=fake_compare,
                ),
            ):
                first = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    [],
                    cache_dir=cache_dir,
                )
                second = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    [],
                    cache_dir=cache_dir,
                )

        self.assertEqual(first.final_classification, "PASS")
        self.assertEqual(second.final_classification, "PASS")
        self.assertEqual(download_count, 1)
        self.assertEqual(materialize_count, 1)
        self.assertEqual(trivy_count, 1)
        self.assertEqual(compare_count, 1)

    def test_digestless_cache_hit_streams_once_and_skips_source_consumers(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []

            zip_data = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_data).hexdigest()
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

            download_count = 0
            materialize_count = 0
            trivy_count = 0
            compare_count = 0

            def download(_url, dest, policy=None):
                del _url, policy
                nonlocal download_count
                download_count += 1
                with open(dest, "wb") as f:
                    f.write(zip_data)
                return zip_sha

            def fake_materialize(_repository, _commit, destination, **_kwargs):
                nonlocal materialize_count
                materialize_count += 1
                return SimpleNamespace(
                    source_root=destination,
                    plugin_json=None,
                    package_json=None,
                )

            def fake_trivy(*_args, source_root=None, **_kwargs):
                del source_root
                nonlocal trivy_count
                trivy_count += 1
                return ap.ScannerStatus(name="trivy", status="passed"), []

            def fake_compare(_extract_dir, _snapshot, ref):
                nonlocal compare_count
                del ref
                compare_count += 1
                return (
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                )

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch.object(
                    ap.audit_source_snapshot,
                    "materialize_source_snapshot",
                    side_effect=fake_materialize,
                ),
                patch(
                    "audit_plugins.run_clamav",
                    return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
                ),
                patch("audit_plugins.run_trivy", side_effect=fake_trivy),
                patch(
                    "audit_plugins.run_semgrep",
                    return_value=(
                        ap.ScannerStatus(name="semgrep", status="skipped"),
                        [],
                    ),
                ),
                patch(
                    "audit_plugins.compare_source_and_artifact_from_snapshot",
                    side_effect=fake_compare,
                ),
            ):
                first = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )
                second = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )

        self.assertEqual(first.final_classification, "PASS")
        self.assertEqual(second.final_classification, "PASS")
        self.assertEqual(download_count, 2)
        self.assertEqual(materialize_count, 1)
        self.assertEqual(trivy_count, 1)
        self.assertEqual(compare_count, 1)

    def test_cache_miss_does_source_materialization(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
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
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []
            zip_data = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_data).hexdigest()

            download_count = 0
            materialize_count = 0
            trivy_count = 0
            compare_count = 0

            def download(_url, dest, policy=None):
                del _url, policy
                nonlocal download_count
                download_count += 1
                with open(dest, "wb") as f:
                    f.write(zip_data)
                return zip_sha

            def fake_materialize(_repository, _commit, destination, **_kwargs):
                nonlocal materialize_count
                materialize_count += 1
                return SimpleNamespace(
                    source_root=destination,
                    plugin_json=None,
                    package_json=None,
                )

            def fake_trivy(*_args, source_root=None, **_kwargs):
                del source_root
                nonlocal trivy_count
                trivy_count += 1
                return ap.ScannerStatus(name="trivy", status="passed"), []

            def fake_compare(_extract_dir, _snapshot, ref):
                nonlocal compare_count
                del ref
                compare_count += 1
                return (
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                )

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch.object(
                    ap.audit_source_snapshot,
                    "materialize_source_snapshot",
                    side_effect=fake_materialize,
                ),
                patch(
                    "audit_plugins.run_clamav",
                    return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
                ),
                patch("audit_plugins.run_trivy", side_effect=fake_trivy),
                patch(
                    "audit_plugins.run_semgrep",
                    return_value=(
                        ap.ScannerStatus(name="semgrep", status="skipped"),
                        [],
                    ),
                ),
                patch(
                    "audit_plugins.compare_source_and_artifact_from_snapshot",
                    side_effect=fake_compare,
                ),
            ):
                report = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                )

        self.assertEqual(report.final_classification, "PASS")
        self.assertEqual(download_count, 1)
        self.assertEqual(materialize_count, 1)
        self.assertEqual(trivy_count, 1)
        self.assertEqual(compare_count, 1)

    def test_skip_cache_forces_fresh_audit(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_dir = os.path.join(tmp_dir, ".audit-cache")
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
            policy = {"enforcement": {"mode": "report-only"}, "scanners": {}}
            exceptions = []
            zip_data = _make_zip([_regular("plugin.json", '{"name":"test"}')])
            zip_sha = hashlib.sha256(zip_data).hexdigest()

            download_count = 0
            materialize_count = 0
            trivy_count = 0
            compare_count = 0

            def download(_url, dest, policy=None):
                del _url, policy
                nonlocal download_count
                download_count += 1
                with open(dest, "wb") as f:
                    f.write(zip_data)
                return zip_sha

            def fake_materialize(_repository, _commit, destination, **_kwargs):
                nonlocal materialize_count
                materialize_count += 1
                return SimpleNamespace(
                    source_root=destination,
                    plugin_json=None,
                    package_json=None,
                )

            def fake_trivy(*_args, source_root=None, **_kwargs):
                del source_root
                nonlocal trivy_count
                trivy_count += 1
                return ap.ScannerStatus(name="trivy", status="passed"), []

            def fake_compare(_extract_dir, _snapshot, ref):
                nonlocal compare_count
                del ref
                compare_count += 1
                return (
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                )

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
                ),
                patch("audit_plugins.get_repo_file_raw", return_value=None),
                patch("audit_plugins.download_zip", side_effect=download),
                patch.object(
                    ap.audit_source_snapshot,
                    "materialize_source_snapshot",
                    side_effect=fake_materialize,
                ),
                patch(
                    "audit_plugins.run_clamav",
                    return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
                ),
                patch("audit_plugins.run_trivy", side_effect=fake_trivy),
                patch(
                    "audit_plugins.run_semgrep",
                    return_value=(
                        ap.ScannerStatus(name="semgrep", status="skipped"),
                        [],
                    ),
                ),
                patch(
                    "audit_plugins.compare_source_and_artifact_from_snapshot",
                    side_effect=fake_compare,
                ),
            ):
                _ = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                _ = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=False,
                )
                _ = ap.audit_repository(
                    "https://github.com/owner/repo",
                    policy,
                    exceptions,
                    cache_dir=cache_dir,
                    skip_cache=True,
                )

        self.assertEqual(download_count, 3)
        self.assertEqual(materialize_count, 2)
        self.assertEqual(trivy_count, 2)
        self.assertEqual(compare_count, 2)

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

            def mock_download(url, dest_path, policy=None):
                del url, policy
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
                        "digest": f"sha256:{zip_sha}",
                    }
                ],
            }

            with (
                patch("audit_plugins.get_repo_metadata", return_value={"name": "repo"}),
                patch("audit_plugins.get_releases", return_value=[release_data]),
                patch(
                    "audit_plugins._resolve_ref_to_commit_and_tree_sha",
                    return_value=("a" * 40, "tree123", None),
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

            def mock_download(url, dest_path, policy=None):
                del url, policy
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
                        "digest": f"sha256:{zip_sha}",
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

            def mock_download(url, dest_path, policy=None):
                del url, policy
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
                    return_value=("a" * 40, "tree123", None),
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
