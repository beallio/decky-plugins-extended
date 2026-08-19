#!/usr/bin/env python3
"""audit_plugins.py - Automated security-auditing pipeline for Decky Loader plugins.

Static inspection only.  Plugin code is NEVER imported or executed.

Usage:
    uv run python audit_plugins.py --all
    uv run python audit_plugins.py --changed [--base-ref <git-ref>]
    uv run python audit_plugins.py --repository https://github.com/owner/repo
    uv run python audit_plugins.py --all --output-dir /path/to/reports

Exit codes:
    0  All audits passed (PASS or PASS_WITH_WARNINGS in any mode; BLOCK/
       MANUAL_REVIEW in report-only mode).
    1  Internal infrastructure failure (always fatal regardless of mode).
    2  One or more BLOCK findings (enforcement mode only).
    3  One or more MANUAL_REVIEW findings, none BLOCK (enforcement mode only).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import logging
import math
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Collection, Optional
from urllib.parse import urlparse

import requests
import yaml
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import audit_source_snapshot
import audit_worklist
import plugin_release_utils

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUDIT_SCHEMA_VERSION = "1"
POLICY_VERSION = "1"
PLUGINS_FILE = "additional_plugins.txt"
DEFAULT_POLICY_FILE = "security-policy.yml"
DEFAULT_ALLOWLIST_FILE = "security-allowlist.yml"
DEFAULT_OUTPUT_DIR = "security-reports"
CACHE_DIR = ".audit-cache"
VERDICTS_FILE = "security-verdicts.json"
LEGACY_VERDICTS_FILE = "verdicts.json"
REQUEST_TIMEOUT = 30  # seconds per HTTP request
DOWNLOAD_TIMEOUT = 120  # seconds for ZIP downloads
MAX_RETRIES = 3
EVIDENCE_MAX_LEN = 256
SECRET_REDACT = "[REDACTED]"
SEMGREP_RULES_FILE = str(Path(__file__).with_name("semgrep-rules.yml"))

log = logging.getLogger("audit_plugins")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

# Final classification values (ordered by severity descending)
CLASSIFICATION_ORDER = [
    "AUDIT_ERROR",
    "BLOCK",
    "MANUAL_REVIEW",
    "PASS_WITH_WARNINGS",
    "PASS",
]

RULE_CLASSIFICATION_VALUES = {
    "BLOCK",
    "MANUAL_REVIEW",
    "PASS_WITH_WARNINGS",
    "PASS",
}

DEFAULT_BLOCKABLE_RULES = (
    "MALWARE",
    "ARCHIVE_TRAVERSAL",
    "ARCHIVE_ESCAPE_SYMLINK",
    "ARCHIVE_BOMB_RATIO",
    "ARCHIVE_BOMB_SIZE",
    "ARCHIVE_SETUID_FILE",
    "ARCHIVE_DEVICE_FILE",
    "ARCHIVE_NAMED_PIPE",
    "ARCHIVE_FILE_COUNT_EXCEEDED",
    "ARCHIVE_SINGLE_FILE_TOO_LARGE",
)

_NON_TABLE_RULE_IDS = {
    "ARCHIVE_BOMB_RATIO",
    "ARCHIVE_BOMB_SIZE",
    "ARCHIVE_DEVICE_FILE",
    "ARCHIVE_DUPLICATE_PATH",
    "ARCHIVE_ESCAPE_SYMLINK",
    "ARCHIVE_FILE_COUNT_EXCEEDED",
    "ARCHIVE_NAMED_PIPE",
    "ARCHIVE_SETUID_FILE",
    "ARCHIVE_SINGLE_FILE_TOO_LARGE",
    "ARCHIVE_TRAVERSAL",
    "CORRUPT_ARCHIVE",
    "INVALID_PACKAGE_JSON",
    "INVALID_PLUGIN_JSON",
    "MALWARE",
    "MISSING_PLUGIN_JSON",
    "MISSING_PLUGIN_NAME",
    "MISSING_RELEASE_METADATA",
    "MODIFIED_SOURCE_FILE",
    "NATIVE_BINARY",
    "OBFUSCATION_LARGE_BASE64",
    "PACKAGE_LIFECYCLE_SCRIPT",
    "ROOT_ACCESS",
    "SOURCE_ARTIFACT_DIFF_INCOMPLETE",
    "ZIP_ONLY_EXECUTABLE",
    "ZIP_ONLY_SCRIPT",
}


_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "github_token",
        re.compile(
            r"ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"
        ),
    ),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|api_secret)\s*[=:]\s*"
            r"(?P<quote>['\"])(?P<value>[^'\"]{16,})(?P=quote)"
        ),
    ),
    (
        "bearer_token",
        re.compile(
            r"(?i)(?:bearer|token)\s*[=:]\s*"
            r"(?P<quote>['\"])(?P<value>[^'\"]{20,})(?P=quote)"
        ),
    ),
    (
        "cloudflare_token",
        re.compile(
            r"(?i)cf[-_](?:token|key|api)\s*[=:]\s*"
            r"(?P<quote>['\"])(?P<value>[^'\"]{20,})(?P=quote)"
        ),
    ),
    ("password_literal", re.compile(r"(?i)password\s*=\s*['\"]([^'\"]{8,})['\"]")),
]


def redact_secrets(text: str) -> str:
    """Redact secret patterns from text."""
    if not text:
        return text
    result = str(text)
    for _name, pattern in _SECRET_PATTERNS:

        def _repl(m: re.Match) -> str:
            if "value" in m.re.groupindex:
                full = m.group(0)
                start_value = m.start("value") - m.start(0)
                end_value = m.end("value") - m.start(0)
                return full[:start_value] + SECRET_REDACT + full[end_value:]
            if m.lastindex and m.lastindex >= 1:
                full = m.group(0)
                start_g1 = m.start(1) - m.start(0)
                end_g1 = m.end(1) - m.start(0)
                return full[:start_g1] + SECRET_REDACT + full[end_g1:]
            return SECRET_REDACT

        result = pattern.sub(_repl, result)
    return result


def git_blob_sha1(data: bytes) -> str:
    """Compute Git's blob SHA-1 for binary data."""
    header = f"blob {len(data)}\x00".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


@dataclass
class Finding:
    rule_id: str
    severity: str  # critical / high / medium / low / info
    classification: str  # BLOCK / MANUAL_REVIEW / PASS_WITH_WARNINGS / PASS
    path: str
    line: int
    message: str
    evidence: str  # length-limited, secrets redacted
    scanner: str
    allowlisted: bool = False

    def __post_init__(self) -> None:
        if self.evidence:
            self.evidence = redact_secrets(self.evidence)


@dataclass
class ScannerStatus:
    name: str
    status: str  # passed / found_issue / unavailable / unsupported / failed
    version: Optional[str] = None
    db_version: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class ArchiveStats:
    compressed_bytes: int = 0
    uncompressed_bytes: int = 0
    file_count: int = 0
    compression_ratio: float = 0.0
    sha256: str = ""
    safe: bool = True
    issues: list[str] = field(default_factory=list)
    static_scan_skipped_extensions: dict[str, int] = field(default_factory=dict)


@dataclass
class AuditReport:
    schema_version: str = AUDIT_SCHEMA_VERSION
    policy_version: str = POLICY_VERSION
    audit_timestamp: str = ""
    repository: str = ""
    release: str = ""
    release_id: str = ""
    github_release_id: str = ""
    asset_id: str = ""
    release_published_at: str = ""
    artifact_url: str = ""
    artifact_sha256: str = ""
    identity_status: str = "UNKNOWN"
    completion_status: str = "incomplete"
    error_scope: str = "release"
    audit_context_hash: str = ""
    resolved_tag_commit_sha: str = ""
    plugin_name: str = ""
    final_classification: str = "AUDIT_ERROR"
    risk_score: int = 0
    findings: list[Finding] = field(default_factory=list)
    scanner_statuses: list[ScannerStatus] = field(default_factory=list)
    archive_stats: Optional[ArchiveStats] = None
    extracted_domains: list[str] = field(default_factory=list)
    native_binaries: list[dict[str, Any]] = field(default_factory=list)
    dependency_summary: dict[str, Any] = field(default_factory=dict)
    source_artifact_diff: dict[str, Any] = field(default_factory=dict)
    allowlist_decisions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class VerdictResult:
    effective_classification: str
    audit_classification: str
    blocking_rule_ids: list[str] = field(default_factory=list)
    identity_status: str = "UNKNOWN"
    current_artifact_sha256: Optional[str] = None
    stored_artifact_sha256: Optional[str] = None
    fail_open: bool = True


@dataclass(frozen=True)
class AuditWorkItem:
    repository: str
    release: dict[str, Any]
    repository_metadata: dict[str, Any]


@dataclass(frozen=True)
class ReviewQueueEntry:
    repository: str
    release_id: str
    score: float
    rarest_rules: tuple[tuple[str, int], ...]


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------


def _load_yaml(path: str) -> dict[str, Any]:
    """Load a YAML file exclusively via PyYAML's safe_load.

    Raises ValueError when the top-level value is not a mapping or when the
    file cannot be parsed.
    """
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected a YAML mapping at the top level, "
            f"got {type(data).__name__!r}."
        )
    return data


def load_policy(path: str = DEFAULT_POLICY_FILE) -> dict[str, Any]:
    """Load and validate security-policy.yml."""
    if not os.path.exists(path):
        log.warning("Policy file %s not found; using built-in defaults.", path)
        return _default_policy()
    try:
        data = _load_yaml(path)
    except (ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"Malformed policy file {path}: {exc}") from exc
    # Merge with defaults so new fields are always present
    policy = _default_policy()
    _deep_merge(policy, data)
    _validate_rule_classifications(policy, path)
    _validate_blockable_rules(policy, path)
    plugin_release_utils.validate_download_policy(policy)
    return policy


def _default_policy() -> dict[str, Any]:
    return {
        "version": "1",
        "enforcement": {"mode": "report-only"},
        "rule_classifications": {},
        "blockable_rules": list(DEFAULT_BLOCKABLE_RULES),
        "archive": {
            "max_files": 10000,
            "max_uncompressed_bytes": 1073741824,
            "max_single_file_bytes": 536870912,
            "max_compression_ratio": 200,
            "max_path_depth": 30,
        },
        "downloads": {
            "release_max_bytes": plugin_release_utils.DEFAULT_RELEASE_MAX_BYTES,
            "source_max_bytes": plugin_release_utils.DEFAULT_SOURCE_MAX_BYTES,
            "connect_timeout_seconds": plugin_release_utils.DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
            "read_timeout_seconds": plugin_release_utils.DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS,
            "chunk_size_bytes": plugin_release_utils.DEFAULT_DOWNLOAD_CHUNK_SIZE_BYTES,
        },
        "vulnerabilities": {
            "block_severity": "critical",
            "review_severity": "high",
        },
        "scanners": {
            "clamav": {"enabled": True, "required": True},
            "trivy": {"enabled": True, "required": True},
            "semgrep": {"enabled": True, "required": False},
            "osv_scanner": {"enabled": False, "required": False},
            "source_artifact_diff": {"enabled": True, "required": True},
        },
    }


def _known_policy_rule_ids() -> set[str]:
    table_rule_ids = {
        rule_id
        for rules in (_PYTHON_RULES, _JS_RULES, _SHELL_RULES)
        for rule_id, _severity, _classification, _message, _pattern in rules
    }
    secret_rule_ids = {f"SECRET_{name.upper()}" for name, _pattern in _SECRET_PATTERNS}
    return table_rule_ids | secret_rule_ids | _NON_TABLE_RULE_IDS


def _validate_rule_classifications(policy: dict[str, Any], path: str) -> None:
    overrides = policy.get("rule_classifications", {})
    if not isinstance(overrides, dict):
        raise ValueError(f"rule_classifications must be a mapping in {path}.")

    known_rule_ids = _known_policy_rule_ids()
    unknown_rule_ids = sorted(set(overrides) - known_rule_ids)
    if unknown_rule_ids:
        raise ValueError(
            f"Unknown rule ID(s) in rule_classifications for {path}: "
            + ", ".join(str(rule_id) for rule_id in unknown_rule_ids)
        )

    invalid_values = {
        rule_id: classification
        for rule_id, classification in overrides.items()
        if classification not in RULE_CLASSIFICATION_VALUES
    }
    if invalid_values:
        rendered = ", ".join(
            f"{rule_id}={classification!r}"
            for rule_id, classification in sorted(invalid_values.items())
        )
        allowed = ", ".join(sorted(RULE_CLASSIFICATION_VALUES))
        raise ValueError(
            f"Invalid rule classification override(s) in {path}: {rendered}. "
            f"Allowed values: {allowed}."
        )


def _validate_blockable_rules(policy: dict[str, Any], path: str) -> None:
    blockable_rules = policy.get("blockable_rules", [])
    if not isinstance(blockable_rules, list) or not all(
        isinstance(rule_id, str) for rule_id in blockable_rules
    ):
        raise ValueError(f"blockable_rules must be a list of rule IDs in {path}.")

    known_rule_ids = _known_policy_rule_ids()
    unknown_rule_ids = sorted(set(blockable_rules) - known_rule_ids)
    if unknown_rule_ids:
        raise ValueError(
            f"Unknown rule ID(s) in blockable_rules for {path}: "
            + ", ".join(unknown_rule_ids)
        )


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


_CANONICAL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_CANONICAL_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_WORKER_PROGRESS_SCHEMA_V2 = "2"
_WORKER_PROGRESS_ROOT_KEYS_V2 = {
    "schema_version",
    "worklist_fingerprint",
    "entries",
}
_WORKER_PROGRESS_RECORD_KEYS_V2 = {
    "repository",
    "github_release_id",
    "asset_id",
    "artifact_sha256",
    "resolved_tag_commit_sha",
    "audit_context_hash",
    "completion_status",
    "report",
    "worklist_fingerprint",
}
_SHARD_MANIFEST_SCHEMA_VERSION = "1"
_SHARD_MANIFEST_ROOT_KEYS = {
    "schema_version",
    "worklist_fingerprint",
    "source_revision",
    "shard_count",
    "shard_index",
    "assigned_identities",
    "attempted_identities",
    "report_identities",
}
_SHARD_MANIFEST_IDENTITY_KEYS = {"repository", "github_release_id", "asset_id"}


def load_allowlist(
    path: str = DEFAULT_ALLOWLIST_FILE,
    *,
    policy: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Load and validate security-allowlist.yml.

    Raises ValueError for malformed entries.
    Returns list of validated exception dicts.
    """
    if not os.path.exists(path):
        return []
    try:
        data = _load_yaml(path)
    except (ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"Malformed allowlist file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Allowlist {path} must be a YAML mapping.")
    exceptions = data.get("exceptions") or []
    if not isinstance(exceptions, list):
        raise ValueError(f"allowlist 'exceptions' must be a list in {path}.")
    blockable_rules = set(
        (policy if policy is not None else _default_policy()).get("blockable_rules", [])
    )
    validated: list[dict[str, Any]] = []
    seen_identities: dict[tuple[str, str, str, str], int] = {}
    for i, entry in enumerate(exceptions):
        if not isinstance(entry, dict):
            raise ValueError(f"Allowlist entry {i} is not a mapping.")
        for required in (
            "repository",
            "release",
            "artifact_sha256",
            "rule",
            "reason",
            "approved_by",
            "expires",
        ):
            if not entry.get(required):
                raise ValueError(
                    f"Allowlist entry {i} missing required field '{required}'."
                )
        try:
            repository = plugin_release_utils.canonical_repository_identity(
                entry["repository"]
            )
        except ValueError as exc:
            raise ValueError(
                f"Allowlist entry {i} has invalid repository: {entry['repository']!r}."
            ) from exc
        rule_id = str(entry["rule"])
        artifact_sha256 = str(entry["artifact_sha256"])
        if rule_id in blockable_rules and not _CANONICAL_SHA256.fullmatch(
            artifact_sha256
        ):
            raise ValueError(
                f"Allowlist entry {i} rule {rule_id!r} requires an exact "
                "lowercase artifact_sha256."
            )
        if artifact_sha256 != "any" and not _CANONICAL_SHA256.fullmatch(
            artifact_sha256
        ):
            raise ValueError(
                f"Allowlist entry {i} artifact_sha256 must be 'any' or an exact "
                "lowercase SHA-256."
            )
        # Validate expires format if present
        if "expires" in entry and entry["expires"]:
            try:
                datetime.date.fromisoformat(str(entry["expires"]))
            except ValueError:
                raise ValueError(
                    f"Allowlist entry {i} 'expires' must be ISO 8601 date (YYYY-MM-DD)."
                )
        identity = (
            repository,
            str(entry["release"]),
            artifact_sha256,
            rule_id,
        )
        previous_index = seen_identities.get(identity)
        if previous_index is not None:
            raise ValueError(
                f"Allowlist entries {previous_index} and {i} collide after "
                "repository canonicalization."
            )
        seen_identities[identity] = i
        validated_entry = dict(entry)
        validated_entry["repository"] = repository
        validated.append(validated_entry)
    return validated


def check_allowlist_expiry(exceptions: list[dict[str, Any]]) -> list[str]:
    """Return warnings for expired allowlist entries."""
    today = datetime.date.today()
    warnings: list[str] = []
    for entry in exceptions:
        expires_str = entry.get("expires")
        if expires_str:
            try:
                expires = datetime.date.fromisoformat(str(expires_str))
                if expires < today:
                    warnings.append(
                        f"Allowlist entry for {entry.get('repository')} "
                        f"rule {entry.get('rule')} expired {expires_str}."
                    )
            except ValueError:
                pass
    return warnings


def apply_allowlist(
    findings: list[Finding],
    exceptions: list[dict[str, Any]],
    repository: str,
    release: str,
    artifact_sha256: str,
    *,
    policy: Optional[dict[str, Any]] = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Mark findings as allowlisted where an exception applies.

    Returns (updated findings, list of allowlist decision records).
    Every rule in the live policy's ``blockable_rules`` may only be allowlisted
    when a canonical lowercase artifact SHA-256 matches exactly.
    """
    today = datetime.date.today()
    decisions: list[dict[str, Any]] = []
    # Normalise repo to "owner/repo" format
    norm_repo = _normalise_repo_key(repository)
    blockable_rules = set(
        (policy if policy is not None else _default_policy()).get("blockable_rules", [])
    )

    for finding in findings:
        for exc in exceptions:
            exc_repo = _normalise_repo_key(str(exc.get("repository", "")))
            exc_rule = str(exc.get("rule", ""))
            exc_release = str(exc.get("release", "")) if exc.get("release") else None
            exc_sha = (
                str(exc.get("artifact_sha256", ""))
                if exc.get("artifact_sha256")
                else None
            )
            expires_str = exc.get("expires")

            if exc_repo != norm_repo:
                continue
            if exc_rule != finding.rule_id:
                continue
            if exc_release and exc_release != release:
                continue

            if finding.rule_id in blockable_rules:
                if (
                    not exc_sha
                    or not _CANONICAL_SHA256.fullmatch(exc_sha)
                    or exc_sha != artifact_sha256
                ):
                    log.warning(
                        "Allowlist entry for %s/%s rejected: %s requires exact artifact_sha256.",
                        exc_repo,
                        exc_rule,
                        finding.rule_id,
                    )
                    continue
            if exc_sha and exc_sha != "any" and exc_sha != artifact_sha256:
                continue

            # Check expiry
            if expires_str:
                try:
                    if datetime.date.fromisoformat(str(expires_str)) < today:
                        log.warning(
                            "Allowlist entry for %s/%s is expired.", exc_repo, exc_rule
                        )
                        continue
                except ValueError:
                    continue

            finding.allowlisted = True
            decisions.append(
                {
                    "rule_id": finding.rule_id,
                    "repository": exc_repo,
                    "release": exc_release,
                    "artifact_sha256": exc_sha,
                    "reason": exc.get("reason"),
                    "approved_by": exc.get("approved_by"),
                    "expires": str(expires_str) if expires_str else None,
                }
            )
            break

    return findings, decisions


def _normalise_repo_key(repo: str) -> str:
    """Normalize a strict GitHub URL or exact owner/repo key."""
    return plugin_release_utils.canonical_repository_identity(repo)


def _scanner_enabled(policy: dict[str, Any], name: str) -> bool:
    """Return True when the named scanner is enabled in policy."""
    scanners = policy.get("scanners", {})
    cfg = scanners.get(name)
    if cfg is None and "-" in name:
        cfg = scanners.get(name.replace("-", "_"))
    if cfg is None and "_" in name:
        cfg = scanners.get(name.replace("_", "-"))
    if cfg is None:
        cfg = {}
    # Support both old bool format and new {enabled, required} format.
    if isinstance(cfg, dict):
        return bool(cfg.get("enabled", True))
    return bool(cfg)


def _scanner_required(policy: dict[str, Any], name: str) -> bool:
    """Return True when the named scanner is required in policy."""
    scanners = policy.get("scanners", {})
    cfg = scanners.get(name)
    if cfg is None and "-" in name:
        cfg = scanners.get(name.replace("-", "_"))
    if cfg is None and "_" in name:
        cfg = scanners.get(name.replace("_", "-"))
    if cfg is None:
        cfg = {}
    if isinstance(cfg, dict):
        return bool(cfg.get("required", False))
    # Legacy bool: treat enabled as required for backward compatibility.
    return bool(cfg)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

SEVERITY_SCORE = {"critical": 40, "high": 15, "medium": 5, "low": 2, "info": 0}


def classify_findings(
    findings: list[Finding],
    has_error: bool = False,
    scanner_statuses: Optional[list[ScannerStatus]] = None,
    policy: Optional[dict[str, Any]] = None,
) -> tuple[str, int]:
    """Aggregate findings into a final classification and risk score.

    A deterministic block takes precedence over behavioral scanner failures.
    Otherwise required scanner failures (status "failed" or "unavailable")
    cause AUDIT_ERROR. "unsupported" on a required scanner causes at least
    MANUAL_REVIEW.

    Returns (classification_string, risk_score).
    """
    if has_error:
        return "AUDIT_ERROR", 0

    active = [f for f in findings if not f.allowlisted]
    score = sum(SEVERITY_SCORE.get(f.severity, 0) for f in active)
    classifications = {f.classification for f in active}

    if "BLOCK" in classifications:
        return "BLOCK", score

    # Check required scanner statuses.
    if scanner_statuses and policy:
        for ss in scanner_statuses:
            name = ss.name if isinstance(ss, ScannerStatus) else ss.get("name", "")
            status = (
                ss.status if isinstance(ss, ScannerStatus) else ss.get("status", "")
            )
            if not _scanner_required(policy, name):
                continue
            if status in ("failed", "unavailable"):
                return "AUDIT_ERROR", 0

    # Unsupported required scanner → at least MANUAL_REVIEW.
    if scanner_statuses and policy:
        for ss in scanner_statuses:
            name = ss.name if isinstance(ss, ScannerStatus) else ss.get("name", "")
            status = (
                ss.status if isinstance(ss, ScannerStatus) else ss.get("status", "")
            )
            if _scanner_required(policy, name) and status == "unsupported":
                classifications.add("MANUAL_REVIEW")

    if "MANUAL_REVIEW" in classifications:
        return "MANUAL_REVIEW", score
    if "PASS_WITH_WARNINGS" in classifications:
        return "PASS_WITH_WARNINGS", score
    return "PASS", score


def apply_rule_classification_policy(
    findings: list[Finding], policy: dict[str, Any]
) -> None:
    """Apply overrides, then cap non-structural findings at manual review."""
    _validate_rule_classifications(policy, "in-memory policy")
    _validate_blockable_rules(policy, "in-memory policy")
    overrides = policy.get("rule_classifications", {})
    blockable_rules = set(policy.get("blockable_rules", []))
    for finding in findings:
        classification = overrides.get(finding.rule_id)
        if classification is not None:
            finding.classification = classification
        if finding.classification == "BLOCK" and finding.rule_id not in blockable_rules:
            finding.classification = "MANUAL_REVIEW"


def apply_rule_classification_overrides(
    findings: list[Finding], policy: dict[str, Any]
) -> None:
    """Backward-compatible name for applying all rule-classification policy."""
    apply_rule_classification_policy(findings, policy)


# ---------------------------------------------------------------------------
# GitHub API client
# ---------------------------------------------------------------------------

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


def _make_github_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    # Read token at call time so tests can control it via os.environ.
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    s.headers.update(headers)
    return s


_gh_session = _make_github_session()


def _gh_get(url: str, params: Optional[dict] = None) -> dict | list:
    """Perform a GitHub API GET with rate-limit handling."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = _gh_session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            if attempt < MAX_RETRIES:
                time.sleep(2**attempt)
                continue
            raise

        if resp.status_code == 429 or (
            resp.status_code == 403 and "rate limit" in resp.text.lower()
        ):
            reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(1, reset - int(time.time())) + 5
            log.warning("GitHub rate limit hit; sleeping %d s.", wait)
            time.sleep(wait)
            continue

        resp.raise_for_status()
        return resp.json()

    raise RuntimeError(f"Failed to fetch {url} after retries")


def get_repo_metadata(owner: str, repo: str) -> dict[str, Any]:
    return _gh_get(f"https://api.github.com/repos/{owner}/{repo}")  # type: ignore


def get_releases(owner: str, repo: str) -> list[dict[str, Any]]:
    return plugin_release_utils.get_releases(
        owner, repo, session=_gh_session, timeout=REQUEST_TIMEOUT
    )


def get_tags(owner: str, repo: str) -> list[dict[str, Any]]:
    return _gh_get(  # type: ignore
        f"https://api.github.com/repos/{owner}/{repo}/tags",
        params={"per_page": 100},
    )


def get_repo_file_raw(owner: str, repo: str, ref: str, path: str) -> Optional[bytes]:
    """Fetch raw file bytes from a GitHub repository at a specific ref."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    try:
        resp = _gh_session.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.content
    except requests.RequestException:
        return None


def parse_owner_repo(url: str) -> tuple[str, str]:
    """Parse a strict GitHub repository URL into canonical owner/repo."""
    return plugin_release_utils.parse_github_repository_url(url)


def find_best_release(releases: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return the newest non-prerelease release with exactly one ZIP asset.

    Falls back to prerelease if no stable release exists.

    Uses the same selection logic as the catalog generator (via plugin_release_utils)
    so the auditor inspects the exact artifact users would install.
    """
    # Try stable first, then allow prereleases.
    result = plugin_release_utils.select_best_release(releases, allow_prerelease=False)
    if result is None:
        result = plugin_release_utils.select_best_release(
            releases, allow_prerelease=True
        )
    return result


# ---------------------------------------------------------------------------
# Plugin list parsing
# ---------------------------------------------------------------------------


def read_repo_urls(path: str = PLUGINS_FILE) -> list[str]:
    """Read repository URLs from additional_plugins.txt, deduplicated."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Plugin list not found: {path}")
    seen: set[str] = set()
    urls: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            canonical = plugin_release_utils.canonicalize_github_repository_url(url)
            norm = canonical.lower()
            if norm in seen:
                log.warning("Duplicate URL skipped: %s", url)
                continue
            seen.add(norm)
            urls.append(canonical)
    return urls


def get_changed_repos(
    plugins_file: str = PLUGINS_FILE, base_ref: str = "HEAD~1"
) -> list[str]:
    """Return repository URLs newly added or changed relative to base_ref.

    Falls back to all repos if git diff is unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "diff", base_ref, "--", plugins_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.warning(
                "git diff failed (exit %d); auditing all repos.", result.returncode
            )
            return read_repo_urls(plugins_file)
        added: list[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                url = line[1:].strip()
                if url and not url.startswith("#") and url.startswith("https://"):
                    added.append(url.rstrip("/"))
        return added
    except Exception as exc:
        log.warning("Could not compute git diff (%s); auditing all repos.", exc)
        return read_repo_urls(plugins_file)


# ---------------------------------------------------------------------------
# Safe ZIP inspection
# ---------------------------------------------------------------------------

# Configurable limits (overridden from policy at runtime)
_ARCHIVE_POLICY: dict[str, Any] = {}


def _archive_policy(key: str) -> Any:
    defaults = _default_policy()["archive"]
    return _ARCHIVE_POLICY.get(key, defaults[key])


def _is_safe_member_path(name: str) -> tuple[bool, str]:
    """Return (is_safe, reason) for a ZIP member path."""
    # Null bytes
    if "\x00" in name:
        return False, "null byte in path"

    # Normalise path separators so backslash traversal ("..\\") can't bypass checks.
    name = name.replace("\\\\", "/")

    # Absolute path
    if name.startswith("/"):
        return False, "absolute path"
    # Windows drive letter
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return False, "Windows drive-letter path"
    # Normalise and check for traversal
    try:
        norm = PurePosixPath(name)
        for part in norm.parts:
            if part == "..":
                return False, "path traversal (..)"
    except Exception:
        return False, "unparseable path"
    # Check depth
    depth = len(norm.parts)
    if depth > _archive_policy("max_path_depth"):
        return False, f"path depth {depth} exceeds limit"
    return True, ""


def inspect_zip(
    zip_path: str,
    policy: Optional[dict[str, Any]] = None,
) -> tuple[ArchiveStats, list[Finding]]:
    """Validate a ZIP archive without extracting it.

    Returns (ArchiveStats, list[Finding]).
    All path safety checks happen before any extraction.
    """
    global _ARCHIVE_POLICY
    # Always reset policy so tests (and repeated calls) start from a clean state.
    _ARCHIVE_POLICY = (policy or {}).get("archive", {})

    stats = ArchiveStats()
    findings: list[Finding] = []

    # Compute SHA-256 and compressed size
    sha256 = hashlib.sha256()
    with open(zip_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha256.update(chunk)
            stats.compressed_bytes += len(chunk)
    stats.sha256 = sha256.hexdigest()

    try:
        zf = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile as exc:
        stats.safe = False
        stats.issues.append(f"Invalid ZIP: {exc}")
        findings.append(
            Finding(
                rule_id="CORRUPT_ARCHIVE",
                severity="high",
                classification="PASS_WITH_WARNINGS",
                path="<archive>",
                line=0,
                message=f"ZIP file is corrupt or invalid: {exc}",
                evidence="",
                scanner="zip-inspector",
            )
        )
        return stats, findings

    seen_paths: dict[str, str] = {}  # normalised lower → original name

    with zf:
        members = zf.infolist()
        stats.file_count = len(members)
        max_files = _archive_policy("max_files")
        if stats.file_count > max_files:
            stats.safe = False
            stats.issues.append(f"Too many files: {stats.file_count} > {max_files}")
            findings.append(
                Finding(
                    rule_id="ARCHIVE_FILE_COUNT_EXCEEDED",
                    severity="high",
                    classification="BLOCK",
                    path="<archive>",
                    line=0,
                    message=f"Archive contains {stats.file_count} files (limit {max_files}).",
                    evidence="",
                    scanner="zip-inspector",
                )
            )

        for info in members:
            name = info.filename
            uncompressed = info.file_size
            stats.uncompressed_bytes += uncompressed

            # --- Path safety ---
            safe, reason = _is_safe_member_path(name)
            if not safe:
                stats.safe = False
                stats.issues.append(f"Unsafe path {name!r}: {reason}")
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_TRAVERSAL",
                        severity="critical",
                        classification="BLOCK",
                        path=name,
                        line=0,
                        message=f"Archive member has unsafe path: {reason}",
                        evidence=_truncate(name, EVIDENCE_MAX_LEN),
                        scanner="zip-inspector",
                    )
                )

            # --- Duplicate / case-collision paths ---
            norm_name = unicodedata.normalize("NFC", name.lower())
            if norm_name in seen_paths:
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_DUPLICATE_PATH",
                        severity="medium",
                        classification="MANUAL_REVIEW",
                        path=name,
                        line=0,
                        message=f"Duplicate normalised path collides with {seen_paths[norm_name]!r}.",
                        evidence=_truncate(name, EVIDENCE_MAX_LEN),
                        scanner="zip-inspector",
                    )
                )
            else:
                seen_paths[norm_name] = name

            # --- Single file size ---
            max_single = _archive_policy("max_single_file_bytes")
            if uncompressed > max_single:
                stats.safe = False
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_SINGLE_FILE_TOO_LARGE",
                        severity="high",
                        classification="BLOCK",
                        path=name,
                        line=0,
                        message=f"Single file {name!r} uncompressed size {uncompressed} exceeds limit.",
                        evidence="",
                        scanner="zip-inspector",
                    )
                )

            # --- Symlinks escaping extraction dir ---
            if info.external_attr >> 28 == 0xA:  # Unix symlink type
                target = "<unreadable>"
                try:
                    target = zf.read(info.filename).decode(errors="replace")
                except Exception as exc:
                    stats.safe = False
                    findings.append(
                        Finding(
                            rule_id="ARCHIVE_ESCAPE_SYMLINK",
                            severity="critical",
                            classification="BLOCK",
                            path=name,
                            line=0,
                            message=f"Symlink {name!r}: target could not be read: {exc}",
                            evidence="",
                            scanner="zip-inspector",
                        )
                    )
                    continue
                # Reject null bytes in symlink target.
                if "\x00" in target:
                    stats.safe = False
                    findings.append(
                        Finding(
                            rule_id="ARCHIVE_ESCAPE_SYMLINK",
                            severity="critical",
                            classification="BLOCK",
                            path=name,
                            line=0,
                            message=f"Symlink {name!r} target contains a null byte.",
                            evidence="",
                            scanner="zip-inspector",
                        )
                    )
                    continue
                # Validate using lexical POSIX path normalization only; no
                # filesystem access.  The extraction base is "/extract".
                _symlink_safe = False
                _symlink_reason = "unknown validation error"
                try:
                    _BASE = "/extract"
                    # Absolute symlink targets are always unsafe.
                    if target.startswith("/"):
                        _symlink_reason = f"absolute symlink target {target!r}"
                    else:
                        link_parent = posixpath.normpath(
                            posixpath.join(_BASE, posixpath.dirname(name))
                        )
                        resolved = posixpath.normpath(
                            posixpath.join(link_parent, target)
                        )
                        # Containment: resolved must equal _BASE or be strictly
                        # below it (i.e., resolved starts with _BASE + "/").
                        if resolved == _BASE or resolved.startswith(_BASE + "/"):
                            _symlink_safe = True
                        else:
                            _symlink_reason = (
                                f"symlink resolves to {resolved!r}, "
                                f"which is outside {_BASE!r}"
                            )
                except Exception as exc:  # noqa: BLE001
                    _symlink_reason = f"validation error: {exc}"

                if not _symlink_safe:
                    stats.safe = False
                    findings.append(
                        Finding(
                            rule_id="ARCHIVE_ESCAPE_SYMLINK",
                            severity="critical",
                            classification="BLOCK",
                            path=name,
                            line=0,
                            message=(
                                f"Symlink {name!r} → {_truncate(target, 80)!r} "
                                f"escapes extraction directory: {_symlink_reason}"
                            ),
                            evidence=_truncate(target, EVIDENCE_MAX_LEN),
                            scanner="zip-inspector",
                        )
                    )

            # --- Device files and special files ---
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = mode & 0xF000
            if file_type in (0x2000, 0x6000):  # char or block device
                stats.safe = False
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_DEVICE_FILE",
                        severity="critical",
                        classification="BLOCK",
                        path=name,
                        line=0,
                        message=f"Archive contains a device file: {name!r}",
                        evidence="",
                        scanner="zip-inspector",
                    )
                )
            if file_type == 0x1000:  # named pipe / FIFO
                stats.safe = False
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_NAMED_PIPE",
                        severity="high",
                        classification="BLOCK",
                        path=name,
                        line=0,
                        message=f"Archive contains a named pipe: {name!r}",
                        evidence="",
                        scanner="zip-inspector",
                    )
                )

            # --- Setuid / setgid ---
            if mode & (stat.S_ISUID | stat.S_ISGID):
                stats.safe = False
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_SETUID_FILE",
                        severity="critical",
                        classification="BLOCK",
                        path=name,
                        line=0,
                        message=f"Archive member {name!r} has setuid/setgid bit set.",
                        evidence="",
                        scanner="zip-inspector",
                    )
                )

        # --- Total uncompressed size ---
        max_total = _archive_policy("max_uncompressed_bytes")
        if stats.uncompressed_bytes > max_total:
            stats.safe = False
            stats.issues.append(
                f"Total uncompressed size {stats.uncompressed_bytes} > {max_total}"
            )
            findings.append(
                Finding(
                    rule_id="ARCHIVE_BOMB_SIZE",
                    severity="critical",
                    classification="BLOCK",
                    path="<archive>",
                    line=0,
                    message=(
                        f"Archive uncompressed size {stats.uncompressed_bytes} bytes "
                        f"exceeds limit {max_total}."
                    ),
                    evidence="",
                    scanner="zip-inspector",
                )
            )

        # --- Compression ratio ---
        if stats.compressed_bytes > 0:
            stats.compression_ratio = stats.uncompressed_bytes / stats.compressed_bytes
            max_ratio = _archive_policy("max_compression_ratio")
            if stats.compression_ratio > max_ratio:
                stats.safe = False
                findings.append(
                    Finding(
                        rule_id="ARCHIVE_BOMB_RATIO",
                        severity="critical",
                        classification="BLOCK",
                        path="<archive>",
                        line=0,
                        message=(
                            f"Compression ratio {stats.compression_ratio:.1f}x "
                            f"exceeds limit {max_ratio}x."
                        ),
                        evidence="",
                        scanner="zip-inspector",
                    )
                )

    return stats, findings


def safe_extract_zip(zip_path: str, dest_dir: str) -> list[str]:
    """Extract a ZIP to dest_dir after validating all paths.

    Returns list of extracted relative paths.
    Raises on any path-safety violation.
    """
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            safe, reason = _is_safe_member_path(name)
            if not safe:
                raise ValueError(f"Refusing to extract unsafe path {name!r}: {reason}")
            # Verify the resolved path stays inside dest_dir
            target = os.path.realpath(os.path.join(dest_dir, name))
            if not target.startswith(
                os.path.realpath(dest_dir) + os.sep
            ) and target != os.path.realpath(dest_dir):
                raise ValueError(
                    f"Extraction of {name!r} would escape destination directory."
                )
            # Skip symlinks during extraction for safety
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode & 0xF000 == 0xA000:
                continue
            zf.extract(info, path=dest_dir)
            extracted.append(name)
    return extracted


# ---------------------------------------------------------------------------
# Binary detection
# ---------------------------------------------------------------------------

# Magic bytes for binary formats
_BINARY_MAGIC: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "ELF", "elf_binary"),
    (b"MZ", "PE", "pe_binary"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat", "macho_binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE", "macho_binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE", "macho_binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit BE", "macho_binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit BE", "macho_binary"),
    (b"\x4d\x5a", "PE/DOS", "pe_binary"),  # alias for MZ
    (b"!<arch>\n", "AR/static lib", "static_archive"),
    (b"\x7f\x45\x4c\x46", "ELF", "elf_binary"),  # same as \x7fELF
]

_ELF_ARCH = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x16: "PowerPC64",
    0x02: "SPARC",
}


def identify_binary(data: bytes, path: str) -> Optional[dict[str, Any]]:
    """Identify a binary file by magic bytes and return metadata dict."""
    if len(data) < 4:
        return None
    for magic, label, kind in _BINARY_MAGIC:
        if data[: len(magic)] == magic:
            info: dict[str, Any] = {"path": path, "type": kind, "label": label}
            if kind == "elf_binary" and len(data) >= 20:
                arch_byte = data[18] if len(data) > 18 else 0
                info["architecture"] = _ELF_ARCH.get(
                    arch_byte, f"unknown(0x{arch_byte:02x})"
                )
                info["stripped"] = _is_elf_stripped(data)
            return info
    # AppImage
    if len(data) >= 11 and data[8:11] == b"AI\x02":
        return {"path": path, "type": "appimage", "label": "AppImage"}
    return None


def _is_elf_stripped(data: bytes) -> bool:
    """Heuristic: check if ELF has a symbol table section."""
    # Proper check would parse section headers; this is a quick heuristic
    return b".symtab" not in data and b".debug_info" not in data


def is_executable_script(data: bytes, mode: int) -> bool:
    """Return True if file appears to be an executable shell script."""
    if mode & 0o111:
        if data[:2] in (b"#!", b"# "):
            return True
    if data[:2] == b"#!":
        return True
    return False


# ---------------------------------------------------------------------------
# Static analysis: suspicious pattern detection
# ---------------------------------------------------------------------------

# Each rule: (rule_id, severity, classification, description, pattern)
_PYTHON_RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    (
        "EXEC_OS_SYSTEM",
        "high",
        "MANUAL_REVIEW",
        "os.system() call",
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
    ),
    (
        "EXEC_OS_POPEN",
        "high",
        "MANUAL_REVIEW",
        "os.popen() call",
        re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
    ),
    (
        "EXEC_SUBPROCESS_POPEN",
        "medium",
        "PASS_WITH_WARNINGS",
        "subprocess.Popen() call",
        re.compile(r"\bsubprocess\.Popen\s*\(", re.IGNORECASE),
    ),
    (
        "EXEC_SUBPROCESS_RUN",
        "medium",
        "PASS_WITH_WARNINGS",
        "subprocess.run() call",
        re.compile(r"\bsubprocess\.run\s*\(", re.IGNORECASE),
    ),
    (
        "EXEC_SUBPROCESS_CALL",
        "medium",
        "PASS_WITH_WARNINGS",
        "subprocess.call() call",
        re.compile(r"\bsubprocess\.call\s*\(", re.IGNORECASE),
    ),
    (
        "EXEC_SHELL_TRUE",
        "high",
        "MANUAL_REVIEW",
        "subprocess with shell=True",
        re.compile(r"\bshell\s*=\s*True\b"),
    ),
    ("EXEC_EVAL", "high", "MANUAL_REVIEW", "eval() call", re.compile(r"\beval\s*\(")),
    ("EXEC_EXEC", "high", "MANUAL_REVIEW", "exec() call", re.compile(r"\bexec\s*\(")),
    (
        "PRIVILEGE_SUDO",
        "high",
        "MANUAL_REVIEW",
        "sudo invocation",
        re.compile(r"[\"'\s]sudo[\s\"']"),
    ),
    (
        "PRIVILEGE_PKEXEC",
        "high",
        "MANUAL_REVIEW",
        "pkexec invocation",
        re.compile(r"[\"'\s]pkexec[\s\"']"),
    ),
    (
        "PRIVILEGE_CHMOD_777",
        "high",
        "MANUAL_REVIEW",
        "chmod 777",
        re.compile(r"\bchmod\s+777\b"),
    ),
    (
        "PRIVILEGE_CHMOD_SUID",
        "critical",
        "BLOCK",
        "chmod +s (setuid/setgid)",
        re.compile(r"\bchmod\s+\+s\b"),
    ),
    (
        "PRIVILEGE_CHOWN_ROOT",
        "high",
        "MANUAL_REVIEW",
        "chown root",
        re.compile(r"\bchown\s+root\b"),
    ),
    (
        "PRIVILEGE_SYSTEMCTL",
        "medium",
        "MANUAL_REVIEW",
        "systemctl usage",
        re.compile(r"\bsystemctl\b"),
    ),
    (
        "PRIVILEGE_MOUNT",
        "high",
        "MANUAL_REVIEW",
        "mount/umount usage",
        re.compile(r"\b(u?mount)\b"),
    ),
    (
        "PRIVILEGE_MODPROBE",
        "critical",
        "MANUAL_REVIEW",
        "kernel module loading",
        re.compile(r"\b(modprobe|insmod|rmmod)\b"),
    ),
    (
        "PRIVILEGE_IPTABLES",
        "high",
        "MANUAL_REVIEW",
        "iptables/nft usage",
        re.compile(r"\b(iptables|ip6tables|nft)\b"),
    ),
    (
        "PRIVILEGE_STEAMOS_READONLY",
        "high",
        "MANUAL_REVIEW",
        "steamos-readonly",
        re.compile(r"\bsteamos-readonly\b"),
    ),
    (
        "PERSIST_SYSTEMD_SERVICE",
        "high",
        "MANUAL_REVIEW",
        "systemd service creation",
        re.compile(r"\.(service|socket|timer)\s*\[Unit\]", re.DOTALL),
    ),
    (
        "PERSIST_CRON",
        "high",
        "MANUAL_REVIEW",
        "cron job installation",
        re.compile(r"\b(crontab|/etc/cron)"),
    ),
    (
        "PERSIST_LD_PRELOAD",
        "critical",
        "MANUAL_REVIEW",
        "LD_PRELOAD modification",
        re.compile(r"\bLD_PRELOAD\b"),
    ),
    (
        "PERSIST_PROFILE_MOD",
        "medium",
        "MANUAL_REVIEW",
        "shell profile modification",
        re.compile(r"(\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/profile)"),
    ),
    (
        "SENSITIVE_SSH_KEY",
        "high",
        "MANUAL_REVIEW",
        "SSH private key access",
        re.compile(r"(\.ssh/id_|id_rsa|id_ed25519|id_ecdsa)(?!\.pub)"),
    ),
    (
        "SENSITIVE_STEAM_AUTH",
        "high",
        "MANUAL_REVIEW",
        "Steam authentication data access",
        re.compile(
            r"(loginusers\.vdf|config\.vdf|ssfn[0-9]|steamguard|SteamDesktopAuthenticator)",
            re.IGNORECASE,
        ),
    ),
    (
        "SENSITIVE_SHADOW",
        "critical",
        "BLOCK",
        "/etc/shadow access",
        re.compile(r"/etc/shadow\b"),
    ),
    (
        "SENSITIVE_ENV_HARVEST",
        "medium",
        "MANUAL_REVIEW",
        "environment variable harvesting",
        re.compile(
            r"\bos\.environ\b.*(?:password|token|secret|key|api)", re.IGNORECASE
        ),
    ),
    (
        "NETWORK_DISABLED_TLS",
        "high",
        "MANUAL_REVIEW",
        "TLS verification disabled",
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context",
            re.IGNORECASE,
        ),
    ),
    (
        "NETWORK_HARDCODED_AUTH",
        "high",
        "MANUAL_REVIEW",
        "hard-coded Authorization header",
        re.compile(
            r"Authorization['\"]?\s*:\s*['\"]?\s*(Bearer|Basic)\s+[A-Za-z0-9+/=]{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "OBFUSCATION_PICKLE",
        "high",
        "MANUAL_REVIEW",
        "pickle.loads on external data",
        re.compile(r"\bpickle\.loads\s*\("),
    ),
    (
        "OBFUSCATION_MARSHAL",
        "high",
        "MANUAL_REVIEW",
        "marshal loading",
        re.compile(r"\bmarshal\.loads?\s*\("),
    ),
    (
        "DESTRUCTIVE_RM_RF",
        "critical",
        "BLOCK",
        "rm -rf with system paths",
        re.compile(r"\brm\s+-[rf]+\s+(/[a-z]|~|/home|/etc|/usr|/bin|/sbin|/lib)"),
    ),
]

_JS_RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    (
        "EXEC_CHILD_EXEC",
        "high",
        "MANUAL_REVIEW",
        "child_process.exec()",
        re.compile(r"\bchild_process\.exec(?:Sync)?\s*\("),
    ),
    (
        "EXEC_CHILD_SPAWN",
        "medium",
        "PASS_WITH_WARNINGS",
        "child_process.spawn()",
        re.compile(r"\bchild_process\.spawn\s*\("),
    ),
    (
        "EXEC_EVAL_JS",
        "high",
        "MANUAL_REVIEW",
        "eval() in JavaScript",
        re.compile(r"\beval\s*\("),
    ),
    (
        "EXEC_FUNCTION_CTOR",
        "high",
        "MANUAL_REVIEW",
        "Function() constructor (dynamic code)",
        re.compile(r"\bnew\s+Function\s*\("),
    ),
    (
        "PRIVILEGE_SUDO_JS",
        "high",
        "MANUAL_REVIEW",
        "sudo invocation in JS",
        re.compile(r"[\"'`]sudo[\s\"'`]"),
    ),
    (
        "NETWORK_DISABLED_TLS_JS",
        "high",
        "MANUAL_REVIEW",
        "TLS verification disabled in JS",
        re.compile(r"rejectUnauthorized\s*:\s*false"),
    ),
    (
        "OBFUSCATION_STRING_CONCAT",
        "medium",
        "PASS_WITH_WARNINGS",
        "suspicious string-construction to hide commands",
        re.compile(r'(?:["\'][a-z]{1,3}["\']\s*\+\s*){5,}'),
    ),
]

_SHELL_RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    (
        "SHELL_CURL_PIPE",
        "critical",
        "BLOCK",
        "curl/wget piped to shell (drive-by execution)",
        re.compile(r"(curl|wget)\s+[^\n]+\|\s*(ba)?sh\b"),
    ),
    (
        "SHELL_BASE64_EXEC",
        "critical",
        "BLOCK",
        "base64-decoded payload execution",
        re.compile(r"base64\s+--?decode[^\n]*\|\s*(ba)?sh\b"),
    ),
    (
        "PRIVILEGE_SUDO_SHELL",
        "high",
        "MANUAL_REVIEW",
        "sudo in shell script",
        re.compile(r"\bsudo\b"),
    ),
    (
        "PRIVILEGE_CHMOD_777_SHELL",
        "high",
        "MANUAL_REVIEW",
        "chmod 777 in shell script",
        re.compile(r"\bchmod\s+777\b"),
    ),
    (
        "PRIVILEGE_SYSTEMCTL_SHELL",
        "medium",
        "MANUAL_REVIEW",
        "systemctl in shell script",
        re.compile(r"\bsystemctl\b"),
    ),
    (
        "DESTRUCTIVE_RM_RF_SHELL",
        "critical",
        "BLOCK",
        "rm -rf with system paths in shell",
        re.compile(r"\brm\s+-[rf]+\s+(/[a-z]|~|/home|/etc|/usr|/bin|/sbin|/lib)"),
    ),
    (
        "PERSIST_UDEV_SHELL",
        "high",
        "MANUAL_REVIEW",
        "udev rule installation",
        re.compile(r"/etc/udev/rules\.d"),
    ),
    (
        "PERSIST_KERNEL_MODULE_SHELL",
        "critical",
        "MANUAL_REVIEW",
        "kernel module installation",
        re.compile(r"\b(modprobe|insmod)\b"),
    ),
]

_URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>\[\]{}|\\^`]+",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_OBFUSCATION_BASE64 = re.compile(
    r"(?:[A-Za-z0-9+/]{60,}={0,2})",
)
_DOWNLOAD_CHMOD_EXEC = re.compile(
    r"(curl|wget)\s+[^\n]+\n[^\n]*(chmod\s+[+0-7]*x|chmod\s+777)[^\n]*\n[^\n]*(exec|subprocess|popen|\./)",
    re.DOTALL,
)


def _truncate(text: str, max_len: int) -> str:
    text = str(text)
    if len(text) > max_len:
        return text[:max_len] + "…"
    return text


def _get_rules_for_extension(ext: str) -> list[tuple[str, str, str, str, re.Pattern]]:
    ext = ext.lower()
    if ext in (".py",):
        return _PYTHON_RULES
    if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
        return _JS_RULES + _PYTHON_RULES  # JS subset overlaps
    if ext in (".sh", ".bash", ".zsh", ".fish", ""):
        return _SHELL_RULES + _PYTHON_RULES
    return _PYTHON_RULES + _JS_RULES + _SHELL_RULES  # unknown: run all


def scan_text_content(
    content: str,
    path: str,
    ext: str,
) -> list[Finding]:
    """Run static analysis rules against text content of a file."""
    findings: list[Finding] = []
    rules = _get_rules_for_extension(ext)
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for rule_id, severity, classification, message, pattern in rules:
            m = pattern.search(line)
            if m:
                evidence = redact_secrets(_truncate(line.strip(), EVIDENCE_MAX_LEN))
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        classification=classification,
                        path=path,
                        line=lineno,
                        message=message,
                        evidence=evidence,
                        scanner="decky-static-rules",
                    )
                )

    # Check for large base64 obfuscation in full content
    for m in _OBFUSCATION_BASE64.finditer(content):
        val = m.group(0)
        if len(val) >= 200:
            lineno = content[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    rule_id="OBFUSCATION_LARGE_BASE64",
                    severity="medium",
                    classification="MANUAL_REVIEW",
                    path=path,
                    line=lineno,
                    message="Large base64-encoded string may conceal an obfuscated payload.",
                    evidence=_truncate(val[:80] + "...", EVIDENCE_MAX_LEN),
                    scanner="decky-static-rules",
                )
            )

    return findings


_ENV_ACCESS_PATTERN = re.compile(
    r"\bos\.environ(?:\.get\s*\(\s*|\s*\[\s*)['\"]([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_PROTECTED_ENV_PREFIXES = (
    "AWS_",
    "CF_",
    "CLOUDFLARE_",
    "GITHUB_",
    "SSH_",
    "STEAM_",
)
_GENERIC_PLUGIN_NAME_STEMS = {"decky", "loader", "plugin", "sdh"}


def _normalised_name_stems(plugin_name: str) -> set[str]:
    normalised = (
        unicodedata.normalize("NFKD", plugin_name)
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    parts = [part.lower() for part in re.findall(r"[A-Za-z0-9]+", normalised)]
    stems = {
        part
        for part in parts
        if len(part) >= 4 and part not in _GENERIC_PLUGIN_NAME_STEMS
    }
    combined = "".join(parts)
    if len(combined) >= 4 and combined not in _GENERIC_PLUGIN_NAME_STEMS:
        stems.add(combined)
    return stems


def _is_plugin_namespaced_env(env_name: str, plugin_name: str) -> bool:
    upper_name = env_name.upper()
    if upper_name.startswith(_PROTECTED_ENV_PREFIXES) or upper_name.endswith(
        "PRIVATE_KEY"
    ):
        return False

    env_parts = [part.lower() for part in upper_name.split("_") if part]
    env_compact = "".join(env_parts)
    return any(
        stem in env_parts or env_compact.startswith(stem)
        for stem in _normalised_name_stems(plugin_name)
    )


def _downgrade_plugin_namespaced_env_findings(
    findings: list[Finding], plugin_name: str
) -> None:
    """Downgrade only env reads clearly namespaced to this plugin."""
    if not plugin_name:
        return
    for finding in findings:
        if (
            finding.rule_id != "SENSITIVE_ENV_HARVEST"
            or finding.classification != "MANUAL_REVIEW"
        ):
            continue
        env_names = _ENV_ACCESS_PATTERN.findall(finding.evidence)
        if env_names and all(
            _is_plugin_namespaced_env(env_name, plugin_name) for env_name in env_names
        ):
            finding.classification = "PASS_WITH_WARNINGS"
            finding.message = "Plugin-namespaced environment variable read."


def extract_urls_and_domains(content: str) -> tuple[list[str], list[str]]:
    """Extract HTTP/HTTPS URLs and unique domain names from text content."""
    urls: list[str] = []
    domains: set[str] = set()
    for m in _URL_PATTERN.finditer(content):
        url = m.group(0).rstrip(".,;)'\"")
        urls.append(url)
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        except Exception:
            pass
    # Also extract raw IPs
    for m in _IP_PATTERN.finditer(content):
        domains.add(m.group(0))
    return urls, list(domains)


# ---------------------------------------------------------------------------
# Secrets scanning
# ---------------------------------------------------------------------------


_FIXTURE_PATH_SEGMENTS = {
    "test",
    "tests",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "mock",
    "mocks",
}


def _looks_like_test_fixture(path: str) -> bool:
    """Return whether ``path`` is explicitly scoped as test/example material."""
    normalized = path.replace("\\", "/")
    parts = tuple(part.lower() for part in PurePosixPath(normalized).parts)
    filename = parts[-1] if parts else ""
    return any(part in _FIXTURE_PATH_SEGMENTS for part in parts) or (
        ".example." in filename
    )


_PLACEHOLDER_SECRET_PATTERNS = {
    "generic_api_key",
    "bearer_token",
    "cloudflare_token",
}


def _looks_like_secret_placeholder(value: str) -> bool:
    """Match only complete, explicitly enumerated placeholder values."""
    if not value or value != value.strip():
        return False
    low = value.lower()
    if low in {"changeme", "placeholder"}:
        return True
    if re.fullmatch(r"your_[a-z0-9_]+", low):
        return True
    if any(
        re.fullmatch(pattern, value)
        for pattern in (
            r"<[^<>]+>",
            r"\[[^\[\]]+\]",
            r"\$\{[^{}]+\}",
            r"\{\{[^{}]+\}\}",
        )
    ):
        return True

    provider_shapes = (
        ("ghp_", 36),
        ("ghs_", 36),
        ("github_pat_", 82),
        ("AKIA", 16),
    )
    for prefix, suffix_length in provider_shapes:
        if value.startswith(prefix):
            suffix = value[len(prefix) :]
            return len(suffix) == suffix_length and len(set(suffix)) == 1
    return False


def _secret_value_shape(value: str) -> tuple[int, bool, bool]:
    """Return non-identifying facts that let reviewers assess a redacted value."""
    contains_whitespace = any(character.isspace() for character in value)
    non_whitespace = [character for character in value if not character.isspace()]
    entirely_alphabetic = bool(non_whitespace) and all(
        character.isalpha() for character in non_whitespace
    )
    return len(value), contains_whitespace, entirely_alphabetic


def _matched_secret_value(name: str, match: re.Match) -> str:
    """Select the redacted value solely for computing non-identifying shape facts."""
    if "value" in match.re.groupindex:
        return match.group("value")
    if name == "password_literal":
        return match.group(1)
    return match.group(0)


def scan_for_secrets(content: str, path: str) -> list[Finding]:
    """Scan text content for secret-like patterns.  Values are redacted."""
    findings: list[Finding] = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, pattern in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                is_fixture = _looks_like_test_fixture(path)
                matched_value = _matched_secret_value(name, m)
                is_placeholder = _looks_like_secret_placeholder(matched_value)
                is_warning = is_fixture and is_placeholder
                value_length, contains_whitespace, entirely_alphabetic = (
                    _secret_value_shape(matched_value)
                )
                # Never print the actual secret value
                evidence = (
                    f"[{name} pattern matched at position {m.start()}; "
                    f"value_length={value_length}; "
                    f"contains_whitespace={'yes' if contains_whitespace else 'no'}; "
                    f"entirely_alphabetic={'yes' if entirely_alphabetic else 'no'}] "
                    f"{SECRET_REDACT}"
                )
                findings.append(
                    Finding(
                        rule_id="SECRET_" + name.upper(),
                        severity="low" if is_warning else "critical",
                        classification=(
                            "PASS_WITH_WARNINGS" if is_warning else "BLOCK"
                        ),
                        path=path,
                        line=lineno,
                        message=(
                            f"Potential {name} detected (redacted)."
                            f"{' Recognized fixture placeholder.' if is_warning else ''}"
                        ),
                        evidence=evidence,
                        scanner="secrets-scanner",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Metadata checking
# ---------------------------------------------------------------------------


def check_plugin_json(
    data: Optional[bytes], path: str = "plugin.json"
) -> tuple[dict[str, Any], list[Finding]]:
    """Validate plugin.json content.  Returns (parsed_dict, findings)."""
    findings: list[Finding] = []
    parsed: dict[str, Any] = {}

    if data is None:
        findings.append(
            Finding(
                rule_id="MISSING_PLUGIN_JSON",
                severity="medium",
                classification="PASS_WITH_WARNINGS",
                path=path,
                line=0,
                message="plugin.json is absent; falling back to package.json for plugin name.",
                evidence="",
                scanner="metadata-checker",
            )
        )
        return parsed, findings

    try:
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        findings.append(
            Finding(
                rule_id="INVALID_PLUGIN_JSON",
                severity="high",
                classification="MANUAL_REVIEW",
                path=path,
                line=0,
                message=f"plugin.json is not valid JSON: {exc}",
                evidence="",
                scanner="metadata-checker",
            )
        )
        return parsed, findings

    if not parsed.get("name"):
        findings.append(
            Finding(
                rule_id="MISSING_PLUGIN_NAME",
                severity="high",
                classification="MANUAL_REVIEW",
                path=path,
                line=0,
                message="plugin.json is missing the 'name' field.",
                evidence="",
                scanner="metadata-checker",
            )
        )

    flags = parsed.get("flags") or []
    if isinstance(flags, list) and any(f.lower() in ("root", "_root") for f in flags):
        findings.append(
            Finding(
                rule_id="ROOT_ACCESS",
                severity="high",
                classification="MANUAL_REVIEW",
                path=path,
                line=0,
                message="Plugin declares 'root' flag in plugin.json. Requires manual review.",
                evidence=_truncate(str(flags), EVIDENCE_MAX_LEN),
                scanner="metadata-checker",
            )
        )

    return parsed, findings


def check_package_json(
    data: Optional[bytes], path: str = "package.json"
) -> tuple[dict[str, Any], list[Finding]]:
    """Validate package.json content.  Returns (parsed_dict, findings)."""
    findings: list[Finding] = []
    parsed: dict[str, Any] = {}

    if data is None:
        return parsed, findings

    try:
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        findings.append(
            Finding(
                rule_id="INVALID_PACKAGE_JSON",
                severity="medium",
                classification="PASS_WITH_WARNINGS",
                path=path,
                line=0,
                message=f"package.json is not valid JSON: {exc}",
                evidence="",
                scanner="metadata-checker",
            )
        )

    # Check for suspicious lifecycle scripts
    scripts = parsed.get("scripts") or {}
    dangerous_hooks = [
        "preinstall",
        "install",
        "postinstall",
        "preuninstall",
        "uninstall",
    ]
    for hook in dangerous_hooks:
        if hook in scripts:
            findings.append(
                Finding(
                    rule_id="PACKAGE_LIFECYCLE_SCRIPT",
                    severity="medium",
                    classification="MANUAL_REVIEW",
                    path=path,
                    line=0,
                    message=f"package.json defines a '{hook}' lifecycle script.",
                    evidence=_truncate(str(scripts[hook]), EVIDENCE_MAX_LEN),
                    scanner="metadata-checker",
                )
            )

    return parsed, findings


# ---------------------------------------------------------------------------
# External scanners (graceful fallback)
# ---------------------------------------------------------------------------


def _run_scanner(
    args: list[str],
    name: str,
    timeout: int = 120,
) -> tuple[bool, str, str]:
    """Run an external scanner. Returns (success, stdout, stderr)."""
    if not shutil.which(args[0]):
        return False, "", f"{args[0]} not found in PATH"
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"{name} timed out after {timeout}s"
    except Exception as exc:
        return False, "", f"{name} error: {exc}"


def _severity_rank(sev: str) -> int:
    """Map a severity string to a numeric rank for comparison."""
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev.lower(), 0)


def run_trivy(
    extract_dir: str,
    policy: dict[str, Any],
    *,
    source_repo: Optional[tuple[str, str, str]] = None,
    source_root: Optional[str] = None,
) -> tuple[ScannerStatus, list[Finding]]:
    """Scan the release artifact and exact-tag source tree with Trivy."""
    if not _scanner_enabled(policy, "trivy"):
        return ScannerStatus(name="trivy", status="skipped"), []

    if not shutil.which("trivy"):
        return (
            ScannerStatus(
                name="trivy",
                status="unavailable",
                detail="trivy not found in PATH",
            ),
            [],
        )

    vuln_cfg = policy.get("vulnerabilities", {})
    block_sev = vuln_cfg.get("block_severity", "critical")
    review_sev = vuln_cfg.get("review_severity", "high")
    block_rank = _severity_rank(block_sev)
    review_rank = _severity_rank(review_sev)

    scan_targets = [("artifact", extract_dir)]
    source_temp: Optional[tempfile.TemporaryDirectory[str]] = None
    errors: list[str] = []
    scope_counts: dict[str, int] = {}
    findings: list[Finding] = []

    try:
        if source_root is not None and source_repo is not None:
            raise ValueError(
                "source_repo is transitional only; use source_root instead"
            )

        if source_root is not None:
            if os.path.isdir(source_root):
                scan_targets.append(("source", source_root))
            else:
                errors.append(
                    f"source scan failed: source_root unavailable: {source_root!r}"
                )
        elif source_repo is not None:
            owner, repo, commit_sha = source_repo
            source_temp = tempfile.TemporaryDirectory(prefix="decky-source-")
            try:
                source_root = _fetch_source_tree(
                    owner, repo, commit_sha, source_temp.name, policy=policy
                )
                scan_targets.append(("source", source_root))
            except Exception as exc:
                errors.append(f"source fetch failed: {exc}")

        for scope, scan_dir in scan_targets:
            # Trivy exits 0 on a completed scan because no --exit-code override is
            # used. Parse any JSON it emits even if the process reports non-zero so
            # useful findings survive alongside an infrastructure error.
            ok, stdout, stderr = _run_scanner(
                ["trivy", "fs", "--format", "json", "--quiet", scan_dir],
                "trivy",
            )
            if not stdout.strip():
                detail = stderr[:500] if stderr else "no output"
                errors.append(f"{scope} scan failed: {detail}")
                continue

            try:
                data = json.loads(stdout)
            except (json.JSONDecodeError, ValueError) as exc:
                errors.append(f"{scope} scan JSON parse error: {exc}")
                continue

            if not ok:
                detail = stderr[:500] if stderr else "scanner exited non-zero"
                errors.append(f"{scope} scan failed: {detail}")

            before = len(findings)
            for result in data.get("Results") or []:
                target = str(result.get("Target") or "dependency manifest")
                for vuln in result.get("Vulnerabilities") or []:
                    vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                    pkg_name = vuln.get("PkgName", "unknown")
                    installed = vuln.get("InstalledVersion", "")
                    fixed = vuln.get("FixedVersion", "")
                    raw_sev = (vuln.get("Severity") or "UNKNOWN").lower()
                    sev = raw_sev if raw_sev in SEVERITY_SCORE else "low"
                    refs = vuln.get("References") or []
                    advisory_url = refs[0] if refs else ""
                    title = _truncate(
                        vuln.get("Title") or vuln.get("Description") or vuln_id,
                        120,
                    )
                    rank = _severity_rank(sev)
                    if rank >= block_rank:
                        classification = "BLOCK"
                    elif rank >= review_rank:
                        classification = "MANUAL_REVIEW"
                    else:
                        classification = "PASS_WITH_WARNINGS"

                    fixed_str = f" (fix: {fixed})" if fixed else ""
                    findings.append(
                        Finding(
                            rule_id=f"TRIVY_{vuln_id.replace('-', '_').upper()}",
                            severity=sev,
                            classification=classification,
                            path=f"{scope}:{target}",
                            line=0,
                            message=(
                                f"[{scope}] {vuln_id} in {pkg_name}@{installed}"
                                f"{fixed_str}: {title}"
                                + (f" — {advisory_url}" if advisory_url else "")
                            ),
                            evidence=_truncate(
                                f"{vuln_id} {pkg_name}@{installed}" + fixed_str,
                                EVIDENCE_MAX_LEN,
                            ),
                            scanner="trivy",
                        )
                    )
            scope_counts[scope] = len(findings) - before
    finally:
        if source_temp is not None:
            source_temp.cleanup()

    detail_parts = [
        f"{scope} scanned ({count} findings)" for scope, count in scope_counts.items()
    ]
    detail_parts.extend(errors)
    detail = "; ".join(detail_parts) or None
    if errors:
        return ScannerStatus(name="trivy", status="failed", detail=detail), findings
    status = "found_issue" if findings else "passed"
    return ScannerStatus(name="trivy", status=status, detail=detail), findings


def run_clamav(
    extract_dir: str, policy: dict[str, Any]
) -> tuple[ScannerStatus, list[Finding]]:
    """Run ClamAV scan. Returns (ScannerStatus, findings)."""
    if not _scanner_enabled(policy, "clamav"):
        return ScannerStatus(name="clamav", status="skipped"), []

    if not shutil.which("clamscan"):
        return (
            ScannerStatus(
                name="clamav",
                status="unavailable",
                detail="clamscan not found in PATH",
            ),
            [],
        )

    ok, stdout, stderr = _run_scanner(
        ["clamscan", "-r", "--no-summary", extract_dir],
        "clamav",
    )

    findings: list[Finding] = []
    # Parse clamscan output: "path: Signature FOUND"
    malware_pattern = re.compile(r"^(.+):\s+(.+)\s+FOUND$", re.MULTILINE)
    for m in malware_pattern.finditer(stdout):
        infected_path = os.path.basename(m.group(1))  # redact full path
        signature = m.group(2)
        findings.append(
            Finding(
                rule_id="MALWARE",
                severity="critical",
                classification="BLOCK",
                path=f"<redacted>/{infected_path}",
                line=0,
                message=f"ClamAV signature detected: {signature}",
                evidence=_truncate(signature, EVIDENCE_MAX_LEN),
                scanner="clamav",
            )
        )

    if findings:
        return ScannerStatus(name="clamav", status="found_issue"), findings

    # clamscan exits 0 for clean, 1 for found, 2 for error.
    # _run_scanner also returns ok=False on timeout or exception.
    if not ok:
        detail = (stderr or stdout)[:500]
        return (
            ScannerStatus(
                name="clamav",
                status="failed",
                detail=detail or "clamscan exited non-zero",
            ),
            [],
        )

    return ScannerStatus(name="clamav", status="passed"), []


def run_semgrep(
    extract_dir: str, policy: dict[str, Any]
) -> tuple[ScannerStatus, list[Finding]]:
    """Run Semgrep static analysis. Returns (ScannerStatus, findings)."""
    if not _scanner_enabled(policy, "semgrep"):
        return ScannerStatus(name="semgrep", status="skipped"), []

    if not shutil.which("semgrep"):
        return (
            ScannerStatus(
                name="semgrep",
                status="unavailable",
                detail="semgrep not found in PATH",
            ),
            [],
        )

    ok, stdout, stderr = _run_scanner(
        [
            "semgrep",
            "--config",
            SEMGREP_RULES_FILE,
            "--json",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            extract_dir,
        ],
        "semgrep",
        timeout=180,
    )

    findings: list[Finding] = []
    if not stdout.strip():
        # No output at all - treat as failure regardless of exit code
        return ScannerStatus(
            name="semgrep", status="failed", detail="no JSON output"
        ), []
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        return ScannerStatus(
            name="semgrep", status="failed", detail=f"JSON parse error: {exc}"
        ), []
    # Unknown severities are treated conservatively as high/MANUAL_REVIEW.
    semgrep_severity_map: dict[str, tuple[str, str]] = {
        "error": ("high", "MANUAL_REVIEW"),
        "warning": ("medium", "MANUAL_REVIEW"),
        "info": ("info", "PASS_WITH_WARNINGS"),
    }
    try:
        for result in data.get("results") or []:
            raw_severity = (
                str(result.get("extra", {}).get("severity", "INFO")).strip().lower()
            )
            norm_severity, classification = semgrep_severity_map.get(
                raw_severity,
                ("high", "MANUAL_REVIEW"),
            )
            findings.append(
                Finding(
                    rule_id="SEMGREP_"
                    + result.get("check_id", "unknown").upper().replace(".", "_")[:60],
                    severity=norm_severity,
                    classification=classification,
                    path=os.path.relpath(result.get("path", ""), extract_dir),
                    line=result.get("start", {}).get("line", 0),
                    message=result.get("extra", {}).get("message", "Semgrep finding"),
                    evidence=_truncate(
                        result.get("extra", {}).get("lines", ""), EVIDENCE_MAX_LEN
                    ),
                    scanner="semgrep",
                )
            )
    except Exception as exc:
        return ScannerStatus(name="semgrep", status="failed", detail=str(exc)), []

    if not ok:
        return (
            ScannerStatus(
                name="semgrep",
                status="failed",
                detail=(stderr or "semgrep exited non-zero")[:500],
            ),
            findings,
        )

    status = "found_issue" if findings else "passed"
    return ScannerStatus(name="semgrep", status=status), findings


# ---------------------------------------------------------------------------
# Source/artifact comparison
# ---------------------------------------------------------------------------

_SCRIPT_EXTENSIONS = {
    ".py",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".pl",
    ".rb",
    ".lua",
    ".ps1",
}

_NON_SCRIPT_GENERATED_EXTENSIONS = {
    ".map",
    ".json",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".avif",
}

_KNOWN_SCRIPT_SHEBANGS = (
    "#!/bin/sh",
    "#!/bin/bash",
    "#!/usr/bin/env python",
    "#!/usr/bin/env node",
)


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _looks_like_script_asset(path: str, data: bytes, executable_bits: bool) -> bool:
    low = path.lower()
    ext = os.path.splitext(low)[1]
    if ext in _NON_SCRIPT_GENERATED_EXTENSIONS:
        return False

    first_line = (
        data.splitlines()[0].decode("utf-8", errors="replace").strip() if data else ""
    )
    has_known_shebang = any(first_line.startswith(s) for s in _KNOWN_SCRIPT_SHEBANGS)
    is_script_ext = ext in _SCRIPT_EXTENSIONS
    # Avoid flagging common generated minified bundles as scripts solely by extension.
    if is_script_ext and (
        low.endswith(".min.js")
        or ".bundle." in low
        or ".chunk." in low
        or "dist/" in low
        or "/dist/" in f"/{low}"
    ):
        is_script_ext = False

    if has_known_shebang:
        return True
    if is_script_ext:
        return True
    if executable_bits and _is_probably_text(data):
        return True
    return False


def _snapshot_source_inventory_lookup(
    snapshot_inventory: tuple[audit_source_snapshot.SourceInventoryEntry, ...],
) -> tuple[
    dict[str, str],
    dict[str, str],
    dict[str, str],
    dict[str, audit_source_snapshot.SourceInventoryEntry],
]:
    exact: dict[str, str] = {}
    lower: dict[str, str] = {}
    path_for_lower: dict[str, str] = {}
    entry_by_path: dict[str, audit_source_snapshot.SourceInventoryEntry] = {}

    for entry in snapshot_inventory:
        exact[entry.path] = entry.git_blob_sha1
        lower_key = entry.path.lower()
        lower[lower_key] = entry.git_blob_sha1
        path_for_lower[lower_key] = entry.path
        entry_by_path[entry.path] = entry

    return exact, lower, path_for_lower, entry_by_path


def _snapshot_source_symlink_payload(
    source_entry: audit_source_snapshot.SourceInventoryEntry,
) -> bytes:
    if source_entry.kind != "symlink":
        raise ValueError(f"expected symlink snapshot entry: {source_entry.path!r}")
    target = source_entry.symlink_target
    if target is None:
        raise ValueError(f"source symlink entry missing target: {source_entry.path!r}")
    return target.encode("utf-8", errors="surrogateescape")


def _validate_snapshot_metadata_path(snapshot_path: str) -> str:
    """Validate snapshot metadata path is canonical POSIX relative form."""
    if not isinstance(snapshot_path, str) or not snapshot_path:
        raise ValueError(f"invalid snapshot metadata path: {snapshot_path!r}")
    if "\\" in snapshot_path:
        raise ValueError(f"invalid snapshot metadata path: {snapshot_path!r}")

    normalized = posixpath.normpath(snapshot_path)
    if (
        normalized == "."
        or normalized != snapshot_path
        or normalized.startswith("/")
        or normalized.startswith("../")
        or "/../" in f"/{normalized}/"
    ):
        raise ValueError(f"invalid snapshot metadata path: {snapshot_path!r}")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"invalid snapshot metadata path: {snapshot_path!r}")

    return normalized


def _assert_snapshot_metadata_payload(
    source_entry: audit_source_snapshot.SourceInventoryEntry,
    payload: bytes,
) -> bytes:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ValueError(
            f"invalid snapshot metadata payload type: {source_entry.path!r}"
        )
    canonical = bytes(payload)
    if len(canonical) != source_entry.size_bytes:
        raise ValueError(f"metadata snapshot size mismatch: {source_entry.path!r}")
    if git_blob_sha1(canonical) != source_entry.git_blob_sha1:
        raise ValueError(f"metadata snapshot hash mismatch: {source_entry.path!r}")
    return canonical


def _read_snapshot_metadata_file(
    source_entry: audit_source_snapshot.SourceInventoryEntry,
    source_root: str,
) -> bytes:
    if source_entry.kind != "file":
        raise ValueError(f"metadata entry is not a regular file: {source_entry.path!r}")
    source_entry_path = _validate_snapshot_metadata_path(source_entry.path)

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError(
            f"metadata snapshot no-follow metadata reads unsupported: {source_entry.path!r}"
        )

    path_parts = source_entry_path.split("/")
    open_fds: list[int] = []
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        file_flags |= os.O_NONBLOCK

    try:
        current_fd = os.open(source_root, root_flags)
        open_fds.append(current_fd)

        for part in path_parts[:-1]:
            current_fd = os.open(part, dir_flags, dir_fd=current_fd)
            open_fds.append(current_fd)

        source_fd = os.open(path_parts[-1], file_flags, dir_fd=current_fd)
        open_fds.append(source_fd)
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError(
                f"metadata snapshot path is non-regular file: {source_entry.path!r}"
            )

        with os.fdopen(source_fd, "rb", closefd=False) as source_file:
            cap = audit_source_snapshot._SOURCE_METADATA_BYTE_LIMIT
            payload = source_file.read(cap)
            extra = source_file.read(1)
            if extra:
                raise ValueError(
                    f"metadata file too large for bounded read: {source_entry.path!r}"
                )

        return _assert_snapshot_metadata_payload(source_entry, payload)
    except FileNotFoundError as exc:
        raise ValueError(
            f"metadata snapshot file is missing: {source_entry.path!r}"
        ) from exc
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(
            f"Could not read source snapshot metadata: {source_entry.path!r}: {exc}"
        ) from exc
    finally:
        for fd in reversed(open_fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _metadata_diff_is_build_stamped(
    path: str,
    source_raw: bytes,
    artifact_raw: bytes,
    normalized_release_version: str,
) -> bool:
    """Return whether metadata drift is limited to Decky's exact build stamps."""
    filename = posixpath.basename(path).lower()
    if filename not in {"plugin.json", "package.json"}:
        return False
    try:
        source = json.loads(source_raw)
        artifact = json.loads(artifact_raw)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return False
    if not isinstance(source, dict) or not isinstance(artifact, dict):
        return False
    if not normalized_release_version:
        return False

    source_version = source.get("version")
    artifact_version = artifact.get("version")
    if (
        source_version != artifact_version
        and isinstance(source_version, str)
        and isinstance(artifact_version, str)
        and artifact_version == normalized_release_version
    ):
        source["version"] = artifact_version

    if filename == "package.json":
        return source == artifact

    source_flags = source.get("flags")
    artifact_flags = artifact.get("flags")
    if source_flags != artifact_flags:
        if (
            isinstance(source_flags, list)
            and isinstance(artifact_flags, list)
            and source_flags.count("debug") == 1
            and [flag for flag in source_flags if flag != "debug"] == artifact_flags
        ):
            source["flags"] = artifact_flags

    source_publish = source.get("publish")
    artifact_publish = artifact.get("publish")
    if isinstance(source_publish, dict) and isinstance(artifact_publish, dict):
        source_image = source_publish.get("image")
        artifact_image = artifact_publish.get("image")
        if (
            source_image != artifact_image
            and isinstance(source_image, str)
            and isinstance(artifact_image, str)
            and source_image.count("/main/") == 1
        ):
            release_tag = f"v{normalized_release_version}"
            if source_image.replace("/main/", f"/{release_tag}/", 1) == artifact_image:
                source_publish["image"] = artifact_image

    return source == artifact


def _resolve_ref_to_commit_and_tree_sha(
    owner: str, repo: str, ref: str
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Resolve tag/ref/commit to (commit_sha, tree_sha, error_detail)."""
    commit_sha = None
    try:
        ref_data = _gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{ref}"
        )
        if not isinstance(ref_data, dict):
            return None, None, f"Invalid ref response for tag {ref!r}"
        obj = ref_data.get("object") or {}
        obj_type = obj.get("type")
        obj_sha = obj.get("sha")
        if not obj_type or not obj_sha:
            return None, None, f"Malformed tag object for {ref!r}"

        if obj_type == "tag":
            tag_obj = _gh_get(
                f"https://api.github.com/repos/{owner}/{repo}/git/tags/{obj_sha}"
            )
            if not isinstance(tag_obj, dict):
                return None, None, f"Invalid annotated-tag response for {ref!r}"
            inner = tag_obj.get("object") or {}
            if inner.get("type") != "commit" or not inner.get("sha"):
                return None, None, f"Annotated tag {ref!r} does not point to a commit"
            commit_sha = inner["sha"]
        elif obj_type == "commit":
            commit_sha = obj_sha
        else:
            return None, None, f"Unsupported tag target type {obj_type!r} for {ref!r}"
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 404:
            # Fallback for refs that are direct commit SHAs or branches.
            commit_sha = ref
        else:
            return None, None, f"Tag resolution failed for {ref!r}: {exc}"
    except Exception as exc:
        return None, None, f"Tag resolution failed for {ref!r}: {exc}"

    try:
        commit_obj = _gh_get(
            f"https://api.github.com/repos/{owner}/{repo}/git/commits/{commit_sha}"
        )
        if not isinstance(commit_obj, dict):
            return (
                str(commit_sha) if commit_sha else None,
                None,
                f"Invalid commit response for {commit_sha!r}",
            )
        tree = commit_obj.get("tree") or {}
        tree_sha = tree.get("sha")
        if not tree_sha:
            return (
                str(commit_sha) if commit_sha else None,
                None,
                f"Missing tree SHA on commit {commit_sha!r}",
            )
        return str(commit_sha) if commit_sha else None, str(tree_sha), None
    except Exception as exc:
        return (
            str(commit_sha) if commit_sha else None,
            None,
            f"Commit/tree resolution failed for {commit_sha!r}: {exc}",
        )


def _resolve_ref_to_tree_sha(
    owner: str, repo: str, ref: str
) -> tuple[Optional[str], Optional[str]]:
    """Resolve tag/ref/commit to a tree SHA. Returns (tree_sha, error_detail)."""
    _c_sha, t_sha, err = _resolve_ref_to_commit_and_tree_sha(owner, repo, ref)
    return t_sha, err


def compare_source_and_artifact_from_snapshot(
    extract_dir: str,
    source_snapshot: audit_source_snapshot.SourceSnapshot,
    ref: str,
) -> tuple[dict[str, Any], list[Finding], ScannerStatus]:
    """Compare extracted ZIP against materialized source snapshot.

    Returns (diff_summary, findings, status).
    """
    summary: dict[str, Any] = {
        "ref": ref,
        "checked": False,
        "zip_only_executables": [],
        "zip_only_scripts": [],
        "modified_source_files": [],
        "large_binaries_absent_from_source": [],
        "unexpected_urls": [],
    }
    findings: list[Finding] = []
    normalized_release_version = plugin_release_utils.normalize_version(ref)

    if not os.path.isdir(extract_dir):
        return (
            summary,
            findings,
            ScannerStatus(
                name="source-artifact-diff",
                status="unavailable",
                detail="Extraction directory is unavailable.",
            ),
        )

    if not os.path.isdir(source_snapshot.source_root):
        return (
            summary,
            findings,
            ScannerStatus(
                name="source-artifact-diff",
                status="failed",
                detail="Source snapshot root is unavailable.",
            ),
        )

    source_tree_exact, source_tree_lower, source_path_lower, source_entries = (
        _snapshot_source_inventory_lookup(source_snapshot.inventory)
    )

    summary["checked"] = True

    # ------------------------------------------------------------------
    # Walk extracted directory and compare with the provided source snapshot.
    # ------------------------------------------------------------------
    for root, _dirs, files in os.walk(extract_dir):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, extract_dir).replace("\\", "/")
            rel_lower = rel_path.lower()

            # Strip a leading plugin-name directory (common in release ZIPs)
            parts = rel_path.split("/", 1)
            short_path = parts[1] if len(parts) == 2 else parts[0]
            short_lower = short_path.lower()

            source_path: Optional[str] = None
            if short_path in source_tree_exact:
                source_path = short_path
            elif rel_path in source_tree_exact:
                source_path = rel_path
            elif short_lower in source_tree_lower:
                source_path = source_path_lower[short_lower]
            elif rel_lower in source_tree_lower:
                source_path = source_path_lower[rel_lower]
            source_sha = (
                source_tree_exact.get(source_path) if source_path is not None else None
            )
            in_source = source_path is not None

            try:
                if os.path.islink(full_path):
                    raw = os.readlink(full_path).encode("utf-8", errors="replace")
                else:
                    with open(full_path, "rb") as source_file:
                        raw = source_file.read()
            except Exception:
                continue

            if not in_source:
                bin_info = identify_binary(raw[:16], rel_path)
                if bin_info:
                    summary["zip_only_executables"].append(rel_path)
                    findings.append(
                        Finding(
                            rule_id="ZIP_ONLY_EXECUTABLE",
                            severity="high",
                            classification="MANUAL_REVIEW",
                            path=rel_path,
                            line=0,
                            message=(
                                f"Binary file {rel_path!r} ({bin_info['label']}) is present "
                                "in the release ZIP but absent from the repository source."
                            ),
                            evidence=bin_info["label"],
                            scanner="source-artifact-diff",
                        )
                    )
                else:
                    executable_bits = bool(
                        os.stat(full_path).st_mode
                        & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    )
                    if _looks_like_script_asset(short_path, raw, executable_bits):
                        summary["zip_only_scripts"].append(rel_path)
                        findings.append(
                            Finding(
                                rule_id="ZIP_ONLY_SCRIPT",
                                severity="high",
                                classification="MANUAL_REVIEW",
                                path=rel_path,
                                line=0,
                                message=(
                                    f"Script-like file {rel_path!r} is present in the "
                                    "release ZIP but absent from the repository source."
                                ),
                                evidence="script-heuristic",
                                scanner="source-artifact-diff",
                            )
                        )
                continue

            source_entry = source_entries[source_path]
            if source_sha is None:
                summary["modified_source_files"].append(rel_path)
                findings.append(
                    Finding(
                        rule_id="MODIFIED_SOURCE_FILE",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=rel_path,
                        line=0,
                        message=(
                            f"File {rel_path!r} is present in repository source "
                            "but has modified content in the release ZIP."
                        ),
                        evidence=f"hash-mismatch (source: <missing>, zip: {git_blob_sha1(raw)[:8]})",
                        scanner="source-artifact-diff",
                    )
                )
                continue

            source_raw = None
            build_stamped_metadata = False
            base = os.path.basename(source_path).lower()

            zip_sha = git_blob_sha1(raw)
            if zip_sha == source_sha:
                continue

            raw_lf = raw.replace(b"\r\n", b"\n")
            zip_sha_lf = git_blob_sha1(raw_lf)
            if zip_sha_lf == source_sha:
                continue

            if base in {"plugin.json", "package.json"}:
                source_lookup = {
                    "plugin.json": source_snapshot.plugin_json,
                    "package.json": source_snapshot.package_json,
                }
                source_raw = source_lookup.get(source_path.lower())
                try:
                    if source_raw is None:
                        if source_entry.kind == "symlink":
                            source_raw = _snapshot_source_symlink_payload(source_entry)
                        else:
                            source_raw = _read_snapshot_metadata_file(
                                source_entry, source_snapshot.source_root
                            )

                    source_raw = _assert_snapshot_metadata_payload(
                        source_entry, source_raw
                    )
                except Exception as exc:
                    try:
                        detail = (
                            f"Could not read source snapshot file {source_path!r}: "
                            f"{_redacted_exception_detail(exc)}"
                        )
                    except Exception:
                        detail = (
                            f"Could not read source snapshot file {source_path!r}: "
                            "unavailable"
                        )
                    return (
                        summary,
                        findings,
                        ScannerStatus(
                            name="source-artifact-diff",
                            status="failed",
                            detail=detail,
                        ),
                    )

            if source_raw is not None:
                build_stamped_metadata = _metadata_diff_is_build_stamped(
                    source_path,
                    source_raw,
                    raw,
                    normalized_release_version,
                )

            if not build_stamped_metadata:
                summary["modified_source_files"].append(rel_path)
                findings.append(
                    Finding(
                        rule_id="MODIFIED_SOURCE_FILE",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=rel_path,
                        line=0,
                        message=(
                            f"File {rel_path!r} is present in repository source "
                            "but has modified content in the release ZIP."
                        ),
                        evidence=f"hash-mismatch (source: {source_sha[:8]}, zip: {zip_sha[:8]})",
                        scanner="source-artifact-diff",
                    )
                )

    summary["zip_only_executables"].sort()
    summary["zip_only_scripts"].sort()
    summary["modified_source_files"].sort()
    status = "found_issue" if findings else "passed"
    return summary, findings, ScannerStatus(name="source-artifact-diff", status=status)


def compare_source_and_artifact(
    extract_dir: str,
    owner: str,
    repo: str,
    ref: str,
) -> tuple[dict[str, Any], list[Finding], ScannerStatus]:
    """Compare extracted ZIP against the repository source at ref.

    Returns (diff_summary, findings, status).
    """
    summary: dict[str, Any] = {
        "ref": ref,
        "checked": False,
        "zip_only_executables": [],
        "zip_only_scripts": [],
        "modified_source_files": [],
        "large_binaries_absent_from_source": [],
        "unexpected_urls": [],
    }
    findings: list[Finding] = []
    normalized_release_version = plugin_release_utils.normalize_version(ref)

    if not os.path.isdir(extract_dir):
        return (
            summary,
            findings,
            ScannerStatus(
                name="source-artifact-diff",
                status="unavailable",
                detail="Extraction directory is unavailable.",
            ),
        )

    try:
        tree_sha, tree_err = _resolve_ref_to_tree_sha(owner, repo, ref)
        if not tree_sha:
            return (
                summary,
                findings,
                ScannerStatus(
                    name="source-artifact-diff",
                    status="failed",
                    detail=tree_err or f"Could not resolve ref {ref!r} to a tree SHA",
                ),
            )
        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}"
        tree_data = _gh_get(tree_url + "?recursive=1")
        if not isinstance(tree_data, dict):
            return (
                summary,
                findings,
                ScannerStatus(
                    name="source-artifact-diff",
                    status="failed",
                    detail="Malformed tree response.",
                ),
            )
        if tree_data.get("truncated") is True:
            return (
                summary,
                findings,
                ScannerStatus(
                    name="source-artifact-diff",
                    status="failed",
                    detail="Tree response truncated by GitHub API.",
                ),
            )
        source_tree_exact: dict[str, Optional[str]] = {}
        source_tree_lower: dict[str, Optional[str]] = {}
        source_path_lower: dict[str, str] = {}
        for item in tree_data.get("tree") or []:
            if isinstance(item, dict):
                p = item.get("path")
                sha = item.get("sha")
                if p:
                    source_tree_exact[p] = sha
                    source_tree_lower[p.lower()] = sha
                    source_path_lower[p.lower()] = p
        summary["checked"] = True
    except Exception as exc:
        detail = f"Could not fetch source tree for {owner}/{repo}@{ref}: {exc}"
        log.debug(detail)
        return (
            summary,
            findings,
            ScannerStatus(
                name="source-artifact-diff",
                status="failed",
                detail=detail,
            ),
        )

    # Walk extracted directory and compare
    for root, _dirs, files in os.walk(extract_dir):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, extract_dir).replace("\\", "/")
            rel_lower = rel_path.lower()

            # Strip a leading plugin-name directory (common in release ZIPs)
            parts = rel_path.split("/", 1)
            short_path = parts[1] if len(parts) == 2 else parts[0]
            short_lower = short_path.lower()

            source_path: Optional[str] = None
            if short_path in source_tree_exact:
                source_path = short_path
            elif rel_path in source_tree_exact:
                source_path = rel_path
            elif short_lower in source_tree_lower:
                source_path = source_path_lower[short_lower]
            elif rel_lower in source_tree_lower:
                source_path = source_path_lower[rel_lower]
            source_sha = (
                source_tree_exact.get(source_path) if source_path is not None else None
            )
            in_source = source_path is not None

            try:
                if os.path.islink(full_path):
                    raw = os.readlink(full_path).encode("utf-8", errors="replace")
                else:
                    with open(full_path, "rb") as fh:
                        raw = fh.read()
            except Exception:
                continue

            bin_info = identify_binary(raw[:16], rel_path)
            if bin_info and not in_source:
                summary["zip_only_executables"].append(rel_path)
                findings.append(
                    Finding(
                        rule_id="ZIP_ONLY_EXECUTABLE",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=rel_path,
                        line=0,
                        message=(
                            f"Binary file {rel_path!r} ({bin_info['label']}) is present "
                            "in the release ZIP but absent from the repository source."
                        ),
                        evidence=bin_info["label"],
                        scanner="source-artifact-diff",
                    )
                )
                continue

            if in_source:
                if source_sha:
                    zip_sha = git_blob_sha1(raw)
                    if zip_sha != source_sha:
                        raw_lf = raw.replace(b"\r\n", b"\n")
                        zip_sha_lf = git_blob_sha1(raw_lf)
                        if zip_sha_lf != source_sha:
                            build_stamped_metadata = False
                            if source_path and posixpath.basename(
                                source_path
                            ).lower() in {"plugin.json", "package.json"}:
                                source_raw = get_repo_file_raw(
                                    owner, repo, ref, source_path
                                )
                                if source_raw is not None:
                                    build_stamped_metadata = (
                                        _metadata_diff_is_build_stamped(
                                            source_path,
                                            source_raw,
                                            raw,
                                            normalized_release_version,
                                        )
                                    )
                            if not build_stamped_metadata:
                                summary["modified_source_files"].append(rel_path)
                                findings.append(
                                    Finding(
                                        rule_id="MODIFIED_SOURCE_FILE",
                                        severity="high",
                                        classification="MANUAL_REVIEW",
                                        path=rel_path,
                                        line=0,
                                        message=(
                                            f"File {rel_path!r} is present in repository source "
                                            "but has modified content in the release ZIP."
                                        ),
                                        evidence=f"hash-mismatch (source: {source_sha[:8]}, zip: {zip_sha[:8]})",
                                        scanner="source-artifact-diff",
                                    )
                                )
                continue

            try:
                executable_bits = bool(
                    os.stat(full_path).st_mode
                    & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                )
            except OSError:
                executable_bits = False

            if _looks_like_script_asset(short_path, raw, executable_bits):
                summary["zip_only_scripts"].append(rel_path)
                findings.append(
                    Finding(
                        rule_id="ZIP_ONLY_SCRIPT",
                        severity="high",
                        classification="MANUAL_REVIEW",
                        path=rel_path,
                        line=0,
                        message=(
                            f"Script-like file {rel_path!r} is present in the release ZIP "
                            "but absent from the repository source."
                        ),
                        evidence="script-heuristic",
                        scanner="source-artifact-diff",
                    )
                )

    summary["zip_only_executables"].sort()
    summary["zip_only_scripts"].sort()
    summary["modified_source_files"].sort()
    status = "found_issue" if findings else "passed"
    return summary, findings, ScannerStatus(name="source-artifact-diff", status=status)


def _trivy_database_identity(version_payload: Any) -> Optional[dict[str, Any]]:
    """Return a fail-safe Trivy database identity from its JSON version payload."""
    if not isinstance(version_payload, Mapping):
        return None

    vulnerability_database = version_payload.get("VulnerabilityDB")
    if not isinstance(vulnerability_database, Mapping):
        return None

    database_version = vulnerability_database.get("Version")
    if (
        not isinstance(database_version, int)
        or isinstance(database_version, bool)
        or database_version < 1
    ):
        return None

    freshness_values = []
    for freshness_field in ("UpdatedAt", "DownloadedAt"):
        if freshness_field not in vulnerability_database:
            continue
        value = vulnerability_database[freshness_field]
        if not isinstance(value, str) or not value.strip():
            return None
        freshness_values.append(value)

    if not freshness_values:
        return None
    return dict(vulnerability_database)


def _scanner_runtime_identities(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return executable/version and database freshness identities for scanners."""
    commands = {
        "clamav": ("clamscan", ["--version"]),
        "trivy": ("trivy", ["--version"]),
        "semgrep": ("semgrep", ["--version"]),
    }
    identities: dict[str, dict[str, Any]] = {}
    for name, (command, version_args) in commands.items():
        if not _scanner_enabled(policy, name):
            identities[name] = {"enabled": False}
            continue
        executable = shutil.which(command)
        identity: dict[str, Any] = {
            "enabled": True,
            "executable": executable,
            "version": None,
        }
        if executable:
            try:
                completed = subprocess.run(
                    [executable, *version_args],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                output = (completed.stdout or completed.stderr).strip()[:2000]
                if completed.returncode == 0 and output:
                    identity["version"] = output
                    if name == "clamav" and output.count("/") >= 2:
                        identity["database"] = output
            except (OSError, subprocess.SubprocessError):
                pass

        if name == "trivy" and executable:
            try:
                completed = subprocess.run(
                    [executable, "version", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if completed.returncode == 0:
                    version_payload = json.loads(completed.stdout)
                    vulnerability_database = _trivy_database_identity(version_payload)
                    if vulnerability_database is not None:
                        identity["database"] = vulnerability_database
            except (OSError, subprocess.SubprocessError, ValueError, TypeError):
                pass

        if name in {"clamav", "trivy"} and "database" not in identity:
            identity["database"] = None
        identities[name] = identity
    return identities


def _scanner_database_freshness_available(
    policy: dict[str, Any], scanner_identities: dict[str, dict[str, Any]]
) -> bool:
    return all(
        not _scanner_enabled(policy, name)
        or bool(scanner_identities.get(name, {}).get("database"))
        for name in ("clamav", "trivy")
    )


def compute_audit_context_hash(
    policy: dict[str, Any],
    exceptions: list[dict[str, Any]],
    policy_path: Optional[str] = None,
    allowlist_path: Optional[str] = None,
    *,
    scanner_identities: Optional[dict[str, dict[str, Any]]] = None,
) -> str:
    hasher = hashlib.sha256()

    hasher.update(json.dumps(policy, sort_keys=True).encode("utf-8"))
    hasher.update(json.dumps(exceptions, sort_keys=True).encode("utf-8"))
    identities = (
        scanner_identities
        if scanner_identities is not None
        else _scanner_runtime_identities(policy)
    )
    hasher.update(json.dumps(identities, sort_keys=True).encode("utf-8"))

    try:
        hasher.update(Path(SEMGREP_RULES_FILE).read_bytes())
    except OSError:
        hasher.update(b"semgrep-rules:unavailable")

    try:
        script_path = Path(__file__).resolve()
        if script_path.exists():
            hasher.update(script_path.read_bytes())
        else:
            hasher.update(POLICY_VERSION.encode("utf-8"))
    except Exception:
        hasher.update(POLICY_VERSION.encode("utf-8"))

    return hasher.hexdigest()[:32]


def _cache_key(
    repository: str,
    release_id: str,
    artifact_sha256: str,
    audit_context_hash: str,
    resolved_tag_commit_sha: str,
) -> str:
    repo_norm = repository.rstrip("/")
    raw = f"{repo_norm}|{release_id}|{artifact_sha256}|{audit_context_hash}|{resolved_tag_commit_sha}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _pre_download_index_key(
    repository: str,
    release_id: str,
    audit_context_hash: str,
    resolved_tag_commit_sha: str,
) -> str:
    repo_norm = repository.rstrip("/")
    raw = f"{repo_norm}|{release_id}|{audit_context_hash}|{resolved_tag_commit_sha}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def load_cached_report_predownload(
    cache_dir: str,
    repository: str,
    release_id: str,
    audit_context_hash: str,
    resolved_tag_commit_sha: str,
) -> Optional[AuditReport]:
    if not os.path.isdir(cache_dir):
        return None

    repo_norm = repository.rstrip("/")
    idx_key = _pre_download_index_key(
        repo_norm, release_id, audit_context_hash, resolved_tag_commit_sha
    )
    idx_path = os.path.join(cache_dir, "index.json")
    cache_key = None

    if os.path.exists(idx_path):
        try:
            with open(idx_path, encoding="utf-8") as f:
                index = json.load(f)
            entry = index.get(idx_key)
            if entry and isinstance(entry, dict):
                if (
                    entry.get("release_id") == release_id
                    and entry.get("repository", "").rstrip("/") == repo_norm
                    and entry.get("audit_context_hash") == audit_context_hash
                    and entry.get("resolved_tag_commit_sha") == resolved_tag_commit_sha
                ):
                    cache_key = entry.get("cache_key")
        except Exception as exc:
            log.debug("Index load failed: %s", exc)

    if not cache_key:
        # Fallback search over cached report json files
        for fname in os.listdir(cache_dir):
            if fname.endswith(".json") and fname != "index.json":
                fpath = os.path.join(cache_dir, fname)
                try:
                    with open(fpath, encoding="utf-8") as f:
                        data = json.load(f)
                    if (
                        data.get("repository", "").rstrip("/") == repo_norm
                        and data.get("release_id") == release_id
                        and data.get("audit_context_hash") == audit_context_hash
                        and data.get("resolved_tag_commit_sha")
                        == resolved_tag_commit_sha
                    ):
                        cache_key = fname[:-5]
                        break
                except Exception:
                    continue

    if not cache_key:
        return None

    path = os.path.join(cache_dir, f"{cache_key}.json")
    if not os.path.exists(path):
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if (
            data.get("audit_context_hash") != audit_context_hash
            or data.get("resolved_tag_commit_sha") != resolved_tag_commit_sha
            or data.get("repository", "").rstrip("/") != repo_norm
            or data.get("release_id") != release_id
        ):
            log.debug("Cache entry rejected due to context or tag commit SHA mismatch.")
            return None

        report = _dict_to_report(data)
        log.info("Cache hit (pre-download) for %s @ %s", repository, release_id)
        return report
    except Exception as exc:
        log.debug("Cache load failed: %s", exc)
        return None


def load_cached_report(
    cache_dir: str,
    repository: str,
    release_id: str,
    artifact_sha256: str,
    audit_context_hash: str,
    resolved_tag_commit_sha: str,
) -> Optional[AuditReport]:
    key = _cache_key(
        repository,
        release_id,
        artifact_sha256,
        audit_context_hash,
        resolved_tag_commit_sha,
    )
    path = os.path.join(cache_dir, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if (
            data.get("audit_context_hash") != audit_context_hash
            or data.get("resolved_tag_commit_sha") != resolved_tag_commit_sha
            or (artifact_sha256 and data.get("artifact_sha256") != artifact_sha256)
        ):
            log.debug("Cache entry rejected due to field mismatch.")
            return None

        report = _dict_to_report(data)
        log.info("Cache hit for %s @ %s", repository, release_id)
        return report
    except Exception as exc:
        log.debug("Cache load failed: %s", exc)
        return None


def save_cached_report(
    cache_dir: str,
    report: AuditReport,
    release_id: str,
    audit_context_hash: str,
    resolved_tag_commit_sha: str,
) -> None:
    if not report.artifact_sha256:
        return
    report.release_id = release_id
    if audit_context_hash:
        report.audit_context_hash = audit_context_hash
    if resolved_tag_commit_sha:
        report.resolved_tag_commit_sha = resolved_tag_commit_sha

    ctx_hash = report.audit_context_hash or audit_context_hash
    commit_sha = report.resolved_tag_commit_sha or resolved_tag_commit_sha

    key = _cache_key(
        report.repository, release_id, report.artifact_sha256, ctx_hash, commit_sha
    )
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, f"{key}.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_report_to_dict(report), f, indent=2, sort_keys=True)

        idx_path = os.path.join(cache_dir, "index.json")
        index = {}
        if os.path.exists(idx_path):
            try:
                with open(idx_path, encoding="utf-8") as f:
                    index = json.load(f)
            except Exception:
                index = {}
        idx_key = _pre_download_index_key(
            report.repository, release_id, ctx_hash, commit_sha
        )
        index[idx_key] = {
            "cache_key": key,
            "artifact_sha256": report.artifact_sha256,
            "repository": report.repository,
            "release_id": release_id,
            "audit_context_hash": ctx_hash,
            "resolved_tag_commit_sha": commit_sha,
        }
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, sort_keys=True)
    except Exception as exc:
        log.debug("Cache save failed: %s", exc)


def _read_verdict_store(path: str) -> Any:
    """Read a tracked verdict store without weakening its integrity boundary."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Verdict store {path} must contain valid JSON: {exc}"
        ) from exc
    except OSError as exc:
        raise ValueError(f"Verdict store {path} could not be read: {exc}") from exc


def _validate_verdict_repository_records(
    raw_repository: str, release_records: Any
) -> dict[str, dict[str, Any]]:
    if not isinstance(release_records, dict):
        raise ValueError(f"verdict repository {raw_repository!r} must map to an object")

    canonical_records: dict[str, dict[str, Any]] = {}
    release_key_pattern = re.compile(r"^.+@[0-9]+$")
    for release_key, record in release_records.items():
        if not isinstance(release_key, str) or not release_key_pattern.fullmatch(
            release_key
        ):
            raise ValueError(
                f"invalid verdict release key {release_key!r} in {raw_repository!r}"
            )
        if not isinstance(record, dict):
            raise ValueError(
                f"verdict release record {raw_repository!r}/{release_key!r} must be an object"
            )
        classification = record.get("classification")
        if (
            not isinstance(classification, str)
            or classification not in CLASSIFICATION_ORDER
        ):
            raise ValueError(
                f"invalid verdict classification for {raw_repository!r}/{release_key!r}"
            )
        for field_name in (
            "blocking_rule_ids",
            "review_rule_ids",
            "warning_rule_ids",
        ):
            rule_ids = record.get(field_name, [])
            if not isinstance(rule_ids, list) or not all(
                isinstance(rule_id, str) for rule_id in rule_ids
            ):
                raise ValueError(
                    f"verdict {field_name} for {raw_repository!r}/{release_key!r} "
                    "must be a list of strings"
                )
        artifact_sha256 = record.get("artifact_sha256")
        if artifact_sha256 is not None and (
            not isinstance(artifact_sha256, str)
            or not _CANONICAL_SHA256.fullmatch(artifact_sha256)
        ):
            raise ValueError(
                f"invalid verdict artifact_sha256 for {raw_repository!r}/{release_key!r}"
            )
        canonical_records[release_key] = record
    return canonical_records


def _validate_verdict_store(
    verdicts: Any,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Validate one canonical tracked snapshot, rejecting repository aliases."""
    if not isinstance(verdicts, dict):
        raise ValueError("verdict store root must be a JSON object")

    validated: dict[str, dict[str, dict[str, Any]]] = {}
    for raw_repository, release_records in verdicts.items():
        if not isinstance(raw_repository, str):
            raise ValueError("verdict repository keys must be strings")
        try:
            repository = plugin_release_utils.canonicalize_github_repository_url(
                raw_repository
            )
        except ValueError as exc:
            raise ValueError(
                f"verdict repository key is not canonical GitHub state: {raw_repository!r}"
            ) from exc
        if repository in validated:
            raise ValueError(
                f"verdict repository mappings collide after normalization: {repository}"
            )
        validated[repository] = _validate_verdict_repository_records(
            raw_repository, release_records
        )
    return validated


def load_verdicts(cache_dir: str = CACHE_DIR) -> dict[str, dict[str, dict[str, Any]]]:
    """Load and fully validate the tracked verdict snapshot.

    A missing tracked file is a valid empty snapshot. A present file is an
    integrity boundary: malformed or unreadable state raises and legacy cache
    state is never consulted.
    """
    del cache_dir  # Legacy cache verdicts are intentionally not trusted.
    return _validate_verdict_store(_read_verdict_store(VERDICTS_FILE))


def _write_verdicts_atomic(
    verdicts: dict[str, dict[str, dict[str, Any]]], destination: str | None = None
) -> None:
    """Atomically replace the tracked verdict store with deterministic JSON."""
    destination = destination or VERDICTS_FILE
    destination_dir = os.path.dirname(os.path.abspath(destination))
    os.makedirs(destination_dir, exist_ok=True)
    filename = os.path.basename(destination)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{filename}.", suffix=".tmp", dir=destination_dir
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(verdicts, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _merge_tracked_verdict_aliases(
    verdicts: Any,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Canonicalize tracked aliases with deterministic, fail-closed precedence."""
    if not isinstance(verdicts, dict):
        raise ValueError("verdict store root must be a JSON object")

    grouped: dict[str, list[tuple[str, dict[str, dict[str, Any]]]]] = {}
    for raw_repository, release_records in verdicts.items():
        if not isinstance(raw_repository, str):
            raise ValueError("verdict repository keys must be strings")
        try:
            repository = plugin_release_utils.canonicalize_github_repository_url(
                raw_repository
            )
        except ValueError as exc:
            raise ValueError(
                f"verdict repository key is not canonical GitHub state: {raw_repository!r}"
            ) from exc
        grouped.setdefault(repository, []).append(
            (
                raw_repository,
                _validate_verdict_repository_records(raw_repository, release_records),
            )
        )

    merged: dict[str, dict[str, dict[str, Any]]] = {}
    for repository, aliases in sorted(grouped.items()):
        release_ids = sorted(
            {
                release_id
                for _, release_records in aliases
                for release_id in release_records
            }
        )
        merged_records: dict[str, dict[str, Any]] = {}
        for release_id in release_ids:
            candidates = [
                (raw_repository, release_records[release_id])
                for raw_repository, release_records in aliases
                if release_id in release_records
            ]
            canonical_record = next(
                (
                    record
                    for raw_repository, record in candidates
                    if raw_repository == repository
                ),
                None,
            )
            if canonical_record is not None:
                merged_records[release_id] = canonical_record
                continue

            candidate_records = [record for _, record in candidates]
            first_record = candidate_records[0]
            if any(record != first_record for record in candidate_records[1:]):
                raise ValueError(
                    "ambiguous tracked verdict aliases for "
                    f"{repository}/{release_id}: no exact canonical key wins"
                )
            merged_records[release_id] = first_record
        merged[repository] = merged_records
    return merged


def apply_verdict_delta(verdict_store: str, verdict_delta: str) -> None:
    """Validate, canonically merge, and atomically apply one verdict delta."""
    tracked = _merge_tracked_verdict_aliases(_read_verdict_store(verdict_store))
    delta = aggregate_verdict_deltas([verdict_delta])

    merged = {
        repository: dict(release_records)
        for repository, release_records in tracked.items()
    }
    for repository, release_records in delta.items():
        merged.setdefault(repository, {}).update(release_records)

    validated = _validate_verdict_store(merged)
    _write_verdicts_atomic(validated, destination=verdict_store)


def _blocking_rule_ids(report: AuditReport) -> list[str]:
    return sorted(
        {
            finding.rule_id
            for finding in report.findings
            if finding.classification == "BLOCK" and not finding.allowlisted
        }
    )


def _rationale_rule_ids(report: AuditReport, classification: str) -> list[str]:
    return sorted(
        {
            finding.rule_id
            for finding in report.findings
            if finding.classification == classification and not finding.allowlisted
        }
    )


def _record_verdict(cache_dir: str, report: AuditReport) -> None:
    """Persist a real audit verdict without replacing one with AUDIT_ERROR."""
    if report.final_classification == "AUDIT_ERROR" or not report.release_id:
        return

    verdicts = load_verdicts(cache_dir)
    repository = plugin_release_utils.canonicalize_github_repository_url(
        report.repository
    )
    repository_verdicts = verdicts.setdefault(repository, {})
    current = repository_verdicts.get(report.release_id, {})
    updated = {
        "classification": report.final_classification,
        "blocking_rule_ids": _blocking_rule_ids(report),
        # A MANUAL_REVIEW verdict can correctly have no blocking rules. Keep the
        # review and warning rationale alongside it so that is not ambiguous.
        "review_rule_ids": _rationale_rule_ids(report, "MANUAL_REVIEW"),
        "warning_rule_ids": _rationale_rule_ids(report, "PASS_WITH_WARNINGS"),
        "artifact_sha256": report.artifact_sha256,
        "audit_context_hash": report.audit_context_hash,
        "audited_at": report.audit_timestamp,
    }
    stable_fields = ("classification", "blocking_rule_ids", "artifact_sha256")
    if all(current.get(field) == updated[field] for field in stable_fields):
        refresh_fields = (
            "audit_context_hash",
            "review_rule_ids",
            "warning_rule_ids",
        )
        if any(current.get(field) != updated[field] for field in refresh_fields):
            for field in refresh_fields:
                current[field] = updated[field]
            _write_verdicts_atomic(verdicts)
        elif not os.path.exists(VERDICTS_FILE):
            _write_verdicts_atomic(verdicts)
        return
    repository_verdicts[report.release_id] = updated
    _write_verdicts_atomic(verdicts)


def _release_id(release: dict[str, Any]) -> str:
    zip_assets = [
        asset
        for asset in (release.get("assets") or [])
        if asset.get("name", "").lower().endswith(".zip")
    ]
    if len(zip_assets) != 1:
        return ""
    return f"{release.get('tag_name', '')}@{zip_assets[0].get('id', '')}"


def effective_stored_classification(
    entry: dict[str, Any], blockable_rules: Collection[str] | None = None
) -> str:
    """Re-derive whether a durable BLOCK is justified by the current policy.

    Re-derivation is deliberately demotion-only. A stored non-BLOCK verdict is
    never promoted from stale rule IDs, while a stored BLOCK without a currently
    blockable rationale fails open to MANUAL_REVIEW.
    """
    stored_classification = entry.get("classification", "AUDIT_ERROR")
    if stored_classification != "BLOCK":
        return stored_classification

    if blockable_rules is None:
        blockable_rules = load_policy().get("blockable_rules", [])
    blocking_rule_ids = entry.get("blocking_rule_ids") or []
    if set(blocking_rule_ids).intersection(blockable_rules):
        return "BLOCK"
    return "MANUAL_REVIEW"


def classification_for(
    repository: str,
    release: AuditReport | dict[str, Any],
    verdicts: dict[str, dict[str, dict[str, Any]]],
    blockable_rules: Collection[str] | None = None,
    *,
    current_artifact_sha256: Optional[str] = None,
) -> VerdictResult:
    """Return the current and effective classifications for one release.

    An AuditReport represents an immediate attempt and can therefore expose an
    AUDIT_ERROR while falling back to a prior durable verdict.  A release
    mapping represents a catalog lookup and reports the durable verdict itself.
    """
    canonical_repository = plugin_release_utils.canonicalize_github_repository_url(
        repository
    )
    repository_verdicts = verdicts.get(canonical_repository, {})
    if not repository_verdicts:
        for stored_repository, stored_verdicts in verdicts.items():
            try:
                candidate = plugin_release_utils.canonicalize_github_repository_url(
                    stored_repository
                )
            except ValueError:
                continue
            if candidate == canonical_repository:
                repository_verdicts = stored_verdicts
                break

    if isinstance(release, AuditReport):
        audit_classification = release.final_classification
        prior = repository_verdicts.get(release.release_id, {})
        current_hash = release.artifact_sha256 or current_artifact_sha256
        if audit_classification != "AUDIT_ERROR":
            return VerdictResult(
                effective_classification=audit_classification,
                audit_classification=audit_classification,
                blocking_rule_ids=_blocking_rule_ids(release),
                identity_status="CURRENT",
                current_artifact_sha256=current_hash or None,
                stored_artifact_sha256=current_hash or None,
                fail_open=False,
            )
        stored_hash = prior.get("artifact_sha256")
        identity_status = (
            "UNKNOWN"
            if not prior
            else (
                "CURRENT"
                if current_hash and stored_hash == current_hash
                else "STALE_HASH"
            )
        )
        prior_classification = prior.get("classification", "AUDIT_ERROR")
        if identity_status == "CURRENT" and prior_classification != "AUDIT_ERROR":
            return VerdictResult(
                effective_classification=effective_stored_classification(
                    prior, blockable_rules
                ),
                audit_classification="AUDIT_ERROR",
                blocking_rule_ids=list(prior.get("blocking_rule_ids") or []),
                identity_status=identity_status,
                current_artifact_sha256=current_hash,
                stored_artifact_sha256=stored_hash,
                fail_open=False,
            )
        return VerdictResult(
            "AUDIT_ERROR",
            "AUDIT_ERROR",
            [],
            identity_status=identity_status,
            current_artifact_sha256=current_hash or None,
            stored_artifact_sha256=stored_hash,
            fail_open=True,
        )

    entry = repository_verdicts.get(_release_id(release), {})
    classification = entry.get("classification", "AUDIT_ERROR")
    stored_hash = entry.get("artifact_sha256")
    if not entry:
        return VerdictResult(
            effective_classification="AUDIT_ERROR",
            audit_classification="AUDIT_ERROR",
            identity_status="UNKNOWN",
            current_artifact_sha256=current_artifact_sha256,
            stored_artifact_sha256=None,
            fail_open=True,
        )
    if not current_artifact_sha256 or stored_hash != current_artifact_sha256:
        return VerdictResult(
            effective_classification="AUDIT_ERROR",
            audit_classification=classification,
            blocking_rule_ids=list(entry.get("blocking_rule_ids") or []),
            identity_status="STALE_HASH",
            current_artifact_sha256=current_artifact_sha256,
            stored_artifact_sha256=stored_hash,
            fail_open=True,
        )
    return VerdictResult(
        effective_classification=effective_stored_classification(
            entry, blockable_rules
        ),
        audit_classification=classification,
        blocking_rule_ids=list(entry.get("blocking_rule_ids") or []),
        identity_status="CURRENT",
        current_artifact_sha256=current_artifact_sha256,
        stored_artifact_sha256=stored_hash,
        fail_open=False,
    )


def _dict_to_report(data: dict[str, Any]) -> AuditReport:
    report = AuditReport(
        **{
            k: v
            for k, v in data.items()
            if k
            not in (
                "findings",
                "scanner_statuses",
                "archive_stats",
                "allowlist_decisions",
            )
        }
    )
    report.findings = [Finding(**ff) for ff in data.get("findings", [])]
    report.scanner_statuses = [
        ScannerStatus(**ss) for ss in data.get("scanner_statuses", [])
    ]
    if data.get("archive_stats"):
        report.archive_stats = ArchiveStats(**data["archive_stats"])
    report.allowlist_decisions = data.get("allowlist_decisions", [])
    return report


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def _report_to_dict(report: AuditReport) -> dict[str, Any]:
    d = asdict(report)
    # Convert dataclasses in lists
    return d


def generate_json_report(report: AuditReport) -> str:
    """Produce deterministic JSON report string."""
    return json.dumps(_report_to_dict(report), indent=2, sort_keys=True, default=str)


_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_CLASS_EMOJI = {
    "PASS": "✅",
    "PASS_WITH_WARNINGS": "⚠️",
    "MANUAL_REVIEW": "🔍",
    "BLOCK": "🚫",
    "AUDIT_ERROR": "❌",
}


def generate_markdown_report(report: AuditReport) -> str:
    """Produce a human-readable Markdown audit report."""
    cls = report.final_classification
    cls_emoji = _CLASS_EMOJI.get(cls, "❓")
    lines: list[str] = [
        f"# Security Audit Report: {report.plugin_name or report.repository}",
        "",
        "## Executive Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Repository | `{report.repository}` |",
        f"| Release | `{report.release}` |",
        f"| Artifact SHA-256 | `{report.artifact_sha256 or 'N/A'}` |",
        f"| Classification | {cls_emoji} **{cls}** |",
        f"| Risk Score | {report.risk_score} |",
        f"| Audit Timestamp | {report.audit_timestamp} |",
        "",
    ]

    # Findings summary
    active = [f for f in report.findings if not f.allowlisted]
    blocks = [f for f in active if f.classification == "BLOCK"]
    reviews = [f for f in active if f.classification == "MANUAL_REVIEW"]
    warnings = [f for f in active if f.classification == "PASS_WITH_WARNINGS"]

    lines += [
        "## Findings",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🚫 BLOCK | {len(blocks)} |",
        f"| 🔍 MANUAL_REVIEW | {len(reviews)} |",
        f"| ⚠️ PASS_WITH_WARNINGS | {len(warnings)} |",
        "",
    ]

    def _render_findings(title: str, findings: list[Finding]) -> list[str]:
        out = [f"### {title}", ""]
        if not findings:
            out += ["*None.*", ""]
            return out
        for f in findings[:50]:  # cap at 50 per section
            sev_emoji = _SEVERITY_EMOJI.get(f.severity, "⚪")
            out.append(
                f"- {sev_emoji} **{f.rule_id}** `{f.path}:{f.line}` — {f.message}"
            )
            if f.evidence:
                out.append(f"  > Evidence: `{f.evidence}`")
        out.append("")
        return out

    lines += _render_findings("Blocking Findings", blocks)
    lines += _render_findings("Manual Review Required", reviews)
    lines += _render_findings("Warnings", warnings)

    # Root/privilege section
    root_findings = [
        f
        for f in active
        if f.rule_id
        in ("ROOT_ACCESS", "PRIVILEGE_SUDO", "PRIVILEGE_PKEXEC", "PRIVILEGE_SUDO_SHELL")
    ]
    if root_findings:
        lines += ["## Root and Privilege Usage", ""]
        for f in root_findings:
            lines.append(f"- **{f.rule_id}** at `{f.path}:{f.line}`: {f.message}")
        lines.append("")

    # Network destinations
    if report.extracted_domains:
        lines += ["## Network Destinations", ""]
        for domain in sorted(set(report.extracted_domains))[:100]:
            lines.append(f"- `{domain}`")
        lines.append("")

    # Native binaries
    if report.native_binaries:
        lines += ["## Included Native Binaries", ""]
        for b in report.native_binaries:
            lines.append(
                f"- `{b.get('path')}` — {b.get('label')} ({b.get('architecture', 'unknown arch')})"
            )
        lines.append("")

    # Archive stats
    if report.archive_stats:
        stats = report.archive_stats
        skipped_extensions = (
            stats.get("static_scan_skipped_extensions", {})
            if isinstance(stats, dict)
            else stats.static_scan_skipped_extensions
        )
        skipped_summary = (
            ", ".join(
                f"{ext}: {count}" for ext, count in sorted(skipped_extensions.items())
            )
            or "None"
        )
        lines += [
            "## Archive Statistics",
            "",
            "| Property | Value |",
            "|----------|-------|",
            f"| Files | {stats['file_count'] if isinstance(stats, dict) else stats.file_count} |",
            f"| Compressed Size | {_fmt_bytes(stats['compressed_bytes'] if isinstance(stats, dict) else stats.compressed_bytes)} |",
            f"| Uncompressed Size | {_fmt_bytes(stats['uncompressed_bytes'] if isinstance(stats, dict) else stats.uncompressed_bytes)} |",
            f"| Compression Ratio | {(stats['compression_ratio'] if isinstance(stats, dict) else stats.compression_ratio):.1f}x |",
            f"| Safe | {'✅' if (stats['safe'] if isinstance(stats, dict) else stats.safe) else '🚫'} |",
            f"| Static source rules skipped | {skipped_summary} |",
            "",
        ]

    # Malware results
    malware = [f for f in report.findings if f.rule_id == "MALWARE"]
    lines += ["## Malware Scan Results", ""]
    if malware:
        for f in malware:
            lines.append(f"- 🔴 **DETECTED** `{f.path}`: {f.message}")
    else:

        def _ss_name(s: Any) -> str:
            return s.name if isinstance(s, ScannerStatus) else (s.get("name") or "")

        clamav_status = next(
            (s for s in report.scanner_statuses if _ss_name(s) == "clamav"),
            None,
        )
        if clamav_status:
            st = (
                clamav_status.status
                if isinstance(clamav_status, ScannerStatus)
                else clamav_status.get("status")
            )
            lines.append(f"ClamAV status: {st}")
        else:
            lines.append("*ClamAV not run.*")
    lines.append("")

    # Scanner statuses
    lines += ["## Scanner Status", ""]
    for ss in report.scanner_statuses:
        name = ss.name if isinstance(ss, ScannerStatus) else ss.get("name", "?")
        status = ss.status if isinstance(ss, ScannerStatus) else ss.get("status", "?")
        detail = (
            ss.detail if isinstance(ss, ScannerStatus) else ss.get("detail")
        ) or ""
        icon = {
            "passed": "✅",
            "found_issue": "🔴",
            "unavailable": "⚠️",
            "failed": "❌",
            "skipped": "⏭️",
        }.get(status, "❓")
        lines.append(
            f"- {icon} **{name}**: {status}" + (f" — {detail}" if detail else "")
        )
    lines.append("")

    # Allowlisted findings
    allowlisted = [f for f in report.findings if f.allowlisted]
    if allowlisted:
        lines += ["## Allowlisted Findings", ""]
        for f in allowlisted:
            lines.append(f"- **{f.rule_id}** `{f.path}:{f.line}` (allowlisted)")
        lines.append("")

    # Errors
    if report.errors:
        lines += ["## Errors and Incomplete Checks", ""]
        for err in report.errors:
            lines.append(f"- ❌ {err}")
        lines.append("")

    # Recommended actions
    lines += ["## Recommended Actions", ""]
    if cls == "PASS":
        lines.append("No action required. Audit passed with no findings.")
    elif cls == "PASS_WITH_WARNINGS":
        lines.append("Review warnings above. No blocking issues found.")
    elif cls == "MANUAL_REVIEW":
        lines += [
            "**Manual review is required before this plugin can be accepted.**",
            "",
            "Review the findings above, in particular:",
        ]
        for f in reviews[:10]:
            lines.append(f"- `{f.rule_id}` at `{f.path}`: {f.message}")
    elif cls == "BLOCK":
        lines += [
            "**This plugin is BLOCKED. Do not merge until blocking findings are resolved.**",
            "",
        ]
        for f in blocks[:10]:
            lines.append(f"- `{f.rule_id}` at `{f.path}`: {f.message}")
    elif cls == "AUDIT_ERROR":
        lines += [
            "**The audit did not complete successfully. Do not merge until the audit passes.**",
        ]
    lines.append("")
    lines.append(
        "_Note: A passing audit does not guarantee a plugin is safe. "
        "This audit performs static analysis only and cannot detect all threats._"
    )

    return "\n".join(lines)


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KiB"
    if n < 1024**3:
        return f"{n / 1024**2:.1f} MiB"
    return f"{n / 1024**3:.1f} GiB"


# ---------------------------------------------------------------------------
# Core audit logic
# ---------------------------------------------------------------------------


def download_zip(
    url: str, dest_path: str, policy: Optional[dict[str, Any]] = None
) -> str:
    """Download a ZIP from url to dest_path.  Returns SHA-256 hex."""
    return plugin_release_utils.bounded_stream_download(
        url,
        dest_path,
        session=_gh_session,
        kind="release",
        policy=policy,
    ).sha256


def _download_source_archive(
    owner: str,
    repo: str,
    commit_sha: str,
    dest_path: str | Path,
    policy: Optional[dict[str, Any]] = None,
) -> None:
    """Download the exact commit tarball without invoking repository code."""
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{commit_sha}"
    plugin_release_utils.bounded_stream_download(
        url,
        dest_path,
        session=_gh_session,
        kind="source",
        policy=policy,
    )


def _fetch_source_tree(
    owner: str,
    repo: str,
    commit_sha: str,
    destination: str | Path,
    policy: Optional[dict[str, Any]] = None,
) -> str:
    """Materialize an exact GitHub source archive without executing its contents."""
    destination_path = Path(destination)
    destination_path.mkdir(parents=True, exist_ok=True)
    archive_path = destination_path / "source.tar.gz"
    extracted_path = destination_path / "extracted"
    extracted_path.mkdir()
    effective_policy = policy if policy is not None else _default_policy()
    _download_source_archive(
        owner, repo, commit_sha, archive_path, policy=effective_policy
    )

    limits = effective_policy["archive"]
    file_count = 0
    total_size = 0
    top_levels: set[str] = set()
    seen_paths: set[str] = set()

    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            safe, reason = _is_safe_member_path(member.name)
            if not safe:
                raise ValueError(
                    f"Unsafe source archive member {member.name!r}: {reason}"
                )
            relative = PurePosixPath(member.name)
            if not relative.parts:
                continue
            top_levels.add(relative.parts[0])
            target = extracted_path.joinpath(*relative.parts)

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                # Git symlinks and other special entries are unnecessary for
                # dependency resolution and are never materialized.
                continue

            file_count += 1
            total_size += member.size
            if file_count > limits["max_files"]:
                raise ValueError("Source archive exceeds maximum file count")
            if member.size > limits["max_single_file_bytes"]:
                raise ValueError(f"Source archive member too large: {member.name}")
            if total_size > limits["max_uncompressed_bytes"]:
                raise ValueError("Source archive exceeds maximum uncompressed size")
            relative_key = relative.as_posix()
            if relative_key in seen_paths:
                raise ValueError(f"Duplicate source archive member: {member.name}")
            seen_paths.add(relative_key)

            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"Could not read source archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)

    if file_count == 0:
        raise ValueError("Source archive contains no regular files")
    if len(top_levels) == 1:
        source_root = extracted_path / next(iter(top_levels))
        if source_root.is_dir():
            return str(source_root)
    return str(extracted_path)


def _find_metadata_in_extracted(
    extract_dir: str, meta_file: str
) -> tuple[Optional[bytes], Optional[str]]:
    """Return first metadata file bytes/path from extracted ZIP, if present."""
    for root, _dirs, files in os.walk(extract_dir):
        if meta_file in files:
            fp = os.path.join(root, meta_file)
            rel = os.path.relpath(fp, extract_dir)
            try:
                with open(fp, "rb") as fh:
                    return fh.read(), rel
            except Exception:
                return None, rel
    return None, None


def _merge_findings_unique(existing: list[Finding], new_items: list[Finding]) -> None:
    """Append findings while preventing exact duplicates."""
    seen = {
        (
            f.rule_id,
            f.path,
            f.line,
            f.message,
            f.scanner,
        )
        for f in existing
    }
    for f in new_items:
        key = (f.rule_id, f.path, f.line, f.message, f.scanner)
        if key not in seen:
            existing.append(f)
            seen.add(key)


def build_audit_worklist(
    repository_urls: list[str],
    *,
    latest_only: bool = False,
    release_fetcher: Any = None,
    metadata_fetcher: Any = None,
) -> tuple[list[AuditWorkItem], list[AuditReport]]:
    """Build the complete deterministic eligible-release worklist."""
    if release_fetcher is None:
        release_fetcher = get_releases
    if metadata_fetcher is None:
        metadata_fetcher = get_repo_metadata
    worklist: list[AuditWorkItem] = []
    errors: list[AuditReport] = []
    canonical_urls = plugin_release_utils.sort_repository_urls(repository_urls)
    for repository in canonical_urls:
        owner, repo = parse_owner_repo(repository)
        try:
            metadata = metadata_fetcher(owner, repo)
            releases = release_fetcher(owner, repo)
            eligible = plugin_release_utils.ordered_eligible_releases(
                releases, allow_prerelease=True
            )
        except Exception as exc:
            errors.append(
                AuditReport(
                    repository=repository,
                    final_classification="AUDIT_ERROR",
                    completion_status="incomplete",
                    error_scope="repository",
                    errors=[f"Failed to enumerate repository releases: {exc}"],
                )
            )
            continue
        if latest_only:
            eligible = eligible[:1]
        if not eligible:
            errors.append(
                AuditReport(
                    repository=repository,
                    final_classification="AUDIT_ERROR",
                    completion_status="incomplete",
                    error_scope="repository",
                    errors=["No catalog-eligible releases found."],
                )
            )
            continue
        worklist.extend(
            AuditWorkItem(repository, release, metadata) for release in eligible
        )
    return worklist, errors


def select_audit_shard(
    worklist: list[AuditWorkItem], shard_count: int, shard_index: int
) -> list[AuditWorkItem]:
    """Select one deterministic SHA-256 shard from a complete worklist."""
    if shard_count <= 0:
        raise ValueError("shard_count must be greater than zero")
    if shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard_index must satisfy 0 <= index < shard_count")
    selected = []
    for item in worklist:
        repository_key = plugin_release_utils.canonical_repository_key(item.repository)
        release_id = str(item.release.get("id", ""))
        digest = hashlib.sha256(
            f"{repository_key}\0{release_id}".encode("utf-8")
        ).digest()
        if int.from_bytes(digest, "big") % shard_count == shard_index:
            selected.append(item)
    return selected


_RESUME_IDENTITY_FIELDS = (
    "repository",
    "github_release_id",
    "asset_id",
    "artifact_sha256",
    "resolved_tag_commit_sha",
    "audit_context_hash",
    "completion_status",
    "worklist_fingerprint",
)


def resume_identity_matches(
    candidate: dict[str, Any], expected: dict[str, Any]
) -> bool:
    """Return whether an exact completed audit identity may be resumed."""
    return (
        isinstance(candidate, dict)
        and candidate.get("completion_status") == "completed"
        and all(
            candidate.get(field) == expected.get(field)
            for field in _RESUME_IDENTITY_FIELDS
        )
    )


_RESUME_REPORT_REQUIRED_FIELDS = (
    "repository",
    "release",
    "release_id",
    "github_release_id",
    "asset_id",
    "artifact_url",
    "artifact_sha256",
    "identity_status",
    "resolved_tag_commit_sha",
    "audit_context_hash",
    "final_classification",
    "completion_status",
)

_AGGREGATE_REPORT_REQUIRED_FIELDS = (
    "repository",
    "release",
    "release_id",
    "github_release_id",
    "asset_id",
    "artifact_url",
    "artifact_sha256",
    "identity_status",
    "resolved_tag_commit_sha",
    "audit_context_hash",
    "final_classification",
    "completion_status",
)

_AGGREGATE_REPORT_COMPLETION_STATUSES = ("completed", "incomplete")
_IDENTITY_STATUS_VALUES = ("CURRENT", "STALE_HASH", "UNKNOWN")
_AGGREGATE_VERDICT_DELTA_REQUIRED_FIELDS = (
    "classification",
    "blocking_rule_ids",
    "review_rule_ids",
    "warning_rule_ids",
    "artifact_sha256",
    "audit_context_hash",
    "audited_at",
)
_AGGREGATE_VERDICT_DELTA_RELEASE_KEY = re.compile(r"^.+@[0-9]+$")


def _validate_aggregated_report_record(
    raw_report: dict[str, Any], report_path: str
) -> dict[str, Any]:
    """Validate and normalize one shard report record."""
    if not isinstance(raw_report, dict):
        raise ValueError(f"Invalid report record in {report_path}")

    completion_status = raw_report.get("completion_status", "incomplete")
    if completion_status not in _AGGREGATE_REPORT_COMPLETION_STATUSES:
        raise ValueError(f"Invalid completion status in {report_path}")

    repository = raw_report.get("repository")
    if not isinstance(repository, str):
        raise ValueError(f"Invalid repository in {report_path}")
    try:
        canonical = plugin_release_utils.canonicalize_github_repository_url(repository)
    except ValueError as exc:
        raise ValueError(f"Invalid repository in {report_path}") from exc
    raw_report["repository"] = canonical

    final_classification = raw_report.get("final_classification")
    if completion_status == "completed":
        missing = [
            field
            for field in _AGGREGATE_REPORT_REQUIRED_FIELDS
            if not isinstance(raw_report.get(field), str) or not raw_report.get(field)
        ]
        if missing:
            raise ValueError(
                f"Incomplete completed report in {report_path}: missing {', '.join(sorted(missing))}"
            )
        if final_classification not in RULE_CLASSIFICATION_VALUES:
            raise ValueError(
                f"Invalid completed report classification in {report_path}"
            )
        if raw_report["identity_status"] not in _IDENTITY_STATUS_VALUES:
            raise ValueError(f"Invalid identity status in {report_path}")
        if raw_report["identity_status"] != "CURRENT":
            raise ValueError(f"Non-current completed report in {report_path}")
        if not _CANONICAL_SHA256.fullmatch(raw_report["artifact_sha256"]):
            raise ValueError(f"Invalid completed artifact SHA-256 in {report_path}")
        expected_release_id = f"{raw_report['release']}@{raw_report['asset_id']}"
        if raw_report["release_id"] != expected_release_id:
            raise ValueError(
                f"Invalid completed release identity in {report_path}: "
                f"{raw_report['release_id']!r} != {expected_release_id!r}"
            )

    elif completion_status == "incomplete":
        final_classification = (
            final_classification if isinstance(final_classification, str) else ""
        )
        if final_classification not in RULE_CLASSIFICATION_VALUES | {"AUDIT_ERROR"}:
            raise ValueError(f"Invalid report classification in {report_path}")

    return raw_report


def _validate_aggregated_verdict_delta_record(
    repository: str,
    release_id: str,
    record: Any,
    delta_path: str,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError(
            f"Invalid verdict delta record in {delta_path}: {repository}/{release_id}"
        )
    extra_fields = set(record.keys()) - set(_AGGREGATE_VERDICT_DELTA_REQUIRED_FIELDS)
    if extra_fields:
        raise ValueError(
            f"Unexpected verdict delta field(s) in {delta_path}: "
            f"{', '.join(sorted(extra_fields))}"
        )
    missing = [
        field
        for field in _AGGREGATE_VERDICT_DELTA_REQUIRED_FIELDS
        if field not in record
    ]
    if missing:
        raise ValueError(
            f"Invalid verdict delta record in {delta_path}: missing {', '.join(sorted(missing))} for {repository}/{release_id}"
        )

    if not isinstance(
        release_id, str
    ) or not _AGGREGATE_VERDICT_DELTA_RELEASE_KEY.fullmatch(release_id):
        raise ValueError(
            f"Invalid verdict release key in {delta_path}: {repository}/{release_id}"
        )

    classification = record["classification"]
    if (
        not isinstance(classification, str)
        or classification not in RULE_CLASSIFICATION_VALUES
    ):
        raise ValueError(
            f"Invalid verdict delta classification in {delta_path}: {repository}/{release_id}"
        )
    for required_field in (
        "blocking_rule_ids",
        "review_rule_ids",
        "warning_rule_ids",
    ):
        rule_ids = record[required_field]
        if not isinstance(rule_ids, list) or not all(
            isinstance(rule_id, str) for rule_id in rule_ids
        ):
            raise ValueError(
                f"Invalid verdict delta {required_field} in {delta_path}: "
                f"{repository}/{release_id}"
            )

    for required_field in ("artifact_sha256", "audit_context_hash", "audited_at"):
        if not isinstance(record.get(required_field), str) or not record.get(
            required_field
        ):
            raise ValueError(
                f"Invalid verdict delta {required_field} in {delta_path}: "
                f"{repository}/{release_id}"
            )
    if not _CANONICAL_SHA256.fullmatch(record["artifact_sha256"]):
        raise ValueError(
            f"Invalid verdict delta artifact SHA-256 in {delta_path}: {repository}/{release_id}"
        )
    return record


def _normalize_verdict_delta(
    delta: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, dict[str, dict[str, Any]]]:
    normalized: dict[str, dict[str, dict[str, Any]]] = {}
    for repository, releases in delta.items():
        canonical = repository
        try:
            canonical = plugin_release_utils.canonicalize_github_repository_url(
                repository
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid repository key {repository!r} in verdict delta"
            ) from exc

        normalized_releases: dict[str, dict[str, Any]] = {}
        for release_id, record in sorted(releases.items(), key=lambda item: item[0]):
            normalized_releases[release_id] = {
                key: (sorted(value) if isinstance(value, list) else value)
                for key, value in sorted(record.items(), key=lambda item: item[0])
            }
        normalized[canonical] = normalized_releases

    return normalized


def _load_aggregate_shard_reports(report_path: str) -> list[AuditReport]:
    with open(report_path, encoding="utf-8") as report_file:
        payload = json.load(report_file)
    if not isinstance(payload, dict) or not isinstance(payload.get("reports"), list):
        raise ValueError(f"Invalid shard report: {report_path}")

    shard_reports: list[AuditReport] = []
    for raw_report in payload["reports"]:
        normalized_report = _validate_aggregated_report_record(raw_report, report_path)
        report = _dict_to_report(normalized_report)
        report.repository = normalized_report["repository"]
        shard_reports.append(report)
    return shard_reports


def _resumable_progress_report(
    candidate: dict[str, Any],
    expected: dict[str, Any],
    progress_key: str,
) -> Optional[AuditReport]:
    """Deserialize a checkpoint report only when its full identity is current."""
    if not resume_identity_matches(candidate, expected):
        return None

    expected_key = "\0".join(
        (
            expected["repository"],
            expected["github_release_id"],
            expected["asset_id"],
        )
    )
    if progress_key != expected_key:
        return None

    raw_report = candidate.get("report")
    if not isinstance(raw_report, dict) or any(
        field not in raw_report for field in _RESUME_REPORT_REQUIRED_FIELDS
    ):
        return None

    try:
        report = _dict_to_report(raw_report)
    except Exception:
        return None

    expected_report_identity = {
        "release": expected["release"],
        "release_id": expected["release_id"],
        "github_release_id": expected["github_release_id"],
        "asset_id": expected["asset_id"],
        "artifact_url": expected["artifact_url"],
        "artifact_sha256": expected["artifact_sha256"],
        "resolved_tag_commit_sha": expected["resolved_tag_commit_sha"],
        "audit_context_hash": expected["audit_context_hash"],
        "completion_status": "completed",
    }
    if report.repository != expected["repository"] or any(
        getattr(report, field) != value
        for field, value in expected_report_identity.items()
    ):
        return None
    if (
        report.identity_status != "CURRENT"
        or not isinstance(report.final_classification, str)
        or report.final_classification not in RULE_CLASSIFICATION_VALUES
    ):
        return None
    return report


def aggregate_audit_reports(report_paths: list[str]) -> list[AuditReport]:
    """Load deterministic shard reports and reject duplicate release identities."""
    reports: list[AuditReport] = []
    seen: set[tuple[str, str, str]] = set()
    for report_path in report_paths:
        for report in _load_aggregate_shard_reports(report_path):
            key = (report.repository, report.github_release_id, report.asset_id)
            if key in seen:
                raise ValueError(f"duplicate release identity in shard reports: {key}")
            seen.add(key)
            reports.append(report)
    reports.sort(
        key=lambda report: plugin_release_utils.release_order_key(
            {
                "published_at": report.release_published_at,
                "id": report.github_release_id,
                "assets": [{"id": report.asset_id, "name": "release.zip"}],
            }
        ),
        reverse=True,
    )
    reports.sort(key=lambda report: report.repository)
    return reports


def aggregate_verdict_deltas(
    delta_paths: list[str],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Merge isolated verdict deltas, rejecting duplicate or conflicting keys."""
    merged: dict[str, dict[str, dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for delta_path in delta_paths:
        with open(delta_path, encoding="utf-8") as delta_file:
            delta = json.load(delta_file)
        if not isinstance(delta, dict):
            raise ValueError(f"Invalid verdict delta: {delta_path}")
        for repository, releases in delta.items():
            canonical = plugin_release_utils.canonicalize_github_repository_url(
                repository
            )
            if not isinstance(releases, dict):
                raise ValueError(f"Invalid verdict delta repository: {repository}")
            for release_id, record in releases.items():
                key = (canonical, release_id)
                if key in seen:
                    raise ValueError(f"duplicate verdict key in shard deltas: {key}")
                record = _validate_aggregated_verdict_delta_record(
                    canonical,
                    release_id,
                    record,
                    delta_path,
                )
                seen.add(key)
                merged.setdefault(canonical, {})[release_id] = record
    return merged


def audit_repository(
    repo_url: str,
    policy: dict[str, Any],
    exceptions: list[dict[str, Any]],
    cache_dir: str = CACHE_DIR,
    skip_cache: bool = False,
    policy_path: Optional[str] = DEFAULT_POLICY_FILE,
    allowlist_path: Optional[str] = DEFAULT_ALLOWLIST_FILE,
) -> AuditReport:
    """Select the best release for a repository and audit that exact release."""
    report = AuditReport(
        audit_timestamp=datetime.datetime.now(datetime.UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        repository=repo_url.rstrip("/"),
    )

    try:
        owner, repo = parse_owner_repo(repo_url)
    except ValueError as exc:
        report.errors.append(str(exc))
        report.final_classification = "AUDIT_ERROR"
        return report

    # --- Repository metadata ---
    try:
        meta = get_repo_metadata(owner, repo)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            report.errors.append(f"Repository {owner}/{repo} not found.")
        else:
            report.errors.append(f"Failed to fetch repository metadata: {exc}")
        report.final_classification = "AUDIT_ERROR"
        return report
    except Exception as exc:
        report.errors.append(f"Failed to fetch repository metadata: {exc}")
        report.final_classification = "AUDIT_ERROR"
        return report

    try:
        releases = get_releases(owner, repo)
    except Exception as exc:
        report.errors.append(f"Failed to fetch releases: {exc}")
        report.final_classification = "AUDIT_ERROR"
        return report

    if not releases:
        report.errors.append(f"Repository {owner}/{repo} has no releases.")
        report.final_classification = "AUDIT_ERROR"
        return report

    release = find_best_release(releases)
    if release is None:
        report.errors.append(
            f"No eligible release found for {owner}/{repo} "
            "(all releases have zero or multiple ZIP assets)."
        )
        report.final_classification = "AUDIT_ERROR"
        return report

    return audit_release(
        repo_url,
        release,
        policy,
        exceptions,
        cache_dir,
        skip_cache,
        _repo_metadata=meta,
        _policy_path=policy_path,
        _allowlist_path=allowlist_path,
    )


_SCOPED_ARCHIVE_INSPECTION_EXCEPTIONS = (
    OSError,
    EOFError,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
)


def _redacted_exception_detail(exc: BaseException) -> str:
    """Return a bounded diagnostic safe for public audit outputs."""
    return redact_secrets(_truncate(str(exc), EVIDENCE_MAX_LEN))


def _combine_scanner_detail(
    base_detail: Optional[str], source_preparation_error: Optional[str]
) -> Optional[str]:
    """Build a bounded, redacted scanner detail that preserves original context."""
    detail_parts: list[str] = []
    if base_detail:
        detail_parts.append(base_detail)
    if source_preparation_error:
        detail_parts.append(
            f"source snapshot preparation failed: {source_preparation_error}"
        )
    if not detail_parts:
        return None
    return redact_secrets(_truncate("; ".join(detail_parts), EVIDENCE_MAX_LEN))


def _record_release_local_error(
    report: AuditReport,
    *,
    label: str,
    status_name: str,
    exc: BaseException,
) -> AuditReport:
    """Complete one release-local error report without creating a verdict."""
    detail = _redacted_exception_detail(exc)
    report.errors.append(f"{label}: {detail}")
    report.scanner_statuses.append(
        ScannerStatus(name=status_name, status="failed", detail=detail)
    )
    report.final_classification = "AUDIT_ERROR"
    report.identity_status = "CURRENT" if report.artifact_sha256 else "UNKNOWN"
    report.completion_status = "incomplete"
    report.error_scope = "release"
    return report


def audit_release(
    repo_url: str,
    release: dict[str, Any],
    policy: dict[str, Any],
    exceptions: list[dict[str, Any]],
    cache_dir: str = CACHE_DIR,
    skip_cache: bool = False,
    *,
    _repo_metadata: Optional[dict[str, Any]] = None,
    _policy_path: Optional[str] = DEFAULT_POLICY_FILE,
    _allowlist_path: Optional[str] = DEFAULT_ALLOWLIST_FILE,
    _persist_verdict: bool = True,
) -> AuditReport:
    """Audit exactly one supplied plugin release without selecting another."""
    report = AuditReport(
        audit_timestamp=datetime.datetime.now(datetime.UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        repository=repo_url.rstrip("/"),
    )

    try:
        owner, repo = parse_owner_repo(repo_url)
    except ValueError as exc:
        report.errors.append(str(exc))
        return report

    tag_name = release.get("tag_name", "")
    report.release = tag_name

    zips = [
        asset
        for asset in (release.get("assets") or [])
        if asset.get("name", "").lower().endswith(".zip")
    ]
    if len(zips) != 1:
        report.errors.append(f"Expected exactly one ZIP asset; found {len(zips)}.")
        return report

    asset = zips[0]
    report.release_id = f"{tag_name}@{asset.get('id', '')}"
    report.github_release_id = str(release.get("id", ""))
    report.asset_id = str(asset.get("id", ""))
    report.release_published_at = str(
        release.get("published_at") or release.get("created_at") or ""
    )
    report.artifact_url = asset.get("browser_download_url", "")
    github_artifact_sha256 = plugin_release_utils.normalize_github_sha256_digest(
        asset.get("digest")
    )
    report.artifact_sha256 = github_artifact_sha256 or ""

    try:
        meta = (
            _repo_metadata
            if _repo_metadata is not None
            else get_repo_metadata(owner, repo)
        )
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            report.errors.append(f"Repository {owner}/{repo} not found.")
        else:
            report.errors.append(f"Failed to fetch repository metadata: {exc}")
        return report
    except Exception as exc:
        report.errors.append(f"Failed to fetch repository metadata: {exc}")
        return report

    if meta.get("archived"):
        report.errors.append(f"Repository {owner}/{repo} is archived.")

    commit_sha, _tree_sha, tag_err = _resolve_ref_to_commit_and_tree_sha(
        owner, repo, tag_name
    )
    if not commit_sha:
        report.errors.append(
            f"Failed to resolve ref {tag_name} to commit SHA: {tag_err or 'unknown error'}"
        )
        report.final_classification = "AUDIT_ERROR"
        return report

    resolved_tag_commit_sha = commit_sha
    report.resolved_tag_commit_sha = resolved_tag_commit_sha
    artifact_url = report.artifact_url

    plugin_meta_data: Optional[bytes] = None
    plugin_meta_path = f"plugin.json@{tag_name}"
    package_meta_data: Optional[bytes] = None
    package_meta_path = f"package.json@{tag_name}"
    report.plugin_name = repo

    # --- Cache check ---
    release_id = report.release_id

    scanner_identities = _scanner_runtime_identities(policy)
    audit_ctx_hash = compute_audit_context_hash(
        policy,
        exceptions,
        policy_path=_policy_path,
        allowlist_path=_allowlist_path,
        scanner_identities=scanner_identities,
    )
    report.audit_context_hash = audit_ctx_hash
    scheduled_cache_requires_freshness = os.environ.get("AUDIT_SCHEDULED") == "1"
    cache_bypassed = skip_cache or (
        scheduled_cache_requires_freshness
        and not _scanner_database_freshness_available(policy, scanner_identities)
    )
    if cache_bypassed and not skip_cache:
        log.warning(
            "Scheduled report cache bypassed because scanner database freshness "
            "could not be established."
        )

    if not cache_bypassed and github_artifact_sha256:
        cached = load_cached_report_predownload(
            cache_dir=cache_dir,
            repository=repo_url,
            release_id=release_id,
            audit_context_hash=audit_ctx_hash,
            resolved_tag_commit_sha=resolved_tag_commit_sha,
        )
        if cached and cached.artifact_sha256 == github_artifact_sha256:
            cached.github_release_id = report.github_release_id
            cached.asset_id = report.asset_id
            cached.release_published_at = report.release_published_at
            cached.identity_status = "CURRENT"
            cached.completion_status = "completed"
            if _persist_verdict:
                _record_verdict(cache_dir, cached)
            return cached

    # --- Download ZIP ---
    tmp_dir = tempfile.mkdtemp(prefix="decky-audit-")
    zip_path = os.path.join(tmp_dir, "release.zip")
    extract_dir = os.path.join(tmp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        try:
            artifact_sha256 = download_zip(artifact_url, zip_path, policy=policy)
        except (
            OSError,
            requests.RequestException,
            plugin_release_utils.DownloadLimitError,
        ) as exc:
            return _record_release_local_error(
                report,
                label="Failed to download release artifact",
                status_name="release-download",
                exc=exc,
            )

        report.artifact_sha256 = artifact_sha256
        if github_artifact_sha256 and artifact_sha256 != github_artifact_sha256:
            report.errors.append(
                "Downloaded artifact SHA-256 does not match GitHub's release digest."
            )
            report.final_classification = "AUDIT_ERROR"
            return report

        # --- Cache check with known SHA ---
        if not cache_bypassed:
            cached = load_cached_report(
                cache_dir,
                repo_url,
                release_id,
                artifact_sha256,
                audit_context_hash=audit_ctx_hash,
                resolved_tag_commit_sha=resolved_tag_commit_sha,
            )
            if cached:
                cached.github_release_id = report.github_release_id
                cached.asset_id = report.asset_id
                cached.release_published_at = report.release_published_at
                cached.identity_status = "CURRENT"
                cached.completion_status = "completed"
                if _persist_verdict:
                    _record_verdict(cache_dir, cached)
                return cached

        # --- ZIP inspection ---
        source_snapshot: Optional[audit_source_snapshot.SourceSnapshot] = None
        source_preparation_error: Optional[str] = None
        try:
            source_snapshot = audit_source_snapshot.materialize_source_snapshot(
                repo_url,
                resolved_tag_commit_sha,
                os.path.join(tmp_dir, "source"),
                session=_gh_session,
                policy=policy,
            )
            if source_snapshot.plugin_json is not None:
                plugin_meta_data = source_snapshot.plugin_json
            if source_snapshot.package_json is not None:
                package_meta_data = source_snapshot.package_json
        except Exception as exc:
            source_preparation_error = _redacted_exception_detail(exc)
            report.findings.append(
                Finding(
                    rule_id="SOURCE_ARTIFACT_PREPARATION_FAILED",
                    severity="low",
                    classification="PASS_WITH_WARNINGS",
                    path="",
                    line=0,
                    message="Source snapshot could not be prepared from tag commit.",
                    evidence=source_preparation_error,
                    scanner="source-snapshot",
                )
            )

        try:
            zip_stats, zip_findings = inspect_zip(zip_path, policy)
        except _SCOPED_ARCHIVE_INSPECTION_EXCEPTIONS as exc:
            return _record_release_local_error(
                report,
                label="Archive inspection failed",
                status_name="zip-inspector",
                exc=exc,
            )
        report.archive_stats = zip_stats
        report.findings.extend(zip_findings)

        if any(finding.rule_id == "CORRUPT_ARCHIVE" for finding in zip_findings):
            report.errors.append("Archive inspection could not complete: corrupt ZIP.")

        if not zip_stats.safe:
            # If archive is fundamentally unsafe, report without extracting
            log.warning(
                "Archive for %s failed safety checks; skipping extraction.", repo_url
            )

        # --- Safe extraction ---
        if zip_stats.safe:
            try:
                safe_extract_zip(zip_path, extract_dir)
            except Exception as exc:
                report.errors.append(
                    f"Extraction failed: {_redacted_exception_detail(exc)}"
                )
                zip_stats.safe = False

        # --- Walk extracted content ---
        all_urls: list[str] = []
        all_domains: set[str] = set()

        if zip_stats.safe and os.path.isdir(extract_dir):
            for root, _dirs, files in os.walk(extract_dir):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(full_path, extract_dir)
                    ext = os.path.splitext(fname)[1].lower()

                    try:
                        with open(full_path, "rb") as fh:
                            raw = fh.read()
                    except Exception:
                        continue

                    # Binary detection
                    bin_info = identify_binary(raw[:16], rel_path)
                    if bin_info:
                        report.native_binaries.append(bin_info)
                        report.findings.append(
                            Finding(
                                rule_id="NATIVE_BINARY",
                                severity="medium",
                                classification="MANUAL_REVIEW",
                                path=rel_path,
                                line=0,
                                message=f"Native binary: {bin_info['label']} ({bin_info.get('architecture', 'unknown arch')})",
                                evidence=bin_info["label"],
                                scanner="binary-detector",
                            )
                        )
                        continue  # Don't try to parse as text

                    # Text analysis
                    try:
                        content = raw.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    # Static source-behaviour rules do not apply to generated data
                    # formats. Secrets still scan below because source maps and JSON
                    # can embed credentials or original source text.
                    if ext in _NON_SCRIPT_GENERATED_EXTENSIONS:
                        skipped = zip_stats.static_scan_skipped_extensions
                        skipped[ext] = skipped.get(ext, 0) + 1
                    else:
                        text_findings = scan_text_content(content, rel_path, ext)
                        report.findings.extend(text_findings)

                    # Secrets
                    secret_findings = scan_for_secrets(content, rel_path)
                    report.findings.extend(secret_findings)

                    # URLs and domains
                    urls, domains = extract_urls_and_domains(content)
                    all_urls.extend(urls)
                    all_domains.update(domains)

        report.extracted_domains = sorted(all_domains)

        trivy_source_enabled = _scanner_enabled(policy, "trivy")

        # --- Metadata fallback from ZIP when missing at tag ---
        zip_plugin_json, zip_plugin_rel = _find_metadata_in_extracted(
            extract_dir, "plugin.json"
        )
        zip_package_json, zip_package_rel = _find_metadata_in_extracted(
            extract_dir, "package.json"
        )
        if plugin_meta_data is None and zip_plugin_json is not None:
            plugin_meta_data = zip_plugin_json
            plugin_meta_path = zip_plugin_rel or "plugin.json"
        if package_meta_data is None and zip_package_json is not None:
            package_meta_data = zip_package_json
            package_meta_path = zip_package_rel or "package.json"

        try:
            pj_data, pj_findings = check_plugin_json(plugin_meta_data, plugin_meta_path)
            pkg_data, pkg_findings = check_package_json(
                package_meta_data, package_meta_path
            )
            _merge_findings_unique(report.findings, pj_findings)
            _merge_findings_unique(report.findings, pkg_findings)
            report.plugin_name = (
                (pj_data.get("name") or "")
                or (pkg_data.get("name") or "")
                or report.plugin_name
                or repo
            )
        except Exception as exc:
            report.errors.append(f"Failed to process release metadata: {exc}")

        if plugin_meta_data is None and package_meta_data is None:
            report.findings.append(
                Finding(
                    rule_id="MISSING_RELEASE_METADATA",
                    severity="low",
                    classification="PASS_WITH_WARNINGS",
                    path="plugin.json,package.json",
                    line=0,
                    message=(
                        f"Metadata unavailable for {owner}/{repo}@{tag_name}: neither tagged-source "
                        "nor ZIP plugin.json/package.json was found."
                    ),
                    evidence="",
                    scanner="metadata-checker",
                )
            )

        _downgrade_plugin_namespaced_env_findings(report.findings, report.plugin_name)

        # --- External scanners ---
        if zip_stats.safe and os.path.isdir(extract_dir):
            trivy_status, trivy_findings = run_trivy(
                extract_dir,
                policy,
                source_root=(
                    source_snapshot.source_root if source_snapshot is not None else None
                ),
            )
            if source_preparation_error is not None and trivy_source_enabled:
                trivy_status = ScannerStatus(
                    name="trivy",
                    status="failed",
                    detail=_combine_scanner_detail(
                        trivy_status.detail,
                        source_preparation_error,
                    ),
                )
            report.scanner_statuses.append(trivy_status)
            report.findings.extend(trivy_findings)

            clam_status, clam_findings = run_clamav(extract_dir, policy)
            report.scanner_statuses.append(clam_status)
            report.findings.extend(clam_findings)

            semgrep_status, semgrep_findings = run_semgrep(extract_dir, policy)
            report.scanner_statuses.append(semgrep_status)
            report.findings.extend(semgrep_findings)

            # Source/artifact comparison
            if _scanner_enabled(policy, "source-artifact-diff"):
                if source_preparation_error is None and source_snapshot is not None:
                    diff_summary, diff_findings, diff_status = (
                        compare_source_and_artifact_from_snapshot(
                            extract_dir,
                            source_snapshot,
                            tag_name,
                        )
                    )
                else:
                    diff_summary = {"ref": tag_name, "checked": False}
                    diff_findings: list[Finding] = []
                    diff_status = ScannerStatus(
                        name="source-artifact-diff",
                        status="failed",
                        detail=_combine_scanner_detail(
                            None
                            if source_preparation_error is not None
                            else "Source-artifact snapshot is missing.",
                            source_preparation_error,
                        ),
                    )
            else:
                diff_summary, diff_findings, diff_status = (
                    {"ref": tag_name, "checked": False},
                    [],
                    ScannerStatus(name="source-artifact-diff", status="skipped"),
                )
            report.source_artifact_diff = diff_summary
            report.scanner_statuses.append(diff_status)
            report.findings.extend(diff_findings)
            if diff_status.status in (
                "failed",
                "unavailable",
                "unsupported",
            ) and not _scanner_required(policy, "source-artifact-diff"):
                report.findings.append(
                    Finding(
                        rule_id="SOURCE_ARTIFACT_DIFF_INCOMPLETE",
                        severity="low",
                        classification="PASS_WITH_WARNINGS",
                        path="",
                        line=0,
                        message=diff_status.detail
                        or "Source/artifact comparison did not complete.",
                        evidence="",
                        scanner="source-artifact-diff",
                    )
                )
        else:
            for scanner_name in ("trivy", "clamav", "semgrep", "source-artifact-diff"):
                report.scanner_statuses.append(
                    ScannerStatus(
                        name=scanner_name,
                        status="unavailable",
                        detail="Extraction failed; scanner skipped.",
                    )
                )

        # Overrides run first; the structural ceiling then prevents behavioural
        # rules from escalating above MANUAL_REVIEW. Findings remain intact.
        apply_rule_classification_policy(report.findings, policy)

        # --- Apply allowlist ---
        report.findings, report.allowlist_decisions = apply_allowlist(
            report.findings,
            exceptions,
            repo_url,
            tag_name,
            artifact_sha256,
            policy=policy,
        )

        # --- Final classification ---
        has_error = bool(report.errors)
        report.final_classification, report.risk_score = classify_findings(
            report.findings,
            has_error=has_error,
            scanner_statuses=report.scanner_statuses,
            policy=policy,
        )
        report.identity_status = "CURRENT" if report.artifact_sha256 else "UNKNOWN"
        report.completion_status = (
            "completed"
            if report.final_classification != "AUDIT_ERROR"
            else "incomplete"
        )

        # --- Cache result ---
        if report.final_classification != "AUDIT_ERROR" and not cache_bypassed:
            save_cached_report(
                cache_dir,
                report,
                release_id,
                audit_context_hash=audit_ctx_hash,
                resolved_tag_commit_sha=resolved_tag_commit_sha,
            )
        if _persist_verdict:
            _record_verdict(cache_dir, report)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return report


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------


def _run_summary_stats(
    reports: list[AuditReport],
) -> tuple[Counter[str], list[tuple[str, int]]]:
    classifications = Counter(report.final_classification for report in reports)
    rule_counts: Counter[str] = Counter()
    for report in reports:
        rule_counts.update(
            {finding.rule_id for finding in report.findings if finding.rule_id}
        )
    top_rules = sorted(rule_counts.items(), key=lambda item: (-item[1], item[0]))[:10]
    return classifications, top_rules


def rank_review_queue(
    verdicts: dict[str, dict[str, dict[str, Any]]],
) -> list[ReviewQueueEntry]:
    """Rank releases by inverse corpus rule frequency without changing verdicts."""
    releases: list[tuple[str, str, set[str]]] = []
    for repository, repository_verdicts in sorted(verdicts.items()):
        for release_id, record in sorted(repository_verdicts.items()):
            rule_ids: set[str] = set()
            for field_name in (
                "blocking_rule_ids",
                "review_rule_ids",
                "warning_rule_ids",
            ):
                values = record.get(field_name, [])
                if isinstance(values, list):
                    rule_ids.update(
                        value for value in values if isinstance(value, str) and value
                    )
            releases.append((repository, release_id, rule_ids))

    total_releases = len(releases)
    if not total_releases:
        return []

    frequencies: Counter[str] = Counter()
    for _repository, _release_id, rule_ids in releases:
        frequencies.update(rule_ids)

    ranked = [
        ReviewQueueEntry(
            repository=repository,
            release_id=release_id,
            score=math.fsum(
                math.log(total_releases / frequencies[rule_id])
                for rule_id in sorted(rule_ids)
            ),
            rarest_rules=tuple(
                sorted(
                    ((rule_id, frequencies[rule_id]) for rule_id in rule_ids),
                    key=lambda item: (item[1], item[0]),
                )[:3]
            ),
        )
        for repository, release_id, rule_ids in releases
    ]
    return sorted(
        ranked,
        key=lambda entry: (-entry.score, entry.repository, entry.release_id),
    )


def generate_run_summary(
    reports: list[AuditReport],
    verdicts: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
) -> str:
    """Return aggregate tallies and a reporting-only rarity-ranked review queue."""
    classifications, top_rules = _run_summary_stats(reports)
    lines = [
        "## Audit Run Summary",
        "",
        f"Total releases audited: **{len(reports)}**",
        "",
        "| Classification | Count |",
        "|---|---:|",
    ]
    for classification in CLASSIFICATION_ORDER:
        lines.append(f"| {classification} | {classifications[classification]} |")

    lines.extend(
        [
            "",
            "| Top rule ID | Releases | Firing rate |",
            "|---|---:|---:|",
        ]
    )
    total = len(reports)
    for rule_id, count in top_rules:
        rate = count / total * 100 if total else 0
        lines.append(f"| {rule_id} | {count} | {rate:.2f}% |")
    if not top_rules:
        lines.append("| None | 0 | 0.00% |")

    verdict_store = load_verdicts() if verdicts is None else verdicts
    ranked_releases = rank_review_queue(verdict_store)
    total_ranked = len(ranked_releases)
    lines.extend(
        [
            "",
            "### Review queue by rarity (reporting only)",
            "",
            (
                "Rarity scores prioritize review; they never alter a finding or "
                "release classification."
            ),
            "",
            "| Rank | Release | Score | Rarest contributing rules |",
            "|---:|---|---:|---|",
        ]
    )
    for rank, entry in enumerate(ranked_releases[:10], start=1):
        repository = entry.repository.removeprefix("https://github.com/")
        rarest = ", ".join(
            f"{rule_id} ({frequency}/{total_ranked})"
            for rule_id, frequency in entry.rarest_rules
        )
        lines.append(
            f"| {rank} | `{repository}` `{entry.release_id}` | "
            f"{entry.score:.1f} | {rarest or 'None'} |"
        )
    if not ranked_releases:
        lines.append("| - | None | 0.0 | None |")

    return "\n".join(lines) + "\n"


def _atomic_write_text(path: str | Path, content: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _report_identity_key(report: AuditReport) -> str:
    return "\0".join((report.repository, report.github_release_id, report.asset_id))


def _progress_record(
    report: AuditReport, worklist_fingerprint: Optional[str] = None
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "repository": report.repository,
        "github_release_id": report.github_release_id,
        "asset_id": report.asset_id,
        "artifact_sha256": report.artifact_sha256,
        "resolved_tag_commit_sha": report.resolved_tag_commit_sha,
        "audit_context_hash": report.audit_context_hash,
        "completion_status": report.completion_status,
        "report": _report_to_dict(report),
    }
    if worklist_fingerprint is not None:
        normalized = _normalise_worklist_fingerprint(
            worklist_fingerprint, "worklist_fingerprint"
        )
        record["worklist_fingerprint"] = normalized
    return record


def _normalise_positive_decimal_id(value: Any, field_name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}: {value!r}")
    if not value or not _CANONICAL_POSITIVE_DECIMAL.fullmatch(value):
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_progress_identity_key(key: str) -> tuple[str, str, str]:
    if not isinstance(key, str):
        raise ValueError("Invalid progress manifest")
    parts = key.split("\0")
    if len(parts) != 3:
        raise ValueError("Invalid progress manifest")
    identity = _normalise_manifest_identity(
        {
            "repository": parts[0],
            "github_release_id": parts[1],
            "asset_id": parts[2],
        }
    )
    return identity["repository"], identity["github_release_id"], identity["asset_id"]


def _normalise_progress_record(
    identity_key: str, value: Mapping[str, Any], expected_fingerprint: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("Invalid progress manifest")
    if not isinstance(value.get("report"), dict):
        raise ValueError("Invalid progress manifest")
    value_fingerprint = value.get("worklist_fingerprint")
    if value_fingerprint != expected_fingerprint:
        raise ValueError("Invalid progress manifest")

    repository, github_release_id, asset_id = _normalise_progress_identity_key(
        identity_key
    )
    if set(value.keys()) != _WORKER_PROGRESS_RECORD_KEYS_V2:
        raise ValueError("Invalid progress manifest")

    repository_value = _normalise_str(value["repository"], "repository")
    if repository_value != repository:
        raise ValueError("Invalid progress manifest")

    if value.get("github_release_id") != github_release_id:
        raise ValueError("Invalid progress manifest")
    if value.get("asset_id") != asset_id:
        raise ValueError("Invalid progress manifest")

    _normalise_positive_decimal_id(value["github_release_id"], "github_release_id")
    _normalise_positive_decimal_id(value["asset_id"], "asset_id")

    if not isinstance(value.get("artifact_sha256"), str):
        raise ValueError("Invalid progress manifest")
    if (
        not _CANONICAL_SHA256.fullmatch(value["artifact_sha256"])
        and value["artifact_sha256"]
    ):
        raise ValueError("Invalid progress manifest")
    if not isinstance(value.get("resolved_tag_commit_sha"), str):
        raise ValueError("Invalid progress manifest")
    audit_context_hash = _normalise_str(
        value["audit_context_hash"], "audit_context_hash"
    )
    if not audit_context_hash:
        raise ValueError("Invalid progress manifest")

    completion_status = value.get("completion_status")
    if completion_status not in {"completed", "incomplete"}:
        raise ValueError("Invalid progress manifest")

    return {
        **value,
        "repository": repository,
        "github_release_id": github_release_id,
        "asset_id": asset_id,
        "audit_context_hash": audit_context_hash,
    }


def _write_progress_manifest(
    path: str | Path,
    records: dict[str, dict[str, Any]],
    worklist_fingerprint: Optional[str] = None,
) -> None:
    if worklist_fingerprint is not None:
        normalized_fingerprint = _normalise_worklist_fingerprint(
            worklist_fingerprint, "worklist_fingerprint"
        )
        normalized_records = {
            key: {
                **_normalise_progress_record(
                    key,
                    {
                        **value,
                        "worklist_fingerprint": normalized_fingerprint,
                    },
                    normalized_fingerprint,
                ),
                "worklist_fingerprint": normalized_fingerprint,
            }
            for key, value in records.items()
        }
        payload = {
            "schema_version": _WORKER_PROGRESS_SCHEMA_V2,
            "worklist_fingerprint": normalized_fingerprint,
            "entries": normalized_records,
        }
    else:
        payload = {"schema_version": "1", "entries": records}
    _atomic_write_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def _normalise_worklist_fingerprint(
    value: Any, field_name: str = "worklist_fingerprint"
) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid {field_name}: {value!r}")
    if not _CANONICAL_SHA256.fullmatch(value):
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _load_progress_manifest(
    path: str | Path, expected_worklist_fingerprint: Optional[str] = None
) -> dict[str, dict[str, Any]]:
    if not Path(path).is_file():
        return {}

    expected_fingerprint = (
        None
        if expected_worklist_fingerprint is None
        else _normalise_worklist_fingerprint(expected_worklist_fingerprint)
    )

    with open(path, encoding="utf-8") as progress_file:
        payload = json.load(progress_file)

    if not isinstance(payload, dict):
        raise ValueError(f"Invalid progress manifest: {path}")
    if expected_fingerprint is None:
        if payload.get("schema_version") != "1":
            raise ValueError(f"Invalid progress manifest: {path}")
        if not isinstance(payload.get("entries"), dict):
            raise ValueError(f"Invalid progress manifest: {path}")
        return payload["entries"]

    if payload.get("schema_version") == "1":
        return {}
    if payload.get("schema_version") != _WORKER_PROGRESS_SCHEMA_V2:
        raise ValueError(f"Invalid progress manifest: {path}")
    if set(payload.keys()) != _WORKER_PROGRESS_ROOT_KEYS_V2:
        raise ValueError(f"Invalid progress manifest: {path}")
    if not isinstance(payload.get("entries"), dict):
        raise ValueError(f"Invalid progress manifest: {path}")

    normalized_root_fingerprint = _normalise_worklist_fingerprint(
        payload["worklist_fingerprint"], "worklist_fingerprint"
    )

    entries: dict[str, dict[str, Any]] = {}
    for key, value in payload["entries"].items():
        entries[key] = _normalise_progress_record(
            key,
            value,
            normalized_root_fingerprint,
        )

    if normalized_root_fingerprint != expected_fingerprint:
        return {}
    return entries


def _normalise_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Invalid {field_name}: {value!r}")
    return value


def _normalise_manifest_identity(raw: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ValueError("Manifest identity must be an object")
    provided = set(raw.keys())
    if provided != _SHARD_MANIFEST_IDENTITY_KEYS:
        extras = ", ".join(sorted(provided - _SHARD_MANIFEST_IDENTITY_KEYS))
        missing = ", ".join(sorted(_SHARD_MANIFEST_IDENTITY_KEYS - provided))
        if extras and missing:
            raise ValueError(f"Unexpected identity keys: {extras}; missing: {missing}")
        if extras:
            raise ValueError(f"Unexpected identity keys: {extras}")
        raise ValueError(f"Missing identity keys: {missing}")

    repository = plugin_release_utils.canonicalize_github_repository_url(
        _normalise_str(raw["repository"], "repository")
    )
    if raw["repository"] != repository:
        raise ValueError("Repository URL is not canonical")
    github_release_id = _normalise_positive_decimal_id(
        raw["github_release_id"], "github_release_id"
    )
    asset_id = _normalise_positive_decimal_id(raw["asset_id"], "asset_id")
    return {
        "repository": repository,
        "github_release_id": github_release_id,
        "asset_id": asset_id,
    }


def _normalise_manifest_identities(
    identities: Any, field_name: str
) -> list[dict[str, str]]:
    if not isinstance(identities, list):
        raise ValueError(f"{field_name} must be a list")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in identities:
        normalized_entry = _normalise_manifest_identity(entry)
        key = (
            normalized_entry["repository"],
            normalized_entry["github_release_id"],
            normalized_entry["asset_id"],
        )
        if key in seen:
            raise ValueError(f"Duplicate identity in {field_name}")
        seen.add(key)
        normalized.append(normalized_entry)
    return normalized


def _shard_index_for_manifest_identity(
    identity: Mapping[str, str], shard_count: int
) -> int:
    repository_key = plugin_release_utils.canonical_repository_key(
        identity["repository"]
    )
    release_id = identity["github_release_id"]
    digest = hashlib.sha256(f"{repository_key}\0{release_id}".encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % shard_count


def _normalise_shard_manifest(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("Shard manifest must be an object")

    required = set(_SHARD_MANIFEST_ROOT_KEYS)
    provided = set(raw.keys())
    if provided != required:
        extras = ", ".join(sorted(provided - required))
        missing = ", ".join(sorted(required - provided))
        if extras and missing:
            raise ValueError(
                f"Unexpected shard manifest keys: {extras}; missing: {missing}"
            )
        if extras:
            raise ValueError(f"Unexpected shard manifest keys: {extras}")
        raise ValueError(f"Missing shard manifest keys: {missing}")

    schema_version = raw["schema_version"]
    if not isinstance(schema_version, str) or not schema_version:
        raise ValueError("Invalid schema_version")
    if schema_version != _SHARD_MANIFEST_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported shard manifest schema version: {schema_version!r}"
        )
    worklist_fingerprint = _normalise_worklist_fingerprint(
        raw["worklist_fingerprint"], "worklist_fingerprint"
    )
    source_revision = raw["source_revision"]
    if not isinstance(source_revision, str) or not source_revision:
        raise ValueError("Invalid source_revision")
    if not _CANONICAL_GIT_SHA1.fullmatch(source_revision):
        raise ValueError(f"Invalid source_revision: {source_revision!r}")
    shard_count = _normalise_positive_int(raw["shard_count"], "shard_count")
    shard_index = _normalise_non_negative_int(raw["shard_index"], "shard_index")
    if shard_index >= shard_count:
        raise ValueError("shard_index must satisfy 0 <= index < shard_count")

    assigned = _normalise_manifest_identities(
        raw["assigned_identities"], "assigned_identities"
    )
    attempted = _normalise_manifest_identities(
        raw["attempted_identities"], "attempted_identities"
    )
    report = _normalise_manifest_identities(
        raw["report_identities"], "report_identities"
    )

    assigned_set = {
        (identity["repository"], identity["github_release_id"], identity["asset_id"])
        for identity in assigned
    }
    attempted_set = {
        (identity["repository"], identity["github_release_id"], identity["asset_id"])
        for identity in attempted
    }
    report_set = {
        (identity["repository"], identity["github_release_id"], identity["asset_id"])
        for identity in report
    }

    if not attempted_set.issubset(assigned_set):
        raise ValueError("attempted_identities must be a subset of assigned_identities")
    if not report_set.issubset(assigned_set):
        raise ValueError("report_identities must be a subset of assigned_identities")
    if report != attempted:
        raise ValueError("report_identities must equal attempted_identities")

    for identity in assigned:
        if _shard_index_for_manifest_identity(identity, shard_count) != shard_index:
            raise ValueError(
                "assigned_identities include an identity not assigned to this shard"
            )

    return {
        "schema_version": schema_version,
        "worklist_fingerprint": worklist_fingerprint,
        "source_revision": source_revision,
        "shard_count": shard_count,
        "shard_index": shard_index,
        "assigned_identities": assigned,
        "attempted_identities": attempted,
        "report_identities": report,
    }


def _write_shard_manifest(path: str | Path, manifest: Mapping[str, Any]) -> None:
    normalised = _normalise_shard_manifest(manifest)
    _atomic_write_text(
        path,
        json.dumps(normalised, indent=2, sort_keys=True) + "\n",
    )


def _load_shard_manifest(path: str | Path) -> dict[str, Any]:
    if not Path(path).is_file():
        raise ValueError(f"Shard manifest not found: {path}")
    with open(path, encoding="utf-8") as manifest_file:
        payload = json.load(manifest_file)
    return _normalise_shard_manifest(payload)


def _validate_expected_shard_manifest(
    manifest: Mapping[str, Any],
    worklist: Mapping[str, Any],
    shard_index: int,
) -> dict[str, Any]:
    normalised_manifest = _normalise_shard_manifest(manifest)

    worklist_fingerprint = worklist.get("fingerprint")
    if worklist_fingerprint is not None:
        worklist_fingerprint = _normalise_worklist_fingerprint(
            worklist_fingerprint, "worklist_fingerprint"
        )
    else:
        raise ValueError("Invalid expected worklist")

    payload = worklist.get("payload")
    if not isinstance(payload, Mapping):
        raise ValueError("Invalid expected worklist")

    source_revision = _normalise_str(payload["source_revision"], "source_revision")
    shard_count = _normalise_positive_int(payload["shard_count"], "shard_count")
    if not isinstance(shard_index, int) or shard_index < 0:
        raise ValueError("Invalid shard_index")

    expected_assigned = [
        audit_worklist.worklist_identity(item)
        for item in audit_worklist.select_worklist_shard(payload, shard_index)
    ]

    if normalised_manifest["worklist_fingerprint"] != worklist_fingerprint:
        raise ValueError("Invalid shard manifest: worklist_fingerprint mismatch")
    if normalised_manifest["source_revision"] != source_revision:
        raise ValueError("Invalid shard manifest: source_revision mismatch")
    if normalised_manifest["shard_count"] != shard_count:
        raise ValueError("Invalid shard manifest: shard_count mismatch")
    if normalised_manifest["shard_index"] != shard_index:
        raise ValueError("Invalid shard manifest: shard_index mismatch")
    if normalised_manifest["assigned_identities"] != expected_assigned:
        raise ValueError("Invalid shard manifest: assigned_identities mismatch")

    return normalised_manifest


def _verdict_delta_from_reports(
    reports: list[AuditReport],
) -> dict[str, dict[str, dict[str, Any]]]:
    delta: dict[str, dict[str, dict[str, Any]]] = {}
    for report in reports:
        if report.completion_status != "completed" or not report.release_id:
            continue
        repository = plugin_release_utils.canonicalize_github_repository_url(
            report.repository
        )
        delta.setdefault(repository, {})[report.release_id] = {
            "classification": report.final_classification,
            "blocking_rule_ids": _blocking_rule_ids(report),
            "review_rule_ids": _rationale_rule_ids(report, "MANUAL_REVIEW"),
            "warning_rule_ids": _rationale_rule_ids(report, "PASS_WITH_WARNINGS"),
            "artifact_sha256": report.artifact_sha256,
            "audit_context_hash": report.audit_context_hash,
            "audited_at": report.audit_timestamp,
        }
    return delta


def write_reports(
    reports: list[AuditReport],
    output_dir: str,
    *,
    verdicts: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
) -> tuple[str, str]:
    """Write JSON and Markdown aggregate reports to output_dir.

    Returns (json_path, md_path).
    When reports is empty, produces deterministic empty aggregate files so the
    workflow artifact upload always finds files.
    """
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "security-report.json")
    md_path = os.path.join(output_dir, "security-report.md")

    generated_at = max(
        (report.audit_timestamp for report in reports if report.audit_timestamp),
        default="",
    )
    agg = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "generated_at": generated_at,
        "report_count": len(reports),
        "reports": [_report_to_dict(r) for r in reports],
    }

    _atomic_write_text(
        json_path, json.dumps(agg, indent=2, sort_keys=True, default=str) + "\n"
    )

    if not reports:
        md_content = (
            "# Decky Plugin Security Audit\n\n"
            f"Generated: {agg['generated_at']}\n\n"
            "No plugin repository changes were detected.\n"
        )
    else:
        md_parts: list[str] = [
            "# Decky Plugin Security Audit",
            "",
            f"Generated: {agg['generated_at']}",
            f"Reports: {len(reports)}",
            "",
            generate_run_summary(reports, verdicts=verdicts).rstrip(),
            "",
            "---",
            "",
        ]
        for report in reports:
            md_parts.append(generate_markdown_report(report))
            md_parts.append("\n---\n")
        md_content = "\n".join(md_parts)

    _atomic_write_text(md_path, md_content)

    return json_path, md_path


def _release_outcome_exit_code(
    reports: list[AuditReport], enforcement_mode: str
) -> int:
    """Apply the documented mixed release-outcome precedence 4, 2, 3, 0."""
    if any(report.final_classification == "AUDIT_ERROR" for report in reports):
        return 4
    if enforcement_mode != "enforce":
        return 0
    if any(report.final_classification == "BLOCK" for report in reports):
        return 2
    if any(report.final_classification == "MANUAL_REVIEW" for report in reports):
        return 3
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point.  Returns exit code."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Static security audit for Decky Loader plugin releases.",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Audit all repositories in additional_plugins.txt",
    )
    mode_group.add_argument(
        "--changed",
        action="store_true",
        help="Audit repositories newly added or changed relative to base branch",
    )
    mode_group.add_argument(
        "--repository",
        metavar="URL",
        help="Audit one explicit repository URL",
    )
    mode_group.add_argument(
        "--aggregate-reports",
        nargs="+",
        metavar="REPORT",
        help="Aggregate isolated shard report JSON files",
    )
    mode_group.add_argument(
        "--merge-verdict-delta",
        metavar="DELTA",
        help="Validate and atomically merge one verdict delta into the tracked store",
    )
    parser.add_argument(
        "--prepare-worklist",
        metavar="WORKLIST",
        help="Prepare immutable worklist JSON at the given path",
    )
    parser.add_argument(
        "--aggregate-verdict-deltas",
        nargs="*",
        default=[],
        metavar="DELTA",
        help="Verdict delta JSON files to aggregate with shard reports",
    )
    parser.add_argument(
        "--latest-only",
        action="store_true",
        help="Audit one latest eligible release; valid only with --repository",
    )
    parser.add_argument(
        "--source-revision",
        help="Source revision used for worklist preparation mode",
    )
    parser.add_argument(
        "--api-deadline-seconds",
        type=int,
        default=300,
        help="API timeout for producer-mode repository discovery",
    )
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument(
        "--progress-manifest",
        help="Atomic resume manifest path (defaults under --output-dir)",
    )
    parser.add_argument(
        "--verdict-delta",
        help="Isolated verdict delta path (defaults under --output-dir)",
    )
    parser.add_argument(
        "--verdict-store",
        default=VERDICTS_FILE,
        help=f"Tracked verdict store path (default: {VERDICTS_FILE})",
    )
    parser.add_argument(
        "--plugins-file",
        default=PLUGINS_FILE,
        help=f"Path to plugin list file (default: {PLUGINS_FILE})",
    )
    parser.add_argument(
        "--base-ref",
        help="Git ref to diff against for --changed mode (default: HEAD~1)",
    )
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_FILE,
        help=f"Policy YAML file (default: {DEFAULT_POLICY_FILE})",
    )
    parser.add_argument(
        "--allowlist",
        default=DEFAULT_ALLOWLIST_FILE,
        help=f"Allowlist YAML file (default: {DEFAULT_ALLOWLIST_FILE})",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--cache-dir",
        default=CACHE_DIR,
        help=f"Cache directory (default: {CACHE_DIR})",
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Bypass cached audit results",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args(argv)

    if args.all:
        selected_mode = "all"
    elif args.changed:
        selected_mode = "changed"
    elif args.repository:
        selected_mode = "repository"
    elif args.aggregate_reports:
        selected_mode = "aggregate-reports"
    elif args.merge_verdict_delta:
        selected_mode = "merge-verdict-delta"
    else:
        parser.error(
            "one of --all, --changed, --repository, "
            "--aggregate-reports, or --merge-verdict-delta must be specified"
        )

    prepare_mode = args.prepare_worklist is not None
    if args.latest_only and selected_mode != "repository":
        parser.error("--latest-only is valid only with --repository")

    if prepare_mode:
        if selected_mode not in {"all", "changed", "repository"}:
            parser.error(
                "--prepare-worklist requires one of --all, --changed, or --repository"
            )
        if selected_mode == "changed" and not (args.base_ref and args.base_ref.strip()):
            parser.error("--prepare-worklist with --changed requires --base-ref")
        if selected_mode != "changed" and args.base_ref:
            parser.error("base_ref is valid only with --changed")
        if args.api_deadline_seconds <= 0:
            parser.error("--api-deadline-seconds must be greater than zero")
        if not args.source_revision:
            parser.error("--source-revision is required with --prepare-worklist")
    else:
        if args.changed and not args.base_ref:
            args.base_ref = "HEAD~1"
        if args.base_ref and selected_mode != "changed":
            parser.error("base_ref is valid only with --changed")
        try:
            select_audit_shard([], args.shard_count, args.shard_index)
        except ValueError as exc:
            parser.error(str(exc))

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.merge_verdict_delta:
        try:
            apply_verdict_delta(args.verdict_store, args.merge_verdict_delta)
        except (OSError, ValueError) as exc:
            log.error("Verdict delta merge failed: %s", exc)
            return 1
        return 0

    if args.prepare_worklist:
        try:
            if args.all:
                repository_urls = read_repo_urls(args.plugins_file)
                selection_mode = "all"
            elif args.changed:
                repository_urls = get_changed_repos(args.plugins_file, args.base_ref)
                selection_mode = "changed"
            else:
                repository_urls = [args.repository]
                selection_mode = "repository"

            fingerprint, _ = audit_worklist.prepare_audit_worklist(
                args.prepare_worklist,
                source_revision=args.source_revision,
                selection_mode=selection_mode,
                repository_urls=repository_urls,
                shard_count=args.shard_count,
                latest_only=args.latest_only,
                base_ref=args.base_ref if args.changed else None,
                release_fetcher=get_releases,
                metadata_fetcher=get_repo_metadata,
                tag_resolver=audit_worklist.resolve_repository_tags_via_ls_remote,
                api_deadline_seconds=args.api_deadline_seconds,
            )
            print(f"worklist_fingerprint={fingerprint}")
            return 0
        except Exception as exc:
            log.error("Failed to prepare audit worklist: %s", exc)
            return 1

    # Load configuration
    try:
        policy = load_policy(args.policy)
    except Exception as exc:
        log.error("Failed to load policy: %s", exc)
        return 1

    try:
        exceptions = load_allowlist(args.allowlist, policy=policy)
    except ValueError as exc:
        log.error("Invalid allowlist: %s", exc)
        return 1

    try:
        verdict_snapshot = load_verdicts(args.cache_dir)
    except ValueError as exc:
        log.error("Invalid verdict store: %s", exc)
        return 1

    expiry_warnings = check_allowlist_expiry(exceptions)
    for w in expiry_warnings:
        log.warning("%s", w)

    enforcement_mode = policy.get("enforcement", {}).get("mode", "report-only")

    if args.aggregate_reports:
        try:
            aggregate_delta_paths = args.aggregate_verdict_deltas or []
            if len(args.aggregate_reports) != len(aggregate_delta_paths):
                raise ValueError(
                    "Each aggregated shard report requires a corresponding verdict delta shard artifact"
                )
            for report_path, delta_path in zip(
                args.aggregate_reports, aggregate_delta_paths
            ):
                shard_reports = _load_aggregate_shard_reports(report_path)
                expected_delta = _normalize_verdict_delta(
                    _verdict_delta_from_reports(shard_reports)
                )
                supplied_delta = _normalize_verdict_delta(
                    aggregate_verdict_deltas([delta_path])
                )
                if expected_delta != supplied_delta:
                    raise ValueError("Aggregated report/delta mismatch")

            reports = aggregate_audit_reports(args.aggregate_reports)
            delta = aggregate_verdict_deltas(aggregate_delta_paths)
            write_reports(reports, args.output_dir, verdicts=verdict_snapshot)
            destination = args.verdict_delta or os.path.join(
                args.output_dir, "security-verdict-delta.json"
            )
            _atomic_write_text(
                destination,
                json.dumps(delta, indent=2, sort_keys=True) + "\n",
            )
        except Exception as exc:
            log.error("Shard aggregation failed: %s", exc)
            return 1
        return _release_outcome_exit_code(reports, enforcement_mode)

    report_json_path = os.path.join(args.output_dir, "security-report.json")
    report_markdown_path = os.path.join(args.output_dir, "security-report.md")
    progress_path = args.progress_manifest or os.path.join(
        args.output_dir, f"progress-shard-{args.shard_index}.json"
    )
    verdict_delta_path = args.verdict_delta or os.path.join(
        args.output_dir, f"verdict-delta-shard-{args.shard_index}.json"
    )

    # Determine repositories to audit
    try:
        if args.all:
            repo_urls = read_repo_urls(args.plugins_file)
        elif args.changed:
            repo_urls = get_changed_repos(args.plugins_file, args.base_ref)
        else:
            repo_urls = [args.repository]
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1

    if not repo_urls:
        log.info("No repositories to audit.")
        # Still write deterministic empty reports so the workflow artifact
        # upload always finds files and CI does not produce a spurious
        # "No files were found" warning.
        try:
            write_reports([], args.output_dir, verdicts=verdict_snapshot)
            _atomic_write_text(
                verdict_delta_path,
                json.dumps({}, indent=2, sort_keys=True) + "\n",
            )
            log.info(
                "Empty reports and verdict delta written: %s, %s, %s",
                report_json_path,
                report_markdown_path,
                verdict_delta_path,
            )
        except Exception as exc:
            log.error("Failed to write empty audit outputs: %s", exc)
            return 1
        # Print distinction in job summary
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            try:
                with open(summary_file, "a", encoding="utf-8") as f:
                    f.write(
                        "## Security Audit\n\n"
                        "No plugin repository changes were detected. "
                        "No plugins were scanned in this run.\n"
                    )
            except Exception:
                pass
        return 0

    log.info("Enumerating %d repository/repositories.", len(repo_urls))
    try:
        worklist, repository_errors = build_audit_worklist(
            repo_urls, latest_only=args.latest_only
        )
        worklist = select_audit_shard(worklist, args.shard_count, args.shard_index)
    except Exception as exc:
        log.error("Failed to build audit worklist: %s", exc)
        return 1

    if args.shard_count > 1 and repository_errors:
        for report in repository_errors:
            detail = "; ".join(report.errors) or "unknown repository error"
            log.error(
                "Run-global sharded enumeration failure for %s: %s",
                report.repository,
                detail,
            )
        return 1

    log.info(
        "Auditing shard %d/%d with %d eligible release(s).",
        args.shard_index,
        args.shard_count,
        len(worklist),
    )
    try:
        progress_records = _load_progress_manifest(progress_path)
    except Exception as exc:
        log.error("Failed to load progress manifest: %s", exc)
        return 1

    reports: list[AuditReport] = []
    if args.shard_index == 0:
        reports.extend(repository_errors)

    for item in worklist:
        release = item.release
        asset = plugin_release_utils.get_zip_asset(release) or {}
        key = "\0".join(
            (
                item.repository,
                str(release.get("id", "")),
                str(asset.get("id", "")),
            )
        )
        resumed_report: Optional[AuditReport] = None
        digest = plugin_release_utils.normalize_github_sha256_digest(
            asset.get("digest")
        )
        if digest and key in progress_records:
            commit_sha, _tree_sha, _error = _resolve_ref_to_commit_and_tree_sha(
                *parse_owner_repo(item.repository), release.get("tag_name", "")
            )
            scanner_identities = _scanner_runtime_identities(policy)
            expected = {
                "repository": item.repository,
                "release": str(release.get("tag_name", "")),
                "release_id": (f"{release.get('tag_name', '')}@{asset.get('id', '')}"),
                "github_release_id": str(release.get("id", "")),
                "asset_id": str(asset.get("id", "")),
                "artifact_url": str(asset.get("browser_download_url", "")),
                "artifact_sha256": digest,
                "resolved_tag_commit_sha": commit_sha or "",
                "audit_context_hash": compute_audit_context_hash(
                    policy,
                    exceptions,
                    policy_path=args.policy,
                    allowlist_path=args.allowlist,
                    scanner_identities=scanner_identities,
                ),
                "completion_status": "completed",
            }
            resumed_report = _resumable_progress_report(
                progress_records[key], expected, key
            )
            if resumed_report is not None:
                log.info(
                    "Resuming completed release %s %s.",
                    item.repository,
                    resumed_report.release_id,
                )

        if resumed_report is not None:
            report = resumed_report
        else:
            try:
                report = audit_release(
                    item.repository,
                    release,
                    policy=policy,
                    exceptions=exceptions,
                    cache_dir=args.cache_dir,
                    skip_cache=args.skip_cache,
                    _repo_metadata=item.repository_metadata,
                    _policy_path=args.policy,
                    _allowlist_path=args.allowlist,
                    _persist_verdict=False,
                )
            except Exception as exc:
                log.error(
                    "Run-global audit failure while processing %s release %s: %s",
                    item.repository,
                    release.get("id", ""),
                    _redacted_exception_detail(exc),
                )
                return 1
        reports.append(report)
        progress_records[key] = _progress_record(report)
        try:
            _write_progress_manifest(progress_path, progress_records)
            write_reports(reports, args.output_dir, verdicts=verdict_snapshot)
            _atomic_write_text(
                verdict_delta_path,
                json.dumps(
                    _verdict_delta_from_reports(reports),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
            )
        except Exception as exc:
            log.error("Failed to checkpoint audit outputs: %s", exc)
            return 1
        cls = report.final_classification
        cls_emoji = _CLASS_EMOJI.get(cls, "❓")
        log.info(
            "%s %s %s → %s (score %d)",
            cls_emoji,
            item.repository,
            report.release_id,
            cls,
            report.risk_score,
        )

    classifications, top_rules = _run_summary_stats(reports)
    classification_tally = ", ".join(
        f"{classification}={classifications[classification]}"
        for classification in CLASSIFICATION_ORDER
    )
    top_rule_tally = ", ".join(
        f"{rule_id}={count}/{len(reports)}" for rule_id, count in top_rules
    )
    log.info(
        "Run summary: total=%d; classifications: %s; top rules: %s",
        len(reports),
        classification_tally,
        top_rule_tally or "none",
    )

    # Write reports
    try:
        json_path, md_path = write_reports(
            reports, args.output_dir, verdicts=verdict_snapshot
        )
        _atomic_write_text(
            verdict_delta_path,
            json.dumps(_verdict_delta_from_reports(reports), indent=2, sort_keys=True)
            + "\n",
        )
        log.info("JSON report: %s", json_path)
        log.info("Markdown report: %s", md_path)
    except Exception as exc:
        log.error("Failed to write reports: %s", exc)
        return 1

    # Print GitHub job summary if available
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a", encoding="utf-8") as f:
                f.write(generate_run_summary(reports, verdicts=verdict_snapshot))
                f.write("\n---\n\n")
                for report in reports:
                    f.write(generate_markdown_report(report))
                    f.write("\n\n---\n\n")
        except Exception as exc:
            log.warning("Could not write step summary: %s", exc)

    # Apply release-local outcome status only after every safe report and verdict
    # delta has been published. Run-global integrity failures return above.
    outcome = _release_outcome_exit_code(reports, enforcement_mode)
    if enforcement_mode != "enforce":
        # Report-only mode: surface findings prominently but exit 0
        blocks = [r for r in reports if r.final_classification == "BLOCK"]
        reviews = [r for r in reports if r.final_classification == "MANUAL_REVIEW"]
        if blocks:
            log.warning(
                "[REPORT-ONLY] %d plugin(s) would be BLOCKED in enforcement mode.",
                len(blocks),
            )
        if reviews:
            log.warning(
                "[REPORT-ONLY] %d plugin(s) would require MANUAL_REVIEW in enforcement mode.",
                len(reviews),
            )
    return outcome


if __name__ == "__main__":
    sys.exit(main())
