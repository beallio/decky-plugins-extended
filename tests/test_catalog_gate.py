import copy
import json
import os

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import pytest

import check_for_updates
import generate_json

REPOSITORY = "https://github.com/owner/plugin"
BLOCKED_HASH = "b" * 64
FALLBACK_HASH = "a" * 64
OFFICIAL_HASH = "c" * 64
BLOCKABLE_RULES = {"ARCHIVE_TRAVERSAL"}


def _release(tag, asset_id, digest, *, prerelease=False):
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "published_at": f"2026-01-0{asset_id}T00:00:00Z",
        "assets": [
            {
                "id": asset_id,
                "name": "plugin.zip",
                "browser_download_url": (
                    f"https://github.com/owner/plugin/releases/download/{tag}/plugin.zip"
                ),
                "digest": f"sha256:{digest}",
            }
        ],
    }


def _version(tag, digest):
    return {
        "name": generate_json.normalize_version(tag),
        "hash": digest,
        "artifact": (
            f"https://github.com/owner/plugin/releases/download/{tag}/plugin.zip"
        ),
        "created": "2026-01-01T00:00:00Z",
        "downloads": 0,
        "updates": 0,
    }


def _artifactless_version(tag, digest):
    version = _version(tag, digest)
    del version["artifact"]
    return version


def _download_policy():
    return {
        "downloads": {
            "release_max_bytes": 7,
            "source_max_bytes": 11,
            "connect_timeout_seconds": 2,
            "read_timeout_seconds": 3,
            "chunk_size_bytes": 2,
        }
    }


def _verdicts(*, all_blocked=False):
    verdicts = {
        REPOSITORY: {
            "v2.0.0@2": {
                "classification": "BLOCK",
                "blocking_rule_ids": ["ARCHIVE_TRAVERSAL"],
                "artifact_sha256": BLOCKED_HASH,
                "audit_context_hash": "context",
                "audited_at": "2026-08-03T00:00:00Z",
            },
            "v1.0.0@1": {
                "classification": "PASS",
                "blocking_rule_ids": [],
                "artifact_sha256": FALLBACK_HASH,
                "audit_context_hash": "context",
                "audited_at": "2026-08-03T00:00:00Z",
            },
        }
    }
    if all_blocked:
        verdicts[REPOSITORY]["v1.0.0@1"]["classification"] = "BLOCK"
        verdicts[REPOSITORY]["v1.0.0@1"]["blocking_rule_ids"] = ["ARCHIVE_TRAVERSAL"]
    return verdicts


def _plugin(versions):
    return {
        "id": 7,
        "name": "Plugin",
        "author": "Owner",
        "description": "Fixture plugin",
        "tags": [],
        "versions": copy.deepcopy(versions),
        "visible": True,
        "image_url": "https://example.invalid/plugin.png",
        "downloads": 0,
        "updates": 0,
        "created": "2025-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
    }


def _run_generator(
    monkeypatch, tmp_path, releases, verdicts, base_versions, enforcement_mode="enforce"
):
    base_plugin = _plugin(base_versions)

    def fetch_json(_url):
        return [copy.deepcopy(base_plugin)]

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {
            "default_branch": "main",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        generate_json,
        "get_package_json",
        lambda *_args: {"name": "plugin", "author": "Owner"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: releases)
    if enforcement_mode is not None:
        monkeypatch.setattr(
            generate_json,
            "load_policy",
            lambda *_a, **_k: {
                "enforcement": {"mode": enforcement_mode},
                "blockable_rules": sorted(BLOCKABLE_RULES),
            },
            raising=False,
        )
    monkeypatch.setattr(
        generate_json,
        "load_verdicts",
        lambda: copy.deepcopy(verdicts),
        raising=False,
    )

    (tmp_path / "additional_plugins.txt").write_text(
        f"{REPOSITORY}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    generate_json.main()

    stable = json.loads((tmp_path / "public/plugins.json").read_text(encoding="utf-8"))
    testing = json.loads(
        (tmp_path / "public/testing_plugins.json").read_text(encoding="utf-8")
    )
    return stable, testing


@pytest.mark.parametrize("classification", ("PASS", "BLOCK"))
def test_matching_verdict_hash_is_current(classification):
    release = _release("v1.0.0", 7, BLOCKED_HASH)
    verdicts = {
        REPOSITORY: {
            "v1.0.0@7": {
                "classification": classification,
                "blocking_rule_ids": (
                    ["ARCHIVE_TRAVERSAL"] if classification == "BLOCK" else []
                ),
                "artifact_sha256": BLOCKED_HASH,
            }
        }
    }

    result = generate_json.classification_for(
        REPOSITORY,
        release,
        verdicts,
        {"ARCHIVE_TRAVERSAL"},
        current_artifact_sha256=BLOCKED_HASH,
    )

    assert result.identity_status == "CURRENT"
    assert result.effective_classification == classification
    assert result.current_artifact_sha256 == BLOCKED_HASH
    assert result.stored_artifact_sha256 == BLOCKED_HASH
    assert result.fail_open is False


@pytest.mark.parametrize("classification", ("PASS", "BLOCK"))
def test_stale_verdict_hash_fails_open(classification):
    release = _release("v1.0.0", 7, FALLBACK_HASH)
    verdicts = {
        REPOSITORY: {
            "v1.0.0@7": {
                "classification": classification,
                "blocking_rule_ids": ["ARCHIVE_TRAVERSAL"],
                "artifact_sha256": BLOCKED_HASH,
            }
        }
    }

    result = generate_json.classification_for(
        REPOSITORY,
        release,
        verdicts,
        {"ARCHIVE_TRAVERSAL"},
        current_artifact_sha256=FALLBACK_HASH,
    )

    assert result.identity_status == "STALE_HASH"
    assert result.effective_classification == "AUDIT_ERROR"
    assert result.audit_classification == classification
    assert result.current_artifact_sha256 == FALLBACK_HASH
    assert result.stored_artifact_sha256 == BLOCKED_HASH
    assert result.fail_open is True


def test_unknown_verdict_fails_open_with_explicit_identity_status():
    release = _release("v1.0.0", 7, FALLBACK_HASH)

    result = generate_json.classification_for(
        REPOSITORY,
        release,
        {},
        {"ARCHIVE_TRAVERSAL"},
        current_artifact_sha256=FALLBACK_HASH,
    )

    assert result.identity_status == "UNKNOWN"
    assert result.effective_classification == "AUDIT_ERROR"
    assert result.current_artifact_sha256 == FALLBACK_HASH
    assert result.stored_artifact_sha256 is None
    assert result.fail_open is True


def test_gate_removes_blocked_existing_version_and_uses_fallback(
    monkeypatch, tmp_path, capsys
):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    stable, testing = _run_generator(
        monkeypatch,
        tmp_path,
        releases,
        _verdicts(),
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)],
    )

    for catalog in (stable, testing):
        plugin = next(item for item in catalog if item["name"] == "Plugin")
        identities = {(v["name"], v["hash"]) for v in plugin["versions"]}
        assert ("2.0.0", BLOCKED_HASH) not in identities
        assert plugin["versions"][0]["name"] == "1.0.0"
        assert plugin["versions"][0]["hash"] == FALLBACK_HASH
    output = capsys.readouterr().out
    assert "Plugin" in output
    assert "v2.0.0" in output
    assert "ARCHIVE_TRAVERSAL" in output


def test_fresh_clone_reads_tracked_verdicts_and_blocks_release(monkeypatch, tmp_path):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    base_plugin = _plugin(
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)]
    )

    monkeypatch.setattr(
        generate_json, "fetch_json", lambda _url: [copy.deepcopy(base_plugin)]
    )
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {
            "default_branch": "main",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        generate_json,
        "get_package_json",
        lambda *_args: {"name": "plugin", "author": "Owner"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: releases)
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda *_a, **_k: {
            "enforcement": {"mode": "enforce"},
            "blockable_rules": sorted(BLOCKABLE_RULES),
        },
        raising=False,
    )

    (tmp_path / "additional_plugins.txt").write_text(
        f"{REPOSITORY}\n", encoding="utf-8"
    )
    (tmp_path / "security-verdicts.json").write_text(
        json.dumps(_verdicts(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    audit_cache = tmp_path / ".audit-cache"
    if audit_cache.exists():
        audit_cache.rmdir()

    monkeypatch.chdir(tmp_path)
    generate_json.main()

    for filename in ("plugins.json", "testing_plugins.json"):
        catalog = json.loads(
            (tmp_path / "public" / filename).read_text(encoding="utf-8")
        )
        plugin = next(item for item in catalog if item["name"] == "Plugin")
        identities = {
            (version["name"], version["hash"]) for version in plugin["versions"]
        }
        assert ("2.0.0", BLOCKED_HASH) not in identities
        assert "2.0.0" not in {version["name"] for version in plugin["versions"]}
        assert BLOCKED_HASH not in {version["hash"] for version in plugin["versions"]}
        assert plugin["versions"][0]["name"] == "1.0.0"
        assert plugin["versions"][0]["hash"] == FALLBACK_HASH


def test_gate_loads_verdicts_only_once(monkeypatch, tmp_path):
    calls = 0

    def load_verdicts():
        nonlocal calls
        calls += 1
        return _verdicts()

    monkeypatch.setattr(generate_json, "load_verdicts", load_verdicts, raising=False)
    monkeypatch.setattr(
        generate_json,
        "fetch_json",
        lambda _url: [_plugin([_version("v1.0.0", FALLBACK_HASH)])],
    )
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json,
        "get_package_json",
        lambda *_args: {"name": "plugin", "author": "Owner"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [_release("v1.0.0", 1, FALLBACK_HASH)],
    )
    (tmp_path / "additional_plugins.txt").write_text(
        f"{REPOSITORY}\n{REPOSITORY}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    generate_json.main()

    assert calls == 1


def test_fully_blocked_plugin_disappears_with_distinct_log(
    monkeypatch, tmp_path, capsys
):
    stable, testing = _run_generator(
        monkeypatch,
        tmp_path,
        [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
        _verdicts(all_blocked=True),
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)],
    )

    output = capsys.readouterr().out
    assert "All valid releases for Plugin are blocked" in output
    assert "No valid releases found for Plugin" not in output
    assert all(plugin["name"] != "Plugin" for plugin in stable)
    assert all(plugin["name"] != "Plugin" for plugin in testing)
    assert (
        "Removed Plugin from stable: gating left the entry with no versions" in output
    )
    assert (
        "Removed Plugin from testing: gating left the entry with no versions" in output
    )


def test_fully_blocked_repository_keeps_the_official_store_versions(
    monkeypatch, tmp_path, capsys
):
    # The official store builds its own artifact for a version, so an upstream
    # row can share a version name with a blocked release while carrying bytes
    # this audit never covered. Blocking every release of the configured
    # repository must not delete a plugin the official store still ships.
    stable, testing = _run_generator(
        monkeypatch,
        tmp_path,
        [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
        _verdicts(all_blocked=True),
        [_version("v1.0.0", OFFICIAL_HASH)],
    )

    output = capsys.readouterr().out
    assert "All valid releases for Plugin are blocked" in output
    assert "Kept the official stable entry for Plugin" in output
    assert "Kept the official testing entry for Plugin" in output
    assert "Removed Plugin from stable" not in output

    for catalog in (stable, testing):
        entry = next(plugin for plugin in catalog if plugin["name"] == "Plugin")
        assert [version["name"] for version in entry["versions"]] == ["1.0.0"]
        assert entry["versions"][0]["hash"] == OFFICIAL_HASH


def test_fully_blocked_repository_still_drops_the_audited_identity(
    monkeypatch, tmp_path
):
    # The surviving upstream row must be the unaudited official artifact only:
    # the exact blocked identity is still removed from the entry.
    stable, _ = _run_generator(
        monkeypatch,
        tmp_path,
        [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
        _verdicts(all_blocked=True),
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", OFFICIAL_HASH)],
    )

    entry = next(plugin for plugin in stable if plugin["name"] == "Plugin")
    assert [(version["name"], version["hash"]) for version in entry["versions"]] == [
        ("1.0.0", OFFICIAL_HASH)
    ]


def test_generator_defers_to_the_store_for_versions_it_publishes(monkeypatch, tmp_path):
    # The official store builds and ships its own artifact for 1.0.0, and the
    # audit skips that release for the same reason. Republishing our build here
    # would replace the store's row with bytes nothing audited.
    (tmp_path / "store_versions.json").write_text(
        json.dumps({REPOSITORY: ["1.0.0"]}), encoding="utf-8"
    )
    verdicts = _verdicts()
    verdicts[REPOSITORY]["v2.0.0@2"]["classification"] = "PASS"
    verdicts[REPOSITORY]["v2.0.0@2"]["blocking_rule_ids"] = []

    stable, _ = _run_generator(
        monkeypatch,
        tmp_path,
        [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
        verdicts,
        [_version("v1.0.0", OFFICIAL_HASH)],
    )

    entry = next(plugin for plugin in stable if plugin["name"] == "Plugin")
    rows = {version["name"]: version["hash"] for version in entry["versions"]}
    assert rows["1.0.0"] == OFFICIAL_HASH, "the store's own artifact must survive"
    assert rows["2.0.0"] == BLOCKED_HASH, "versions the store lacks still ship"


def test_manual_review_and_audit_error_releases_still_ship(monkeypatch, tmp_path):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    verdicts = _verdicts()
    verdicts[REPOSITORY]["v2.0.0@2"]["classification"] = "MANUAL_REVIEW"
    del verdicts[REPOSITORY]["v1.0.0@1"]

    stable, testing = _run_generator(monkeypatch, tmp_path, releases, verdicts, [])

    for catalog in (stable, testing):
        plugin = next(item for item in catalog if item["name"] == "Plugin")
        assert [version["name"] for version in plugin["versions"]] == [
            "2.0.0",
            "1.0.0",
        ]


def test_reconciliation_requires_normalized_name_and_audited_hash():
    plugin = _plugin(
        [
            _version("v2.0.0", "c" * 64),
            _version("v2.0.0", BLOCKED_HASH),
        ]
    )

    removed = generate_json.remove_blocked_versions(plugin, {("2.0.0", BLOCKED_HASH)})

    assert removed == 1
    assert [(v["name"], v["hash"]) for v in plugin["versions"]] == [("2.0.0", "c" * 64)]


def test_custom_update_check_defers_to_official_store_versions(monkeypatch):
    release = _release("v1.0.0", 1, FALLBACK_HASH)
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])
    monkeypatch.setattr(
        generate_json,
        "load_store_versions",
        lambda: {REPOSITORY: {"1.0.0"}},
    )
    monkeypatch.setattr(
        generate_json,
        "build_version_object",
        lambda *_args, **_kwargs: pytest.fail(
            "official store versions must not inspect the GitHub artifact"
        ),
    )
    managed_plugin_names = set()

    assert (
        check_for_updates.check_custom_repos(
            {"Plugin": {("1.0.0", OFFICIAL_HASH)}},
            {},
            BLOCKABLE_RULES,
            managed_plugin_names=managed_plugin_names,
        )
        == []
    )
    assert managed_plugin_names == {"Plugin"}


def test_custom_update_check_skips_oversized_release_without_digest(monkeypatch):
    policy = _download_policy()
    release = _release("v1.0.0", 1, "invalid")
    release["assets"][0]["size"] = policy["downloads"]["release_max_bytes"] + 1
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])
    monkeypatch.setattr(
        generate_json,
        "build_version_object",
        lambda *_args, **_kwargs: pytest.fail(
            "the generator excludes oversized releases without a GitHub digest"
        ),
    )

    assert (
        check_for_updates.check_custom_repos(
            {},
            {},
            BLOCKABLE_RULES,
            download_policy=policy,
        )
        == []
    )


def test_custom_update_check_ignores_blocked_newest_release(monkeypatch):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: releases)

    assert (
        check_for_updates.check_custom_repos(
            {"Plugin": {("1.0.0", FALLBACK_HASH)}},
            _verdicts(),
            BLOCKABLE_RULES,
        )
        == []
    )


def test_custom_update_check_keeps_blocked_newest_release_in_report_only_mode(
    monkeypatch,
):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: releases)

    assert check_for_updates.check_custom_repos(
        {"Plugin": {("1.0.0", FALLBACK_HASH)}},
        _verdicts(),
        BLOCKABLE_RULES,
        enforcement_mode="report-only",
    ) == [("Plugin", "2.0.0")]


def test_upstream_update_check_ignores_blocked_newest_release(monkeypatch):
    upstream = [
        _plugin([_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)])
    ]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
    )

    assert (
        check_for_updates.check_upstream(
            {"Plugin": {("1.0.0", FALLBACK_HASH)}},
            _verdicts(),
            BLOCKABLE_RULES,
            enforcement_mode="enforce",
        )
        == []
    )


def test_upstream_update_check_includes_blocked_newest_release_in_report_only_mode(
    monkeypatch,
):
    upstream = [
        _plugin([_version("v2.0.0", BLOCKED_HASH), _version("1.0.0", FALLBACK_HASH)])
    ]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [
            _release("v2.0.0", 2, BLOCKED_HASH),
            _release("v1.0.0", 1, FALLBACK_HASH),
        ],
    )

    assert check_for_updates.check_upstream(
        {"Plugin": {("1.0.0", FALLBACK_HASH)}},
        _verdicts(),
        BLOCKABLE_RULES,
        enforcement_mode="report-only",
    ) == [("Plugin", "2.0.0")]


def test_upstream_update_check_passes_non_default_download_policy(monkeypatch):
    policy = _download_policy()
    release = _release("v1.0.0", 1, "invalid")
    artifact = release["assets"][0]["browser_download_url"]
    monkeypatch.setattr(
        generate_json,
        "fetch_json",
        lambda _url: [_plugin([_version("v1.0.0", "a" * 64)])],
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])
    observed = []

    def calculate_hash(url, policy=None):
        observed.append((url, policy))
        return "b" * 64

    monkeypatch.setattr(generate_json, "calculate_hash", calculate_hash)

    assert check_for_updates.check_upstream(
        {}, {}, BLOCKABLE_RULES, download_policy=policy
    ) == [("Plugin", "1.0.0")]
    assert observed == [(artifact, policy)]


def test_custom_update_check_passes_non_default_download_policy(monkeypatch):
    policy = _download_policy()
    release = _release("v1.0.0", 1, "invalid")
    artifact = release["assets"][0]["browser_download_url"]
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])
    observed = []

    def calculate_hash(url, policy=None):
        observed.append((url, policy))
        return "b" * 64

    monkeypatch.setattr(generate_json, "calculate_hash", calculate_hash)

    assert check_for_updates.check_custom_repos(
        {}, {}, BLOCKABLE_RULES, download_policy=policy
    ) == [("Plugin", "1.0.0")]
    assert observed == [(artifact, policy)]


def test_upstream_update_gate_requires_the_audited_hash(monkeypatch):
    upstream = [_plugin([_version("v2.0.0", "c" * 64)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [_release("v2.0.0", 2, "c" * 64)],
    )

    assert check_for_updates.check_upstream(
        {"Plugin": {("1.0.0", FALLBACK_HASH)}},
        _verdicts(),
        BLOCKABLE_RULES,
    ) == [("Plugin", "2.0.0")]


def test_artifactless_upstream_version_uses_exact_official_identity_without_download(
    monkeypatch,
):
    policy = _download_policy()
    digest = "a" * 64
    upstream = [_plugin([_artifactless_version("v2.0.0", digest)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: pytest.fail("artifactless Deckbrew rows have no GitHub origin"),
    )

    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "artifactless official identities must not be downloaded"
        ),
    )
    monkeypatch.setattr(
        generate_json,
        "catalog_version_is_blocked",
        lambda *_args, **_kwargs: pytest.fail(
            "artifactless official identities have no repository verdict identity"
        ),
    )

    assert (
        check_for_updates.check_upstream(
            {"Plugin": {("2.0.0", digest)}},
            {},
            BLOCKABLE_RULES,
            download_policy=policy,
        )
        == []
    )


def test_decky_framegen_size_shaped_artifactless_version_never_downloads(monkeypatch):
    digest = "14015d5a652c78b2041fd9668685573840530c306e414aabc0d3cebf95be0642"
    version = _artifactless_version("0.11.15", digest)
    version["size"] = 75_140_408
    plugin = _plugin([version])
    plugin["name"] = "Decky-Framegen"
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [plugin])

    def oversized_download(*_args, **_kwargs):
        raise generate_json.ArtifactDownloadError(
            "declared Content-Length 75140408 exceeds release limit"
        )

    monkeypatch.setattr(generate_json, "calculate_hash", oversized_download)

    assert (
        check_for_updates.check_upstream(
            {"Decky-Framegen": {("0.11.15", digest)}}, {}, BLOCKABLE_RULES
        )
        == []
    )


def test_artifactless_upstream_version_detects_same_version_hash_change(monkeypatch):
    digest = "a" * 64
    upstream = [_plugin([_artifactless_version("v2.0.0", digest)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "fresh artifactless hashes must not be downloaded"
        ),
    )

    assert check_for_updates.check_upstream(
        {"Plugin": {("2.0.0", "b" * 64)}}, {}, BLOCKABLE_RULES
    ) == [("Plugin", "2.0.0")]


def test_artifactless_upstream_version_preserves_verbatim_deckbrew_name(monkeypatch):
    digest = "a" * 64
    version = _artifactless_version("2.0.0", digest)
    version["name"] = "v2.0.0"
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [_plugin([version])])
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "verbatim artifactless identities must not be downloaded"
        ),
    )

    assert (
        check_for_updates.check_upstream(
            {"Plugin": {("v2.0.0", digest)}}, {}, BLOCKABLE_RULES
        )
        == []
    )


@pytest.mark.parametrize("digest", ("A" * 64, "a" * 63, "g" * 64, None))
def test_artifactless_upstream_version_rejects_invalid_hash_without_download(
    monkeypatch, digest
):
    upstream = [_plugin([_artifactless_version("v2.0.0", digest)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail("invalid hashes must not be downloaded"),
    )

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=r"repository=https://plugins\.deckbrew\.xyz/plugins.*version=2\.0\.0.*invalid.*SHA-256",
    ):
        check_for_updates.check_upstream({}, {}, BLOCKABLE_RULES)


@pytest.mark.parametrize("name", ("", None, 2))
def test_artifactless_upstream_version_rejects_invalid_version_name(monkeypatch, name):
    version = _artifactless_version("1.0.0", "a" * 64)
    version["name"] = name
    upstream = [_plugin([version])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail("missing names must not be downloaded"),
    )

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=r"repository=https://plugins\.deckbrew\.xyz/plugins.*version=<unresolved>.*invalid or empty upstream version name",
    ):
        check_for_updates.check_upstream({}, {}, BLOCKABLE_RULES)


def test_present_empty_upstream_artifact_remains_invalid(monkeypatch):
    version = _artifactless_version("v2.0.0", "a" * 64)
    version["artifact"] = ""
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [_plugin([version])])
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail("present artifact uses strict URL path"),
    )

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=r"invalid upstream GitHub release asset URL ''",
    ):
        check_for_updates.check_upstream({}, {}, BLOCKABLE_RULES)


def test_configured_plugin_is_authoritative_over_artifactless_upstream(monkeypatch):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    upstream = [
        _plugin(
            [
                _artifactless_version("v2.0.0", BLOCKED_HASH),
                _artifactless_version("v1.0.0", FALLBACK_HASH),
            ]
        )
    ]
    release_requests = 0

    def get_releases(*_args):
        nonlocal release_requests
        release_requests += 1
        return releases

    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json, "get_repo_info", lambda *_args: {"default_branch": "main"}
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", get_releases)
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "managed upstream plugins must skip the duplicate CDN download"
        ),
    )
    live = {"Plugin": {("1.0.0", FALLBACK_HASH)}}
    managed_plugin_names = set()

    assert (
        check_for_updates.check_custom_repos(
            live,
            _verdicts(),
            BLOCKABLE_RULES,
            enforcement_mode="enforce",
            managed_plugin_names=managed_plugin_names,
        )
        == []
    )
    assert managed_plugin_names == {"Plugin"}
    assert (
        check_for_updates.check_upstream(
            live,
            _verdicts(),
            BLOCKABLE_RULES,
            enforcement_mode="enforce",
            ignored_plugin_names=managed_plugin_names,
        )
        == []
    )
    assert release_requests == 1


def test_configured_plugin_without_valid_release_does_not_hide_upstream_change(
    monkeypatch,
):
    upstream_hash = "a" * 64
    live_hash = "b" * 64
    upstream = [_plugin([_artifactless_version("v2.0.0", upstream_hash)])]
    prerelease_only = [_release("v3.0.0-beta.1", 3, "c" * 64, prerelease=True)]
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json, "get_repo_info", lambda *_args: {"default_branch": "main"}
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: prerelease_only)
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "no-valid-release fallback uses the official identity directly"
        ),
    )
    live = {"Plugin": {("2.0.0", live_hash)}}
    managed_plugin_names = set()

    assert (
        check_for_updates.check_custom_repos(
            live,
            {},
            BLOCKABLE_RULES,
            managed_plugin_names=managed_plugin_names,
        )
        == []
    )
    assert managed_plugin_names == set()
    assert check_for_updates.check_upstream(
        live,
        {},
        BLOCKABLE_RULES,
        ignored_plugin_names=managed_plugin_names,
    ) == [("Plugin", "2.0.0")]


def test_upstream_update_check_rejects_zero_current_release_matches(monkeypatch):
    upstream = [_plugin([_version("v2.0.0", "a" * 64)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [_release("v1.0.0", 1, "a" * 64)],
    )

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=(
            r"repository=https://github\.com/owner/plugin.*version=2\.0\.0.*"
            r"no eligible release matches"
        ),
    ):
        check_for_updates.check_upstream(
            {"Plugin": {("2.0.0", "a" * 64)}}, {}, BLOCKABLE_RULES
        )


def test_upstream_update_check_rejects_multiple_current_release_matches(monkeypatch):
    upstream = [_plugin([_version("v2.0.0", "a" * 64)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [
            _release("v2.0.0", 2, "b" * 64),
            _release("v2.0.0", 3, "c" * 64),
        ],
    )

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=r"repository=https://github\.com/owner/plugin.*version=2\.0\.0.*ambiguous.*2 eligible releases",
    ):
        check_for_updates.check_upstream({}, {}, BLOCKABLE_RULES)


def test_upstream_update_check_rejects_changed_asset_for_same_normalized_version(
    monkeypatch,
):
    upstream_version = _version("Release-2.0.0", "a" * 64)
    current_release = _release("v2.0.0", 2, "b" * 64)
    monkeypatch.setattr(
        generate_json, "fetch_json", lambda _url: [_plugin([upstream_version])]
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [current_release])

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=(
            r"repository=https://github\.com/owner/plugin.*version=2\.0\.0.*"
            r"no ZIP asset matches the upstream artifact URL"
        ),
    ):
        check_for_updates.check_upstream({}, {}, BLOCKABLE_RULES)


def test_upstream_update_check_rejects_stale_upstream_url_and_hash(monkeypatch):
    upstream_version = _version("v2.0.0", "a" * 64)
    upstream_version["artifact"] = (
        "https://github.com/owner/plugin/releases/download/v2.0.0/old-plugin.zip"
    )
    current_release = _release("v2.0.0", 2, "b" * 64)
    monkeypatch.setattr(
        generate_json, "fetch_json", lambda _url: [_plugin([upstream_version])]
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [current_release])

    with pytest.raises(
        check_for_updates.UpstreamArtifactIdentityError,
        match=(
            r"repository=https://github\.com/owner/plugin.*version=2\.0\.0.*"
            r"no ZIP asset matches the upstream artifact URL"
        ),
    ):
        check_for_updates.check_upstream(
            {"Plugin": {("2.0.0", "a" * 64)}}, {}, BLOCKABLE_RULES
        )


def test_upstream_update_check_uses_unique_current_hash_not_catalog_hash(monkeypatch):
    upstream = [_plugin([_version("v2.0.0", "a" * 64)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [_release("v2.0.0", 2, "b" * 64)],
    )

    assert check_for_updates.check_upstream(
        {"Plugin": {("2.0.0", "a" * 64)}}, {}, BLOCKABLE_RULES
    ) == [("Plugin", "2.0.0")]


def test_update_check_main_reports_unresolved_upstream_identity(monkeypatch, capsys):
    upstream = [_plugin([_version("v2.0.0", "a" * 64)])]

    def fetch_json(url):
        return [] if url == check_for_updates.LIVE_URL else upstream

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [])
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [])
    monkeypatch.setattr(generate_json, "load_verdicts", lambda: {})
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {"blockable_rules": sorted(BLOCKABLE_RULES)},
    )

    assert check_for_updates.main() == 1
    output = capsys.readouterr().out
    assert "Fatal artifact identity failure" in output
    assert "repository=https://github.com/owner/plugin" in output
    assert "version=2.0.0" in output
    assert "no eligible release matches" in output
    assert "changed=false" not in output


def test_update_check_main_accepts_production_shaped_artifactless_upstream(
    monkeypatch, capsys
):
    digest = "a" * 64
    plugin = _plugin([_artifactless_version("v2.0.0", digest)])
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [plugin])
    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        lambda *_args, **_kwargs: pytest.fail(
            "production-shaped official identities must not be downloaded"
        ),
    )
    monkeypatch.setattr(generate_json, "load_verdicts", lambda: {})
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {
            "blockable_rules": sorted(BLOCKABLE_RULES),
            "enforcement": {"mode": "enforce"},
        },
    )
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [])

    assert check_for_updates.main() == 0
    output = capsys.readouterr().out
    assert "Live catalog already has every upstream and configured release." in output
    assert "changed=false" in output


def test_update_check_main_rejects_malformed_artifactless_identity_without_output(
    monkeypatch, capsys
):
    plugin = _plugin([_artifactless_version("v2.0.0", "A" * 64)])

    def fetch_json(url):
        return [] if url == check_for_updates.LIVE_URL else [plugin]

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [])
    monkeypatch.setattr(generate_json, "load_verdicts", lambda: {})
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {
            "blockable_rules": sorted(BLOCKABLE_RULES),
            "enforcement": {"mode": "enforce"},
        },
    )
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    assert check_for_updates.main() == 1
    output = capsys.readouterr().out
    assert "Fatal artifact identity failure" in output
    assert "invalid Deckbrew content-addressed SHA-256" in output
    assert "changed=" not in output


@pytest.mark.parametrize("enforcement_mode", ["enforce", "report-only"])
def test_update_check_main_forwards_enforcement_mode_to_upstream_and_configured_checks(
    monkeypatch, enforcement_mode
):
    observed = []

    def fake_upstream(
        live,
        verdicts,
        blockable_rules=None,
        *,
        download_policy=None,
        enforcement_mode=None,
        ignored_plugin_names=None,
    ):
        observed.append(("upstream", enforcement_mode, ignored_plugin_names))
        return []

    def fake_custom(
        live,
        verdicts,
        blockable_rules=None,
        *,
        download_policy=None,
        enforcement_mode=None,
        managed_plugin_names=None,
    ):
        managed_plugin_names.add("Plugin")
        observed.append(("custom", enforcement_mode))
        return []

    monkeypatch.setattr(check_for_updates, "check_upstream", fake_upstream)
    monkeypatch.setattr(check_for_updates, "check_custom_repos", fake_custom)
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: [])
    monkeypatch.setattr(generate_json, "load_verdicts", lambda: {})
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {
            "enforcement": {"mode": enforcement_mode},
            "blockable_rules": sorted(BLOCKABLE_RULES),
        },
    )

    assert check_for_updates.main() == 0
    assert observed == [
        ("custom", enforcement_mode),
        ("upstream", enforcement_mode, {"Plugin"}),
    ]


def test_two_consecutive_update_checks_stay_false_for_blocked_releases(
    monkeypatch, tmp_path, capsys
):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    live, _testing = _run_generator(
        monkeypatch,
        tmp_path,
        releases,
        _verdicts(),
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)],
    )
    upstream_plugin = _plugin(
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)]
    )
    upstream_plugin["name"] = "PLUGIN"
    upstream = [upstream_plugin]

    def fetch_json(url):
        return live if url == check_for_updates.LIVE_URL else upstream

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    monkeypatch.setattr(
        generate_json, "load_verdicts", lambda: _verdicts(), raising=False
    )
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: releases)
    output_path = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    assert check_for_updates.main() == 0
    assert check_for_updates.main() == 0

    output = capsys.readouterr().out
    assert output.count("changed=false") == 2
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "changed=false",
        "changed=false",
    ]


def test_report_only_mode_ships_blocked_releases(monkeypatch, tmp_path, capsys):
    """A BLOCK verdict must not exclude anything while the policy is report-only.

    The first real audit run produced eight BLOCK verdicts, every one a false
    positive, and removed those plugins from the live catalog. security-policy.yml
    had said report-only since it landed; the catalog gate ignored it. This pins
    the gate to the policy so the two cannot disagree again.
    """
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]
    stable, testing = _run_generator(
        monkeypatch,
        tmp_path,
        releases,
        _verdicts(),
        [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)],
        enforcement_mode="report-only",
    )

    for catalog in (stable, testing):
        plugin = next(item for item in catalog if item["name"] == "Plugin")
        names = {version["name"] for version in plugin["versions"]}
        hashes = {version["hash"] for version in plugin["versions"]}
        assert "2.0.0" in names, "report-only must not exclude a BLOCKed release"
        assert BLOCKED_HASH in hashes
        assert plugin["versions"][0]["name"] == "2.0.0"

    # The block is still reported, so tuning data is not lost.
    assert "[report-only]" in capsys.readouterr().out


def test_unreadable_policy_fails_closed_before_public_output(
    monkeypatch, tmp_path, capsys
):
    releases = [
        _release("v2.0.0", 2, BLOCKED_HASH),
        _release("v1.0.0", 1, FALLBACK_HASH),
    ]

    def _boom(*_args, **_kwargs):
        raise OSError("policy unreadable")

    monkeypatch.setattr(generate_json, "load_policy", _boom, raising=False)
    with pytest.raises(SystemExit) as exc_info:
        _run_generator(
            monkeypatch,
            tmp_path,
            releases,
            _verdicts(),
            [_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)],
            enforcement_mode=None,
        )

    assert exc_info.value.code == 1
    assert "Fatal: could not load catalog security policy" in capsys.readouterr().out
    assert not (tmp_path / "public/plugins.json").exists()


def test_artifact_download_failure_is_run_global_before_public_output(
    monkeypatch, tmp_path, capsys
):
    release = _release("v2.0.0", 2, "invalid")

    def _download_failed(*_args, **_kwargs):
        raise generate_json.ArtifactDownloadError("release exceeds limit")

    monkeypatch.setattr(generate_json, "calculate_hash", _download_failed)
    with pytest.raises(SystemExit) as exc_info:
        _run_generator(
            monkeypatch,
            tmp_path,
            [release],
            {},
            [],
        )

    assert exc_info.value.code == 1
    assert "Fatal artifact identity failure" in capsys.readouterr().out
    assert not (tmp_path / "public/plugins.json").exists()


def test_update_check_does_not_skip_artifact_download_failure(monkeypatch):
    release = _release("v1.0.0", 1, "invalid")
    monkeypatch.setattr(generate_json, "read_repo_urls", lambda: [REPOSITORY])
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {"default_branch": "main"},
    )
    monkeypatch.setattr(
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"name": "plugin"}
    )
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])

    def _download_failed(*_args, **_kwargs):
        raise generate_json.ArtifactDownloadError("release exceeds limit")

    monkeypatch.setattr(
        generate_json,
        "calculate_hash",
        _download_failed,
    )

    with pytest.raises(generate_json.ArtifactDownloadError):
        check_for_updates.check_custom_repos({}, {}, BLOCKABLE_RULES)
