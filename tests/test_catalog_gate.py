import copy
import json
import os

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import check_for_updates
import generate_json

REPOSITORY = "https://github.com/owner/plugin"
BLOCKED_HASH = "b" * 64
FALLBACK_HASH = "a" * 64


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


def _verdicts(*, all_blocked=False):
    verdicts = {
        REPOSITORY: {
            "v2.0.0@2": {
                "classification": "BLOCK",
                "blocking_rule_ids": ["STATIC_EVAL"],
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


def _run_generator(monkeypatch, tmp_path, releases, verdicts, base_versions):
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
    assert "STATIC_EVAL" in output


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
        check_for_updates.check_custom_repos({"Plugin": {"1.0.0"}}, _verdicts()) == []
    )


def test_upstream_update_check_ignores_blocked_newest_release(monkeypatch):
    upstream = [
        _plugin([_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)])
    ]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)

    assert check_for_updates.check_upstream({"Plugin": {"1.0.0"}}, _verdicts()) == []


def test_upstream_update_gate_requires_the_audited_hash(monkeypatch):
    upstream = [_plugin([_version("v2.0.0", "c" * 64)])]
    monkeypatch.setattr(generate_json, "fetch_json", lambda _url: upstream)

    assert check_for_updates.check_upstream({"Plugin": {"1.0.0"}}, _verdicts()) == [
        ("Plugin", "2.0.0")
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
    upstream = [
        _plugin([_version("v2.0.0", BLOCKED_HASH), _version("v1.0.0", FALLBACK_HASH)])
    ]

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
        generate_json, "get_plugin_json", lambda *_args: {"name": "Plugin"}
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
