"""Keep catalog updates and security decisions working during store outages."""

import copy
import json
import os

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import pytest
import requests

import check_for_updates
import generate_json

REPOSITORY = "https://github.com/owner/plugin"
OFFICIAL_HASH = "c" * 64
ALLOWED_HASH = "a" * 64
BLOCKED_HASH = "b" * 64


def _plugin(version="1.0.0", digest=OFFICIAL_HASH):
    return {
        "id": 7,
        "name": "Plugin",
        "author": "Owner",
        "description": "Official description",
        "tags": [],
        "versions": [{"name": version, "hash": digest}],
        "visible": True,
        "image_url": "https://example.invalid/plugin.png",
        "downloads": 0,
        "updates": 0,
        "created": "2025-01-01T00:00:00Z",
        "updated": "2026-01-01T00:00:00Z",
    }


def _release(version, asset_id, digest):
    return {
        "tag_name": f"v{version}",
        "prerelease": False,
        "published_at": "2026-10-15T00:00:00Z",
        "assets": [
            {
                "id": asset_id,
                "name": "plugin.zip",
                "browser_download_url": (
                    f"{REPOSITORY}/releases/download/v{version}/plugin.zip"
                ),
                "digest": f"sha256:{digest}",
            }
        ],
    }


@pytest.fixture
def saved_store(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "additional_plugins.txt").write_text(f"{REPOSITORY}\n")
    (tmp_path / "store_plugins.txt").write_text("# generated\n")
    (tmp_path / "store_versions.json").write_text(json.dumps({REPOSITORY: ["1.0.0"]}))
    (tmp_path / "store_sources.json").write_text(json.dumps({"Plugin": [REPOSITORY]}))
    (tmp_path / "store_catalogs.json").write_text(
        json.dumps(
            {
                "captured_at": "2026-10-14T00:00:00Z",
                "stable": [_plugin()],
                "testing": [_plugin()],
            }
        )
    )
    monkeypatch.setattr(
        generate_json,
        "get_repo_info",
        lambda *_args: {
            "default_branch": "main",
            "created_at": "2025-01-01T00:00:00Z",
        },
    )
    monkeypatch.setattr(
        generate_json, "get_package_json", lambda *_args: {"author": "Owner"}
    )
    monkeypatch.setattr(
        generate_json,
        "get_plugin_json",
        lambda *_args: {
            "name": "Plugin",
            "publish": {"image": "https://example.invalid/plugin.png"},
        },
    )
    monkeypatch.setattr(generate_json, "image_is_usable", lambda _url: True)
    monkeypatch.setattr(
        generate_json,
        "get_releases",
        lambda *_args: [
            _release("3.0.0", 3, BLOCKED_HASH),
            _release("2.0.0", 2, ALLOWED_HASH),
            _release("1.0.0", 1, OFFICIAL_HASH),
        ],
    )
    monkeypatch.setattr(
        generate_json,
        "load_policy",
        lambda: {
            "enforcement": {"mode": "enforce"},
            "blockable_rules": ["ARCHIVE_TRAVERSAL"],
        },
    )
    monkeypatch.setattr(
        generate_json,
        "load_verdicts",
        lambda: {
            REPOSITORY: {
                "v3.0.0@3": {
                    "classification": "BLOCK",
                    "blocking_rule_ids": ["ARCHIVE_TRAVERSAL"],
                    "artifact_sha256": BLOCKED_HASH,
                }
            }
        },
    )
    return tmp_path


def test_generator_uses_complete_saved_pair_and_current_security_decisions(
    monkeypatch, saved_store
):
    def fetch_json(url):
        if url == generate_json.PLUGINS_URL:
            return [_plugin("4.0.0", "d" * 64)]
        raise requests.Timeout("testing store is unavailable")

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    before = (saved_store / "store_catalogs.json").read_bytes()
    generate_json.main()

    for filename in ("plugins.json", "testing_plugins.json"):
        catalog = json.loads((saved_store / "public" / filename).read_text())
        assert [plugin["name"] for plugin in catalog] == ["Plugin"]
        assert [version["name"] for version in catalog[0]["versions"]] == [
            "2.0.0",
            "1.0.0",
        ]
        assert catalog[0]["versions"][0]["hash"] == ALLOWED_HASH
        assert catalog[0]["versions"][1]["hash"] == OFFICIAL_HASH
    assert (saved_store / "store_catalogs.json").read_bytes() == before


@pytest.mark.parametrize("has_custom_update", [False, True])
def test_updater_only_requests_rebuild_for_a_confirmed_change_during_outage(
    monkeypatch, saved_store, has_custom_update
):
    live = _plugin() if has_custom_update else _plugin("2.0.0", ALLOWED_HASH)

    def fetch_json(url):
        if url == check_for_updates.LIVE_URL:
            return [copy.deepcopy(live)]
        raise requests.ConnectionError("official store is unavailable")

    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    output = saved_store / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert check_for_updates.main() == 0
    assert output.read_text() == f"changed={str(has_custom_update).lower()}\n"


def test_store_fallback_does_not_hide_a_current_artifact_identity_failure(
    monkeypatch, saved_store
):
    def fetch_json(_url):
        raise requests.ConnectionError("official store is unavailable")

    release = _release("2.0.0", 2, ALLOWED_HASH)
    del release["assets"][0]["digest"]
    monkeypatch.setattr(generate_json, "fetch_json", fetch_json)
    monkeypatch.setattr(generate_json, "get_releases", lambda *_args: [release])

    def calculate_hash(*_args, **_kwargs):
        raise generate_json.ArtifactDownloadError("current artifact is unreachable")

    monkeypatch.setattr(generate_json, "calculate_hash", calculate_hash)
    with pytest.raises(SystemExit) as error:
        generate_json.main()
    assert error.value.code == 1
    assert not (saved_store / "public").exists()
