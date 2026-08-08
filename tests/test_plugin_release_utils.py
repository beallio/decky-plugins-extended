import pytest

import plugin_release_utils as pru
from plugin_release_utils import (
    get_zip_asset,
    has_exactly_one_zip,
    normalize_version,
    parse_semver,
    select_best_release,
    version_sort_key,
)


@pytest.mark.parametrize(
    ("url", "expected_url", "expected_parts"),
    [
        (
            "https://github.com/Owner/Repo",
            "https://github.com/owner/repo",
            ("owner", "repo"),
        ),
        (
            "https://GITHUB.COM/Owner/Repo/",
            "https://github.com/owner/repo",
            ("owner", "repo"),
        ),
        (
            "https://github.com/%4fwner/R%65po",
            "https://github.com/owner/repo",
            ("owner", "repo"),
        ),
    ],
)
def test_github_repository_url_canonicalization(url, expected_url, expected_parts):
    assert pru.parse_github_repository_url(url) == expected_parts
    assert pru.canonicalize_github_repository_url(url) == expected_url
    assert pru.canonical_repository_key(url) == "/".join(expected_parts)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://github.com/owner/repo?download=1",
        "https://github.com/owner/repo#readme",
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo/extra",
        "https://github.com/owner//repo",
        "https://github.com/owner%2Frepo",
        "https://github.com/owner%5Crepo",
        "https://example.com/owner/repo",
        "https://github.com.example/owner/repo",
        "owner/repo",
        " https://github.com/owner/repo",
    ],
)
def test_github_repository_url_rejects_noncanonical_or_hostile_input(url):
    with pytest.raises(ValueError, match="GitHub repository URL"):
        pru.parse_github_repository_url(url)


def _release(
    release_id,
    asset_id,
    *,
    published_at=None,
    created_at=None,
    draft=False,
    prerelease=False,
    asset_names=("plugin.zip",),
):
    return {
        "id": release_id,
        "tag_name": f"v{release_id}",
        "draft": draft,
        "prerelease": prerelease,
        "published_at": published_at,
        "created_at": created_at,
        "assets": [
            {"id": asset_id + index, "name": name}
            for index, name in enumerate(asset_names)
        ],
    }


def test_release_eligibility_is_shared_for_stable_testing_and_audit_consumers():
    stable = _release(1, 10)
    prerelease = _release(2, 20, prerelease=True)
    draft = _release(3, 30, draft=True)
    no_zip = _release(4, 40, asset_names=("notes.txt",))
    multi_zip = _release(5, 50, asset_names=("one.zip", "two.ZIP"))

    assert pru.is_release_eligible(stable, allow_prerelease=False)
    assert not pru.is_release_eligible(prerelease, allow_prerelease=False)
    assert pru.is_release_eligible(prerelease, allow_prerelease=True)
    assert not pru.is_release_eligible(draft, allow_prerelease=True)
    assert not pru.is_release_eligible(no_zip, allow_prerelease=True)
    assert not pru.is_release_eligible(multi_zip, allow_prerelease=True)


def test_ordered_eligible_releases_is_deterministic_and_missing_timestamps_sort_last():
    newest = _release(1, 10, published_at="2025-03-01T00:00:00Z")
    fallback = _release(2, 20, created_at="2025-02-01T00:00:00Z")
    higher_release_id = _release(4, 30, published_at="2025-01-01T00:00:00Z")
    higher_asset_id = _release(4, 40, published_at="2025-01-01T00:00:00Z")
    missing_timestamp = _release(999, 999)
    draft = _release(1000, 1000, draft=True, published_at="2026-01-01T00:00:00Z")

    releases = [
        missing_timestamp,
        higher_release_id,
        newest,
        draft,
        fallback,
        higher_asset_id,
    ]
    assert [
        release["assets"][0]["id"]
        for release in pru.ordered_eligible_releases(releases)
    ] == [
        10,
        20,
        40,
        30,
        999,
    ]


def test_canonical_repository_order_is_owner_repo_ascending():
    repositories = [
        "https://github.com/zeta/plugin",
        "https://github.com/Alpha/zed/",
        "https://github.com/alpha/Beta",
    ]
    assert pru.sort_repository_urls(repositories) == [
        "https://github.com/alpha/beta",
        "https://github.com/alpha/zed",
        "https://github.com/zeta/plugin",
    ]


def test_select_best_release_excludes_drafts():
    stable = _release(1, 10)
    newer_draft = _release(2, 20, draft=True)
    assert select_best_release([newer_draft, stable]) is stable


def test_normalize_github_sha256_digest_accepts_only_exact_valid_digest():
    uppercase = "A1" * 32
    assert (
        pru.normalize_github_sha256_digest(f"sha256:{uppercase}") == uppercase.lower()
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "SHA256:" + "a" * 64,
        "sha256: " + "a" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 65,
        "sha256:" + "g" * 64,
        "sha512:" + "a" * 64,
        "sha256:" + "a" * 64 + "\n",
    ],
)
def test_normalize_github_sha256_digest_rejects_malformed_values(value):
    assert pru.normalize_github_sha256_digest(value) is None


def test_select_best_release_testing_prefers_higher_prerelease():
    stable = {
        "tag_name": "v1.0.0",
        "prerelease": False,
        "assets": [
            {"name": "plugin.zip", "browser_download_url": "http://ex.com/1.0.0.zip"}
        ],
    }
    prerelease = {
        "tag_name": "v2.0.0-beta.1",
        "prerelease": True,
        "assets": [
            {
                "name": "plugin.zip",
                "browser_download_url": "http://ex.com/2.0.0-beta.1.zip",
            }
        ],
    }
    releases = [stable, prerelease]

    # For testing catalog (allow_prerelease=True), higher semver (2.0.0-beta.1) must be selected over 1.0.0.
    best = select_best_release(releases, allow_prerelease=True)
    assert best is not None
    assert best["tag_name"] == "v2.0.0-beta.1"


def test_has_exactly_one_zip_case_insensitive():
    """Verify case-insensitive ZIP asset matching and ambiguous multi-ZIP skipping.

    Decision: A release carrying both 'plugin.zip' and 'Plugin.ZIP' has 2 ZIP assets
    under case-insensitive matching. It is skipped because multiple ZIP assets are
    ambiguous. The old case-sensitive check silently picked 'plugin.zip' while ignoring
    'Plugin.ZIP'; case-insensitive matching safely rejects the release as ambiguous.
    """
    uppercase_zip = {
        "tag_name": "v1.0.0",
        "assets": [
            {"name": "Plugin.ZIP", "browser_download_url": "http://ex.com/plugin.zip"}
        ],
    }
    assert has_exactly_one_zip(uppercase_zip) is True
    assert get_zip_asset(uppercase_zip) == uppercase_zip["assets"][0]

    two_zips = {
        "tag_name": "v1.0.0",
        "assets": [
            {"name": "plugin.zip", "browser_download_url": "http://ex.com/1.zip"},
            {"name": "Plugin.ZIP", "browser_download_url": "http://ex.com/2.zip"},
        ],
    }
    assert has_exactly_one_zip(two_zips) is False
    assert get_zip_asset(two_zips) is None


def test_normalize_version():
    assert normalize_version("v1.2.3") == "1.2.3"
    assert normalize_version("Release-0.7.1") == "0.7.1"
    assert normalize_version("decky-romm-sync-v0.29.0") == "0.29.0"
    assert normalize_version("invalid") == "invalid"


def test_parse_semver():
    assert parse_semver("1.2.3") == (1, 2, 3, [])
    assert parse_semver("1.0.0-beta.1") == (1, 0, 0, [(1, 0, "beta"), (0, 1, "")])
    assert parse_semver("not-a-version") is None


def test_version_sort_key():
    k1 = version_sort_key("1.0.0")
    k2 = version_sort_key("1.0.0-beta.1")
    k3 = version_sort_key("2.0.0-beta.1")
    assert k1 > k2
    assert k3 > k1


def test_select_best_release_stable_only():
    stable = {
        "tag_name": "v1.0.0",
        "prerelease": False,
        "assets": [{"name": "plugin.zip"}],
    }
    prerelease = {
        "tag_name": "v2.0.0-beta.1",
        "prerelease": True,
        "assets": [{"name": "plugin.zip"}],
    }
    releases = [stable, prerelease]

    # For stable catalog (allow_prerelease=False), prereleases must be ignored
    best = select_best_release(releases, allow_prerelease=False)
    assert best is not None
    assert best["tag_name"] == "v1.0.0"
