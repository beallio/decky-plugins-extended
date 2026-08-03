from plugin_release_utils import (
    get_zip_asset,
    has_exactly_one_zip,
    normalize_version,
    parse_semver,
    select_best_release,
    version_sort_key,
)


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
