"""Behavioral coverage for the official catalog pair snapshot helper."""

import json

import pytest
import requests

import store_catalog

CAPTURED_AT = "2026-10-16T12:30:45+00:00"
STABLE_URL = "https://plugins.example/plugins"
TESTING_URL = "https://testing.example/plugins"


def _plugin(name="Official Plugin", plugin_id=7):
    # Version identity fields intentionally belong to the current consumers'
    # security checks, not this shared pair/snapshot shape validator.
    return {"id": plugin_id, "name": name, "versions": [{"name": "v1.0.0"}]}


def _write_snapshot(path, stable=None, testing=None, captured_at=CAPTURED_AT):
    catalogs = store_catalog.OfficialCatalogs(
        stable=[] if stable is None else stable,
        testing=[] if testing is None else testing,
        captured_at=captured_at,
    )
    path.write_text(store_catalog.render_snapshot(catalogs), encoding="utf-8")


def _fetch_from(stable, testing):
    return lambda url: stable if url == STABLE_URL else testing


def test_empty_official_channels_are_valid():
    rendered = store_catalog.render_snapshot(
        store_catalog.OfficialCatalogs([], [], CAPTURED_AT)
    )
    assert json.loads(rendered)["stable"] == []
    assert json.loads(rendered)["testing"] == []


@pytest.mark.parametrize("failure_url", [STABLE_URL, TESTING_URL])
def test_fetch_failure_uses_only_the_complete_saved_pair(tmp_path, failure_url):
    saved_stable = [_plugin("Saved stable")]
    saved_testing = [_plugin("Saved testing", plugin_id=8)]
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, saved_stable, saved_testing)
    original_bytes = path.read_bytes()
    fresh_stable = [_plugin("Fresh stable")]
    calls = []

    def fetch_json(url):
        calls.append(url)
        if url == failure_url:
            raise requests.ConnectionError("official endpoint unavailable")
        return fresh_stable if url == STABLE_URL else [_plugin("Fresh testing")]

    with pytest.warns(store_catalog.StoreCatalogWarning):
        catalogs = store_catalog.fetch_catalogs(
            fetch_json, STABLE_URL, TESTING_URL, snapshot_path=path
        )

    assert catalogs.stable == saved_stable
    assert catalogs.testing == saved_testing
    assert catalogs.captured_at == CAPTURED_AT
    assert catalogs.from_snapshot is True
    assert calls == (
        [STABLE_URL] if failure_url == STABLE_URL else [STABLE_URL, TESTING_URL]
    )
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "decode_error",
    [
        json.JSONDecodeError("invalid catalog JSON", "{", 0),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ],
)
def test_invalid_json_response_falls_back_to_saved_pair(tmp_path, decode_error):
    saved_stable = [_plugin("Saved")]
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, saved_stable, [])

    def fetch_json(_url):
        raise decode_error

    with pytest.warns(store_catalog.StoreCatalogWarning):
        catalogs = store_catalog.fetch_catalogs(
            fetch_json, STABLE_URL, TESTING_URL, snapshot_path=path
        )

    assert catalogs.stable == saved_stable
    assert catalogs.testing == []
    assert catalogs.from_snapshot is True


def test_invalid_live_catalog_structure_falls_back_to_saved_pair(tmp_path):
    saved_stable = [_plugin("Saved")]
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, saved_stable, [])
    calls = []

    def fetch_json(url):
        calls.append(url)
        if url == STABLE_URL:
            return [{"id": True, "name": "Invalid id", "versions": []}]
        return []

    with pytest.warns(store_catalog.StoreCatalogWarning):
        catalogs = store_catalog.fetch_catalogs(
            fetch_json, STABLE_URL, TESTING_URL, snapshot_path=path
        )

    assert calls == [STABLE_URL, TESTING_URL]
    assert catalogs.stable == saved_stable
    assert catalogs.testing == []
    assert catalogs.from_snapshot is True


@pytest.mark.parametrize("snapshot_state", ["missing", "malformed-json", "bad-schema"])
def test_outage_without_a_valid_saved_pair_is_fatal(tmp_path, snapshot_state):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    if snapshot_state == "malformed-json":
        path.write_text("{", encoding="utf-8")
    elif snapshot_state == "bad-schema":
        path.write_text(json.dumps({"stable": [], "testing": []}), encoding="utf-8")

    def fetch_json(_url):
        raise requests.Timeout("official endpoint timed out")

    with pytest.raises(store_catalog.SnapshotError):
        store_catalog.fetch_catalogs(
            fetch_json, STABLE_URL, TESTING_URL, snapshot_path=path
        )

    assert path.exists() is (snapshot_state != "missing")


@pytest.mark.parametrize(
    "captured_at",
    ["2026-10-16T12:30:45", "2026-10-16T12:30:45+01:00", "not-a-timestamp"],
)
def test_snapshot_rejects_naive_or_non_utc_capture_time(tmp_path, captured_at):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    path.write_text(
        json.dumps({"stable": [], "testing": [], "captured_at": captured_at}),
        encoding="utf-8",
    )

    with pytest.raises(store_catalog.SnapshotError):
        store_catalog.load_snapshot(path)


def test_unchanged_live_pair_retains_capture_time_without_writing(tmp_path):
    saved_stable = [_plugin()]
    saved_testing = [_plugin("Testing", plugin_id=8)]
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, saved_stable, saved_testing)
    original_bytes = path.read_bytes()
    live_stable = [
        {"versions": [{"name": "v1.0.0"}], "name": "Official Plugin", "id": 7}
    ]
    live_testing = [{"versions": [{"name": "v1.0.0"}], "name": "Testing", "id": 8}]

    catalogs = store_catalog.fetch_catalogs(
        _fetch_from(live_stable, live_testing),
        STABLE_URL,
        TESTING_URL,
        snapshot_path=path,
    )

    assert catalogs.stable == saved_stable
    assert catalogs.testing == saved_testing
    assert catalogs.captured_at == CAPTURED_AT
    assert catalogs.from_snapshot is False
    assert path.read_bytes() == original_bytes


def test_changed_live_pair_gets_a_fresh_capture_time(tmp_path):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    previous_time = "2000-01-01T00:00:00+00:00"
    _write_snapshot(path, [_plugin("Previous")], [], captured_at=previous_time)

    catalogs = store_catalog.fetch_catalogs(
        _fetch_from([_plugin("Current")], []),
        STABLE_URL,
        TESTING_URL,
        snapshot_path=path,
    )

    assert catalogs.stable == [_plugin("Current")]
    assert catalogs.captured_at != previous_time
    assert catalogs.from_snapshot is False


def test_healthy_live_pair_recovers_from_corrupt_snapshot_without_writing(tmp_path):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    path.write_text("broken snapshot", encoding="utf-8")
    original_bytes = path.read_bytes()
    stable = [_plugin("Recovered stable")]
    testing = [_plugin("Recovered testing", plugin_id=8)]

    catalogs = store_catalog.fetch_catalogs(
        _fetch_from(stable, testing),
        STABLE_URL,
        TESTING_URL,
        snapshot_path=path,
    )

    assert catalogs.stable == stable
    assert catalogs.testing == testing
    assert catalogs.from_snapshot is False
    assert path.read_bytes() == original_bytes

    # The discovery publisher can use the healthy result to replace the bad file.
    repaired = tmp_path / "repaired.json"
    repaired.write_text(store_catalog.render_snapshot(catalogs), encoding="utf-8")
    loaded = store_catalog.load_snapshot(repaired)
    assert loaded.stable == stable
    assert loaded.testing == testing
    assert loaded.from_snapshot is True


def test_healthy_live_pair_recovers_from_missing_snapshot(tmp_path):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    stable = [_plugin("Recovered")]

    catalogs = store_catalog.fetch_catalogs(
        _fetch_from(stable, []), STABLE_URL, TESTING_URL, snapshot_path=path
    )

    assert catalogs.stable == stable
    assert catalogs.testing == []
    assert catalogs.from_snapshot is False
    assert path.exists() is False


def test_separate_snapshot_loads_do_not_share_mutable_catalog_data(tmp_path):
    stable = [_plugin()]
    stable[0]["versions"][0]["metadata"] = {"nested": ["original"]}
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, stable, [_plugin("Testing", plugin_id=8)])

    first = store_catalog.load_snapshot(path)
    second = store_catalog.load_snapshot(path)
    first.stable[0]["name"] = "mutated"
    first.stable[0]["versions"][0]["metadata"]["nested"].append("changed")
    first.testing.clear()

    assert second.stable[0]["name"] == "Official Plugin"
    assert second.stable[0]["versions"][0]["metadata"]["nested"] == ["original"]
    assert second.testing == [_plugin("Testing", plugin_id=8)]


@pytest.mark.parametrize(
    "error",
    [ValueError("security validation failed"), RuntimeError("unrelated failure")],
)
def test_unrelated_and_security_errors_are_not_swallowed(tmp_path, error):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, [_plugin("Saved")], [])

    def fetch_json(_url):
        raise error

    with pytest.raises(type(error), match=str(error)):
        store_catalog.fetch_catalogs(
            fetch_json, STABLE_URL, TESTING_URL, snapshot_path=path
        )


def test_counter_only_changes_do_not_replace_saved_snapshot(tmp_path):
    saved = [_plugin()]
    saved[0]["downloads"] = 10
    saved[0]["versions"][0]["updates"] = 20
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, saved, [])
    original = path.read_text()
    live = json.loads(json.dumps(saved))
    live[0]["downloads"] = 100
    live[0]["versions"][0]["updates"] = 200

    rendered = store_catalog.render_snapshot(
        store_catalog.OfficialCatalogs(live, [], "2026-10-17T12:00:00Z"),
        previous_path=path,
    )

    assert rendered == original
    assert live[0]["downloads"] == 100
    assert live[0]["versions"][0]["updates"] == 200


@pytest.mark.parametrize("change", ["version-hash", "version-name", "description"])
def test_snapshot_publication_preserves_release_and_metadata_changes(tmp_path, change):
    path = tmp_path / store_catalog.SNAPSHOT_FILE
    _write_snapshot(path, [_plugin()], [])
    live = [_plugin()]
    if change == "description":
        live[0]["description"] = "New official description"
    elif change == "version-name":
        live[0]["versions"][0]["name"] = "v2.0.0"
    else:
        live[0]["versions"][0]["hash"] = "a" * 64

    rendered = json.loads(
        store_catalog.render_snapshot(
            store_catalog.OfficialCatalogs(live, [], "2026-10-17T12:00:00Z"),
            previous_path=path,
        )
    )

    assert rendered["stable"] == live
    assert rendered["captured_at"] == "2026-10-17T12:00:00Z"
