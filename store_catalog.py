"""Fetch, validate, and render the official Decky store catalog pair."""

from __future__ import annotations

import json
import os
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import requests

SNAPSHOT_FILE = "store_catalogs.json"


class CatalogValidationError(ValueError):
    """An official channel does not have the required catalog structure."""


class SnapshotError(ValueError):
    """The saved official catalog pair is missing or cannot be validated."""


class StoreCatalogWarning(RuntimeWarning):
    """Live official catalogs were unavailable and a saved pair is in use."""


@dataclass
class OfficialCatalogs:
    stable: list[dict]
    testing: list[dict]
    captured_at: str
    from_snapshot: bool = False


def _validate_channel(channel: object, channel_name: str) -> list[dict]:
    if not isinstance(channel, list):
        raise CatalogValidationError(f"{channel_name} catalog must be a list")

    for index, plugin in enumerate(channel):
        label = f"{channel_name} catalog entry {index}"
        if not isinstance(plugin, dict):
            raise CatalogValidationError(f"{label} must be an object")
        if type(plugin.get("id")) is not int:
            raise CatalogValidationError(f"{label} must have an integer id")
        name = plugin.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CatalogValidationError(f"{label} must have a nonempty name")
        versions = plugin.get("versions")
        if not isinstance(versions, list) or any(
            not isinstance(version, dict) for version in versions
        ):
            raise CatalogValidationError(f"{label} versions must be a list of objects")

    return channel


def _validate_captured_at(value: object) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError("captured_at must be an aware UTC timestamp")
    try:
        timestamp = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
        offset = timestamp.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise CatalogValidationError(
            "captured_at must be an aware UTC timestamp"
        ) from exc
    if timestamp.tzinfo is None or offset is None or offset != timedelta(0):
        raise CatalogValidationError("captured_at must be an aware UTC timestamp")
    return value


def _validate_pair(stable: object, testing: object) -> tuple[list[dict], list[dict]]:
    return (
        _validate_channel(stable, "stable"),
        _validate_channel(testing, "testing"),
    )


def _new_capture_time() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_snapshot(path: str | Path = SNAPSHOT_FILE) -> OfficialCatalogs:
    """Load a complete, validated saved official stable/testing catalog pair."""
    try:
        with open(path, "r", encoding="utf-8") as snapshot_file:
            document = json.load(snapshot_file)
    except FileNotFoundError as exc:
        raise SnapshotError(f"official catalog snapshot is missing: {path}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SnapshotError(f"official catalog snapshot is malformed: {path}") from exc

    if not isinstance(document, dict) or set(document) != {
        "stable",
        "testing",
        "captured_at",
    }:
        raise SnapshotError(
            "official catalog snapshot must contain only stable, testing, and captured_at"
        )

    try:
        stable, testing = _validate_pair(document["stable"], document["testing"])
        captured_at = _validate_captured_at(document["captured_at"])
    except CatalogValidationError as exc:
        raise SnapshotError(f"official catalog snapshot is invalid: {exc}") from exc

    return OfficialCatalogs(
        stable=stable,
        testing=testing,
        captured_at=captured_at,
        from_snapshot=True,
    )


def _catalog_content(channel: list[dict]) -> list[dict]:
    """Exclude only popularity counters when deciding whether to save a revision."""
    return [
        {
            **{
                key: value
                for key, value in plugin.items()
                if key not in {"downloads", "updates", "versions"}
            },
            "versions": [
                {
                    key: value
                    for key, value in version.items()
                    if key not in {"downloads", "updates"}
                }
                for version in plugin["versions"]
            ],
        }
        for plugin in channel
    ]


def render_snapshot(
    catalogs: OfficialCatalogs, *, previous_path: str | Path | None = None
) -> str:
    """Save raw official data without publishing revisions for counter-only changes."""
    stable, testing = _validate_pair(catalogs.stable, catalogs.testing)
    captured_at = _validate_captured_at(catalogs.captured_at)
    if previous_path is not None:
        try:
            previous = load_snapshot(previous_path)
        except SnapshotError:
            previous = None
        if (
            previous is not None
            and _catalog_content(stable) == _catalog_content(previous.stable)
            and _catalog_content(testing) == _catalog_content(previous.testing)
        ):
            stable, testing = previous.stable, previous.testing
            captured_at = previous.captured_at
    return (
        json.dumps(
            {
                "stable": stable,
                "testing": testing,
                "captured_at": captured_at,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def fetch_catalogs(
    fetch_json: Callable[[str], object],
    stable_url: str,
    testing_url: str,
    *,
    snapshot_path: str | Path = SNAPSHOT_FILE,
) -> OfficialCatalogs:
    """Fetch both official channels or return the complete saved pair on outage.

    The caller owns publication of the returned snapshot. This helper never
    writes files, so an unsuccessful or recovered fetch cannot publish partial
    state.
    """
    try:
        stable_payload = fetch_json(stable_url)
        testing_payload = fetch_json(testing_url)
        stable, testing = _validate_pair(stable_payload, testing_payload)
    except (
        requests.RequestException,
        json.JSONDecodeError,
        UnicodeDecodeError,
        CatalogValidationError,
    ) as exc:
        snapshot = load_snapshot(snapshot_path)
        message = (
            f"Official Decky catalog fetch failed ({exc}); using the complete "
            f"saved pair captured at {snapshot.captured_at}."
        )
        warnings.warn(message, StoreCatalogWarning, stacklevel=2)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            annotation = (
                message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            )
            print(f"::warning::{annotation}")
        return snapshot

    try:
        previous = load_snapshot(snapshot_path)
    except SnapshotError:
        previous = None

    captured_at = (
        previous.captured_at
        if previous is not None
        and stable == previous.stable
        and testing == previous.testing
        else _new_capture_time()
    )
    return OfficialCatalogs(
        stable=stable,
        testing=testing,
        captured_at=captured_at,
        from_snapshot=False,
    )
