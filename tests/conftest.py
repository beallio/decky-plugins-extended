import sys

import pytest

import audit_plugins


@pytest.fixture(autouse=True)
def isolate_tracked_verdict_store(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(audit_plugins, "VERDICTS_FILE", "security-verdicts.json")


@pytest.fixture(autouse=True)
def no_package_version_lookups(monkeypatch):
    # The catalog loop fetches each newest tag's package.json from GitHub.
    generate_json = sys.modules.get("generate_json")
    if generate_json is not None:
        monkeypatch.setattr(
            generate_json, "warn_package_version_mismatch", lambda *_args: None
        )
