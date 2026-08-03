import pytest

import audit_plugins


@pytest.fixture(autouse=True)
def isolate_tracked_verdict_store(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(audit_plugins, "VERDICTS_FILE", "security-verdicts.json")
