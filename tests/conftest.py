import pytest

import audit_plugins


@pytest.fixture(autouse=True)
def isolate_tracked_verdict_store(monkeypatch, tmp_path):
    monkeypatch.setattr(
        audit_plugins,
        "VERDICTS_FILE",
        str(tmp_path / "security-verdicts.json"),
    )
