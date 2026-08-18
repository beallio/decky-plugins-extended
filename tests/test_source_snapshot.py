"""tests/test_source_snapshot.py - Unit tests for immutable source snapshots."""

from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from typing import Any

import pytest

import audit_source_snapshot as ss

REPOSITORY = "https://github.com/owner/plugin"
COMMIT = "a" * 40
TOP_DIR = "owner-plugin-aaaaaaaaaa"
PLUGIN_JSON_BYTES = b'{"name": "plug"}'
PACKAGE_JSON_BYTES = b'{"name":"plugin"}'
RUN_SH_BYTES = b"#!/bin/sh\\necho hi\\n"
SYMLINK_TARGET_BYTES = b"../outside"


def _git_blob_sha1(payload: bytes) -> str:
    return hashlib.sha1(f"blob {len(payload)}\\0".encode("ascii") + payload).hexdigest()


def _policy(**overrides: Any) -> dict[str, dict[str, int]]:
    policy = {
        "downloads": {
            "release_max_bytes": 1_000_000,
            "source_max_bytes": 1_000_000,
            "connect_timeout_seconds": 2,
            "read_timeout_seconds": 3,
            "chunk_size_bytes": 4,
        },
        "archive": {
            "max_files": 10,
            "max_uncompressed_bytes": 20_000,
            "max_single_file_bytes": 5_000,
            "max_path_depth": 12,
        },
    }
    policy["archive"].update(overrides)
    return policy


def _build_tar(entries: list[tuple[str, bytes, int, str, str | None]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for path, payload, mode, kind, link_target in entries:
            info = tarfile.TarInfo(path)
            info.mode = mode
            if kind == "file":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
                continue
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = link_target or ""
                archive.addfile(info)
                continue
            if kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = link_target or "target"
                archive.addfile(info)
                continue
            if kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
                continue
            if kind == "char":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
                continue
            if kind == "block":
                info.type = tarfile.BLKTYPE
                archive.addfile(info)
                continue
            raise ValueError(f"unsupported kind: {kind}")
    return stream.getvalue()


def _valid_payload() -> bytes:
    return _build_tar(
        [
            (f"{TOP_DIR}/plugin.json", PLUGIN_JSON_BYTES, 0o644, "file", None),
            (f"{TOP_DIR}/package.json", PACKAGE_JSON_BYTES, 0o644, "file", None),
            (f"{TOP_DIR}/bin/run.sh", RUN_SH_BYTES, 0o755, "file", None),
            (f"{TOP_DIR}/link", b"ignored", 0o644, "symlink", "../outside"),
        ]
    )


@dataclass
class FakeResponse:
    status_code: int = 200
    headers: dict[str, str] | None = None
    chunks: list[bytes] | tuple[bytes, ...] | None = None
    closed: bool = False
    requested_chunk_sizes: list[int] | None = None

    def __post_init__(self) -> None:
        self.headers = self.headers or {}
        self.chunks = list(self.chunks or [])
        if self.requested_chunk_sizes is None:
            self.requested_chunk_sizes = []

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        self.requested_chunk_sizes.append(chunk_size)
        for chunk in self.chunks:
            if chunk:
                yield chunk

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeSession:
    responses: list[FakeResponse]

    def __init__(self, responses: list[FakeResponse]):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses_used: list[FakeResponse] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError(f"unexpected request to {url!r}")
        response = self.responses.pop(0)
        self.responses_used.append(response)
        return response


def test_validation_happens_before_request(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    session = FakeSession([])
    with pytest.raises(ss.SourceSnapshotError, match="Invalid GitHub repository URL"):
        ss.materialize_source_snapshot(
            "https://example.com/owner/plugin",
            COMMIT,
            tmp_path / "snapshot",
            session=session,
            policy=_policy(),
        )
    assert session.calls == []

    session = FakeSession([])
    with pytest.raises(ss.SourceSnapshotError, match="commit SHA"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            "bad-sha",
            tmp_path / "snapshot",
            session=session,
            policy=_policy(),
        )
    assert session.calls == []


def test_materialize_source_snapshot_collects_inventory_and_metadata(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()
    destination = tmp_path / "snapshot"
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        destination,
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )

    assert snapshot.repository == REPOSITORY
    assert snapshot.commit_sha == COMMIT
    assert (
        snapshot.source_url
        == f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}"
    )
    assert snapshot.source_root == str(destination)
    assert snapshot.archive_sha256 == hashlib.sha256(payload).hexdigest()
    assert snapshot.archive_size_bytes == len(payload)
    assert snapshot.plugin_json == b'{"name": "plug"}'
    assert snapshot.package_json == b'{"name":"plugin"}'
    assert snapshot.inventory == (
        ss.SourceInventoryEntry(
            path="bin/run.sh",
            kind="file",
            size_bytes=len(RUN_SH_BYTES),
            git_blob_sha1=_git_blob_sha1(RUN_SH_BYTES),
            mode="100755",
        ),
        ss.SourceInventoryEntry(
            path="link",
            kind="symlink",
            size_bytes=len(SYMLINK_TARGET_BYTES),
            git_blob_sha1=_git_blob_sha1(SYMLINK_TARGET_BYTES),
            mode="120000",
            symlink_target=SYMLINK_TARGET_BYTES.decode("utf-8"),
        ),
        ss.SourceInventoryEntry(
            path="package.json",
            kind="file",
            size_bytes=len(PACKAGE_JSON_BYTES),
            git_blob_sha1=_git_blob_sha1(PACKAGE_JSON_BYTES),
            mode="100644",
        ),
        ss.SourceInventoryEntry(
            path="plugin.json",
            kind="file",
            size_bytes=len(PLUGIN_JSON_BYTES),
            git_blob_sha1=_git_blob_sha1(PLUGIN_JSON_BYTES),
            mode="100644",
        ),
    )
    assert not (destination / "link").exists()


def test_codeload_redirect_chain_keeps_authorization_and_streams_once(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()
    session = FakeSession(
        [
            FakeResponse(status_code=302, headers={"Location": "r1"}),
            FakeResponse(status_code=302, headers={"Location": "r2"}),
            FakeResponse(chunks=[payload]),
        ]
    )
    destination = tmp_path / "snapshot"

    ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        destination,
        session=session,
        policy=_policy(),
    )

    assert len(session.calls) == 3
    assert (
        session.calls[0][0]
        == f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}"
    )
    assert session.calls[1][0].endswith("/r1")
    assert session.calls[2][0].endswith("/r2")
    for _url, kwargs in session.calls:
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["timeout"] == (2, 3)
        assert kwargs["headers"]["Authorization"] == "Bearer test-token"
    final_response = session.responses_used[-1]
    assert final_response.requested_chunk_sizes == [4]


def test_redirect_to_disallowed_host_is_rejected_before_body_read(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()
    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={"Location": "https://api.github.com/owner/plugin/tarball/v1"},
            ),
            FakeResponse(chunks=[payload]),
        ]
    )

    with pytest.raises(ss.RedirectPolicyError, match="host"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert "api.github.com" not in session.calls[-1][0]
    assert (
        session.calls[-1][0]
        == f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}"
    )
    assert session.responses_used[0].closed


def test_redirect_protocol_and_port_rejections(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()

    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={"Location": "http://codeload.github.com/owner/plugin.tar.gz"},
            ),
            FakeResponse(chunks=[payload]),
        ]
    )
    with pytest.raises(ss.RedirectPolicyError, match="non-HTTPS"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-http",
            session=session,
            policy=_policy(),
        )

    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={
                    "Location": "https://codeload.github.com:443/owner/plugin.tar.gz"
                },
            )
        ]
    )
    with pytest.raises(ss.RedirectPolicyError, match="explicit port"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-port",
            session=session,
            policy=_policy(),
        )


def test_redirect_loop_and_redirect_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()

    session = FakeSession(
        [
            FakeResponse(status_code=302, headers={"Location": "/a"}),
            FakeResponse(status_code=302, headers={"Location": "/a"}),
            FakeResponse(chunks=[payload]),
        ]
    )
    with pytest.raises(ss.RedirectPolicyError, match="loop"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-loop",
            session=session,
            policy=_policy(),
        )

    session = FakeSession(
        [
            FakeResponse(status_code=302, headers={"Location": "/a"}),
            FakeResponse(status_code=302, headers={"Location": "/b"}),
            FakeResponse(chunks=[payload]),
        ]
    )
    with pytest.raises(ss.RedirectPolicyError, match="too many redirects"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-hops",
            session=session,
            policy=_policy(),
            max_redirects=1,
        )


@pytest.mark.parametrize(
    "path_case, payload",
    [
        (
            "traversal",
            _build_tar([("../bad/plugin.json", b"{}", 0o644, "file", None)]),
        ),
        (
            "no_top",
            _build_tar([("plugin.json", b"{}", 0o644, "file", None)]),
        ),
        (
            "multi_top",
            _build_tar(
                [
                    (f"{TOP_DIR}/a.json", b"{}", 0o644, "file", None),
                    ("other/b.json", b"{}", 0o644, "file", None),
                ]
            ),
        ),
        (
            "duplicate",
            _build_tar(
                [
                    (f"{TOP_DIR}/a.json", b"{}", 0o644, "file", None),
                    (f"{TOP_DIR}/a.json", b"{}", 0o644, "file", None),
                ]
            ),
        ),
    ],
)
def test_archive_safety_rejects_layout_failures(
    tmp_path, monkeypatch, path_case, payload
):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    with pytest.raises(
        ss.SourceSnapshotError, match="unsafe archive member path|top-level|duplicate"
    ):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / path_case,
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )


@pytest.mark.parametrize("kind", ["hardlink", "fifo", "char", "block"])
def test_archive_safety_rejects_special_members(tmp_path, monkeypatch, kind):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _build_tar([(f"{TOP_DIR}/bad", b"{}", 0o644, kind, None)])
    with pytest.raises(ss.SourceSnapshotError):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / f"special-{kind}",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )


def test_archive_limits_are_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    payload = _build_tar(
        [
            (f"{TOP_DIR}/file", b"a" * 100, 0o644, "file", None),
            (f"{TOP_DIR}/small", b"{}", 0o644, "file", None),
        ]
    )
    with pytest.raises(ss.SourceSnapshotError, match="too large"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "single-file",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(max_single_file_bytes=50),
        )

    payload = _build_tar(
        [
            (f"{TOP_DIR}/a", b"1", 0o644, "file", None),
            (f"{TOP_DIR}/b", b"2", 0o644, "file", None),
        ]
    )
    with pytest.raises(ss.SourceSnapshotError, match="file count"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "max-count",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(max_files=1),
        )

    payload = _build_tar(
        [
            (f"{TOP_DIR}/a", b"12", 0o644, "file", None),
            (f"{TOP_DIR}/b", b"34", 0o644, "file", None),
        ]
    )
    with pytest.raises(ss.SourceSnapshotError, match="max uncompressed"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "max-total",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(max_uncompressed_bytes=3),
        )


def test_repeatable_inventory_and_hashes(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _valid_payload()
    first = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "first",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )
    second = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "second",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )

    assert first.inventory == second.inventory
    assert first.archive_sha256 == second.archive_sha256
    assert first.package_json == second.package_json
    assert first.plugin_json == second.plugin_json


def test_no_partial_snapshot_on_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    payload = _build_tar(
        [(f"{TOP_DIR}/../oops/plugin.json", b"{}", 0o644, "file", None)]
    )
    destination = tmp_path / "broken"

    with pytest.raises(ss.SourceSnapshotError):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            destination,
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )

    assert not destination.exists()
