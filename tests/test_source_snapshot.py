"""tests/test_source_snapshot.py - Unit tests for immutable source snapshots."""

from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import audit_source_snapshot as ss

REPOSITORY = "https://github.com/owner/plugin"
COMMIT = "a" * 40
TOP_DIR = "owner-plugin-aaaaaaaaaa"
PLUGIN_JSON_BYTES = b'{"name": "plug"}'
PACKAGE_JSON_BYTES = b'{"name":"plugin"}'
RUN_SH_BYTES = b"#!/bin/sh\necho hi\n"
SYMLINK_TARGET_BYTES = b"../outside"
NON_UTF8_LINK_BYTES = b"\xffoutside"
NON_UTF8_LINK = NON_UTF8_LINK_BYTES.decode("utf-8", errors="surrogateescape")


def _git_blob_sha1(payload: bytes) -> str:
    return hashlib.sha1(f"blob {len(payload)}\0".encode("ascii") + payload).hexdigest()


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
            "max_path_depth": 5,
        },
    }
    policy["archive"].update(overrides)
    return policy


def _valid_payload() -> bytes:
    return _build_tar(
        [
            (f"{TOP_DIR}/plugin.json", PLUGIN_JSON_BYTES, 0o644, "file", None),
            (f"{TOP_DIR}/package.json", PACKAGE_JSON_BYTES, 0o644, "file", None),
            (f"{TOP_DIR}/bin/run.sh", RUN_SH_BYTES, 0o755, "file", None),
            (f"{TOP_DIR}/link", b"ignored", 0o644, "symlink", "../outside"),
        ]
    )


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
            if kind == "dir":
                info.type = tarfile.DIRTYPE
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
            if kind == "socket":
                info.type = getattr(tarfile, "SOCKTYPE", b"7")
                archive.addfile(info)
                continue
            raise ValueError(f"unsupported kind: {kind}")
    return stream.getvalue()


def _assert_no_source_snapshot_staging(tmp_root: Path) -> None:
    assert not any(
        child.is_dir() and child.name.startswith("source-snapshot-")
        for child in tmp_root.iterdir()
    )


@dataclass
class FakeResponse:
    status_code: int = 200
    headers: dict[str, str] | None = None
    chunks: list[bytes] | tuple[bytes, ...] | None = None
    closed: int = 0
    requested_chunk_sizes: list[int] | None = None
    iterated_chunks: int = 0
    close_calls: list[str] = None

    def __post_init__(self) -> None:
        self.headers = self.headers or {}
        self.chunks = list(self.chunks or [])
        if self.requested_chunk_sizes is None:
            self.requested_chunk_sizes = []
        if self.close_calls is None:
            self.close_calls = []

    def raise_for_status(self) -> None:
        if not (200 <= self.status_code < 400):
            raise RuntimeError(f"response failed: {self.status_code}")

    def iter_content(self, chunk_size: int):
        if chunk_size <= 0:
            raise AssertionError("chunk size must be positive")
        self.requested_chunk_sizes.append(chunk_size)
        for chunk in self.chunks:
            if chunk:
                self.iterated_chunks += 1
                yield chunk

    def close(self) -> None:
        self.closed += 1
        self.close_calls.append("close")


@dataclass
class FakeSession:
    responses: list[FakeResponse]
    headers: dict[str, str] | None = None

    def __init__(
        self, responses: list[FakeResponse], headers: dict[str, str] | None = None
    ):
        self.responses = list(responses)
        self.headers = {} if headers is None else dict(headers)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.responses_used: list[FakeResponse] = []

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        merged_headers = dict(self.headers)
        merged_headers.update(kwargs.get("headers") or {})
        captured = dict(kwargs)
        captured["headers"] = merged_headers
        self.calls.append((url, captured))
        if not self.responses:
            raise AssertionError(f"unexpected request to {url!r}")
        response = self.responses.pop(0)
        self.responses_used.append(response)
        return response


@pytest.mark.parametrize(
    "max_redirects",
    [4, -1, 4.0, "3", True, False],
)
def test_redirect_budget_rejected_early(tmp_path, max_redirects):
    session = FakeSession([])
    with pytest.raises(ss.SourceSnapshotError, match="max_redirects"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot",
            session=session,
            policy=_policy(),
            max_redirects=max_redirects,
        )
    assert session.calls == []


def test_validation_happens_before_request(tmp_path):
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
    source_url = f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}"
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        destination,
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )

    assert snapshot.repository == REPOSITORY
    assert snapshot.commit_sha == COMMIT
    assert snapshot.source_url == source_url
    assert snapshot.source_root == str(destination)
    assert snapshot.archive_sha256 == hashlib.sha256(payload).hexdigest()
    assert snapshot.archive_size_bytes == len(payload)
    assert snapshot.plugin_json == PLUGIN_JSON_BYTES
    assert snapshot.package_json == PACKAGE_JSON_BYTES
    assert (destination / "plugin.json").read_bytes() == PLUGIN_JSON_BYTES
    assert (destination / "package.json").read_bytes() == PACKAGE_JSON_BYTES
    assert (destination / "bin/run.sh").read_bytes() == RUN_SH_BYTES
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


def test_direct_request_response_is_released(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    destination = tmp_path / "direct"
    session = FakeSession([FakeResponse(chunks=[_valid_payload()])])

    ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        destination,
        session=session,
        policy=_policy(),
    )

    final_response = session.responses_used[0]
    assert final_response.requested_chunk_sizes == [4]
    assert final_response.closed == 1


def test_preserves_non_utf8_symlink_target_bytes(tmp_path):
    payload = _build_tar(
        [
            (f"{TOP_DIR}/plugin.json", PLUGIN_JSON_BYTES, 0o644, "file", None),
            (
                f"{TOP_DIR}/bad-link",
                b"x",
                0o644,
                "symlink",
                NON_UTF8_LINK,
            ),
        ]
    )
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "snapshot",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )

    (entry,) = (entry for entry in snapshot.inventory if entry.path == "bad-link")
    recovered = entry.symlink_target.encode("utf-8", errors="surrogateescape")
    assert recovered == NON_UTF8_LINK_BYTES
    assert entry.size_bytes == len(NON_UTF8_LINK_BYTES)
    assert entry.git_blob_sha1 == _git_blob_sha1(NON_UTF8_LINK_BYTES)
    assert entry.mode == "120000"
    assert entry.kind == "symlink"
    assert not (tmp_path / "snapshot" / "bad-link").exists()


def test_codeload_redirect_chain_keeps_authorization_and_streams_once(
    tmp_path, monkeypatch
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
    for _, kwargs in session.calls:
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["timeout"] == (2, 3)
        assert kwargs["headers"]["Authorization"] == "Bearer test-token"
    final_response = session.responses_used[-1]
    assert final_response.requested_chunk_sizes == [4]
    for response in session.responses_used:
        assert response.closed == 1


def test_redirect_chain_and_unknown_host_is_rejected_without_streaming(tmp_path):
    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={
                    "Location": "https://api.example.invalid/owner/plugin/tar.gz/v1"
                },
            )
        ]
    )

    with pytest.raises(ss.RedirectPolicyError, match="host"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-unknown-host",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert session.responses_used[0].iterated_chunks == 0
    assert session.responses_used[0].closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


def test_redirect_with_userinfo_is_rejected_without_streaming(tmp_path):
    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={"Location": "https://user:pass@codeload.github.com/x"},
            )
        ]
    )

    with pytest.raises(ss.RedirectPolicyError, match="userinfo"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-userinfo",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert session.responses_used[0].iterated_chunks == 0
    assert session.responses_used[0].closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


@pytest.mark.parametrize("location", [0, 3.14, b"/r1"])
def test_redirect_malformed_location_types_are_rejected_without_streaming(
    tmp_path, location
):
    session = FakeSession(
        [
            FakeResponse(status_code=302, headers={"Location": location}),
            FakeResponse(chunks=[_valid_payload()]),
        ]
    )

    with pytest.raises(
        ss.RedirectPolicyError, match="missing or malformed redirect location"
    ):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-malformed-location",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert session.responses_used[0].iterated_chunks == 0
    assert session.responses_used[0].closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


def test_session_and_header_authorization_is_not_reused_for_request_scope(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    session = FakeSession(
        [FakeResponse(chunks=[_valid_payload()])],
        headers={"Authorization": "Bearer session-token", "X-From": "session"},
    )

    wrapped = ss._codeload_session(session, max_redirects=0)
    response = wrapped.get(
        f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}",
        headers={"Authorization": "Bearer caller-token", "X-From": "caller"},
    )
    try:
        assert response.status_code == 200
        captured_headers = session.calls[0][1]["headers"]
        assert captured_headers["Authorization"] == "Bearer test-token"
        assert captured_headers["X-From"] == "caller"
    finally:
        response.close()
    assert response.closed == 1


def test_session_auth_hook_is_disabled_for_source_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    class SessionWithAuth(FakeSession):
        def __init__(
            self, responses: list[FakeResponse], headers: dict[str, str] | None = None
        ):
            super().__init__(responses, headers=headers)
            self.auth = ("user", "password")
            self.observed_auth: list[Any] = []

        def get(self, url: str, **kwargs: Any) -> FakeResponse:
            self.observed_auth.append(getattr(self, "auth", None))
            return super().get(url, **kwargs)

    session = SessionWithAuth([FakeResponse(chunks=[_valid_payload()])])
    wrapped = ss._codeload_session(session, max_redirects=0)
    response = wrapped.get(
        f"https://codeload.github.com/owner/plugin/tar.gz/{COMMIT}",
        headers={"X-From": "caller"},
    )
    try:
        assert response.status_code == 200
        assert session.observed_auth == [None]
        captured_headers = session.calls[0][1]["headers"]
        assert captured_headers["Authorization"] == "Bearer test-token"
    finally:
        response.close()
        assert response.closed == 1
        assert session.auth == ("user", "password")


def test_redirect_chain_and_disallowed_hosts_do_not_iterate_rejected_body(tmp_path):
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
    rejected = session.responses_used[0]
    assert rejected.iterated_chunks == 0
    assert rejected.closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


def test_redirect_protocol_port_and_host_validation(tmp_path):
    session = FakeSession(
        [
            FakeResponse(
                status_code=302, headers={"Location": "http://codeload.github.com/x"}
            )
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
                headers={"Location": "https://codeload.github.com:443/x"},
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

    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={"Location": "https://codeload.github.com:bad/x"},
            )
        ]
    )
    with pytest.raises(ss.RedirectPolicyError, match="invalid redirect URL port"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-bad-port",
            session=session,
            policy=_policy(),
        )


def test_redirect_status_policy_is_closed_and_no_next_hop(monkeypatch, tmp_path):
    session = FakeSession(
        [
            FakeResponse(status_code=304),
            FakeResponse(
                status_code=200,
                chunks=[_valid_payload()],
            ),
        ]
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    with pytest.raises(ss.RedirectPolicyError, match="unsupported redirect status"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-unsupported",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert session.responses_used[0].closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


def test_redirect_loop_and_limit_rejections(tmp_path):
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


def test_missing_or_malformed_redirect_location_is_rejected(tmp_path):
    payload = _valid_payload()
    session = FakeSession(
        [
            FakeResponse(
                status_code=302,
                headers={},
            ),
            FakeResponse(chunks=[payload]),
        ]
    )
    with pytest.raises(
        ss.RedirectPolicyError, match="missing or malformed redirect location"
    ):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "snapshot-location",
            session=session,
            policy=_policy(),
        )
    assert len(session.calls) == 1
    assert session.responses_used[0].iterated_chunks == 0
    assert session.responses_used[0].closed == 1
    _assert_no_source_snapshot_staging(tmp_path)


def test_session_authorization_header_is_stripped_from_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    session = FakeSession(
        [FakeResponse(chunks=[_valid_payload()])],
        headers={"Authorization": "Bearer session-token", "X-From": "session"},
    )
    ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "snapshot",
        session=session,
        policy=_policy(),
    )

    assert "Authorization" not in session.calls[0][1]["headers"]


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
        (
            "type-conflict",
            _build_tar(
                [
                    (f"{TOP_DIR}/node", b"{}", 0o644, "file", None),
                    (f"{TOP_DIR}/node", b"", 0o755, "dir", None),
                ]
            ),
        ),
        (
            "ancestor-before-descendant",
            _build_tar(
                [
                    (f"{TOP_DIR}/node", b"{}", 0o644, "file", None),
                    (f"{TOP_DIR}/node/child", b"{}", 0o644, "file", None),
                ]
            ),
        ),
        (
            "descendant-before-ancestor",
            _build_tar(
                [
                    (f"{TOP_DIR}/node/child", b"{}", 0o644, "file", None),
                    (f"{TOP_DIR}/node", b"{}", 0o644, "file", None),
                ]
            ),
        ),
        (
            "symlink-ancestor",
            _build_tar(
                [
                    (
                        f"{TOP_DIR}/link",
                        b"",
                        0o644,
                        "symlink",
                        "../outside",
                    ),
                    (f"{TOP_DIR}/link/child", b"{}", 0o644, "file", None),
                ]
            ),
        ),
        (
            "absolute-path",
            _build_tar([(f"/{TOP_DIR}/bad", b"{}", 0o644, "file", None)]),
        ),
        (
            "backslash-path",
            _build_tar([("owner\\plugin\\bad", b"{}", 0o644, "file", None)]),
        ),
        (
            "windows-drive-path",
            _build_tar([("C:dir/bad", b"{}", 0o644, "file", None)]),
        ),
        (
            "over-depth",
            _build_tar(
                [
                    (
                        f"{TOP_DIR}/a/b/c/d/e/f/g",
                        b"{}",
                        0o644,
                        "file",
                        None,
                    )
                ]
            ),
        ),
    ],
)
def test_archive_safety_rejects_layout_and_path_failures(tmp_path, path_case, payload):
    with pytest.raises(
        ss.SourceSnapshotError,
        match="unsafe archive member path|invalid archive member path|top-level|duplicate|ambiguous|must contain|archive path too deep|archive member",
    ):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / path_case,
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(max_path_depth=3),
        )


def test_archive_safety_allows_explicit_directory_ancestors(tmp_path):
    payload = _build_tar(
        [
            (f"{TOP_DIR}", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/sub", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/sub/file", b"{}", 0o644, "file", None),
        ]
    )
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "explicit-dir",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )
    assert snapshot.inventory == (
        ss.SourceInventoryEntry(
            path="sub/file",
            kind="file",
            size_bytes=2,
            git_blob_sha1=_git_blob_sha1(b"{}"),
            mode="100644",
        ),
    )


def test_archive_safety_allows_directory_headers_after_child_entries(tmp_path):
    payload = _build_tar(
        [
            (f"{TOP_DIR}/sub/file", b"{}", 0o644, "file", None),
            (f"{TOP_DIR}", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/sub", b"", 0o755, "dir", None),
        ]
    )
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "explicit-dir-after-child",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(),
    )
    assert snapshot.inventory == (
        ss.SourceInventoryEntry(
            path="sub/file",
            kind="file",
            size_bytes=2,
            git_blob_sha1=_git_blob_sha1(b"{}"),
            mode="100644",
        ),
    )


def test_archive_safety_rejects_no_regular_files(tmp_path):
    payload = _build_tar(
        [
            (f"{TOP_DIR}/link", b"ignored", 0o644, "symlink", "../outside"),
            (f"{TOP_DIR}/other", b"", 0o644, "symlink", "../outside2"),
        ]
    )
    with pytest.raises(ss.SourceSnapshotError, match="no regular files"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "no-regular",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )


def test_invalid_tarball_is_reported_and_staging_is_cleaned(tmp_path):
    payload = b"not-a-tarball"
    with pytest.raises(ss.SourceSnapshotError, match="malformed or unreadable"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "invalid",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )
    _assert_no_source_snapshot_staging(tmp_path)


@pytest.mark.parametrize("kind", ["hardlink", "fifo", "char", "block", "socket"])
def test_archive_safety_rejects_special_members(tmp_path, kind):
    payload = _build_tar([(f"{TOP_DIR}/bad", b"{}", 0o644, kind, None)])
    with pytest.raises(ss.SourceSnapshotError):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / f"special-{kind}",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(),
        )


def test_archive_limits_are_enforced(tmp_path):
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

    payload = _build_tar(
        [
            (f"{TOP_DIR}", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/dir-a", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/dir-b", b"", 0o755, "dir", None),
            (f"{TOP_DIR}/file", b"{}", 0o644, "file", None),
        ]
    )
    snapshot = ss.materialize_source_snapshot(
        REPOSITORY,
        COMMIT,
        tmp_path / "max-count-includes-dirs",
        session=FakeSession([FakeResponse(chunks=[payload])]),
        policy=_policy(max_files=4),
    )
    assert any(item.path == "file" for item in snapshot.inventory)
    with pytest.raises(ss.SourceSnapshotError, match="file count"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            tmp_path / "max-count-includes-dirs-over",
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(max_files=3),
        )


def test_repeatable_inventory_and_hashes(tmp_path):
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


def test_no_partial_snapshot_on_failure(tmp_path):
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
            policy=_policy(
                max_single_file_bytes=ss._SOURCE_METADATA_BYTE_LIMIT + 2,
                max_uncompressed_bytes=(ss._SOURCE_METADATA_BYTE_LIMIT + 2) * 2,
            ),
        )

    assert not destination.exists()
    _assert_no_source_snapshot_staging(tmp_path)


def test_destination_survives_promotion_race_and_cleanup_staging(tmp_path, monkeypatch):
    destination = tmp_path / "snapshot"
    destination.mkdir()
    with pytest.raises(ss.SourceSnapshotError, match="destination already exists"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            destination,
            session=FakeSession([FakeResponse(chunks=[_valid_payload()])]),
            policy=_policy(),
        )
    _assert_no_source_snapshot_staging(tmp_path)


def test_destination_survives_promotion_race_and_cleanup(tmp_path, monkeypatch):
    payload = _valid_payload()
    destination = tmp_path / "snapshot"
    original_rename = ss._rename_without_replace
    destination_inodes: list[int] = []

    def raced_rename(src: Path, dst: Path) -> None:
        if dst != destination:
            return original_rename(src, dst)
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "sentinel").write_text("preserve")
        destination_inodes.append(dst.stat().st_ino)
        return original_rename(src, dst)

    monkeypatch.setattr(ss, "_rename_without_replace", raced_rename)
    with pytest.raises(ss.SourceSnapshotError, match="destination already exists"):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            destination,
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(
                max_single_file_bytes=ss._SOURCE_METADATA_BYTE_LIMIT + 2,
                max_uncompressed_bytes=(ss._SOURCE_METADATA_BYTE_LIMIT + 2) * 2,
            ),
        )

    assert destination.exists()
    assert destination_inodes == [destination.stat().st_ino]
    assert (destination / "sentinel").read_text() == "preserve"
    _assert_no_source_snapshot_staging(tmp_path)


def test_file_and_symlink_ancestry_rejections_keep_extraction_on_preflight_seam(
    tmp_path, monkeypatch
):
    bad_payloads = [
        _build_tar(
            [
                (f"{TOP_DIR}/node", b"{}", 0o644, "file", None),
                (f"{TOP_DIR}/node/child", b"{}", 0o644, "file", None),
            ]
        ),
        _build_tar(
            [
                (f"{TOP_DIR}/node/child", b"{}", 0o644, "file", None),
                (f"{TOP_DIR}/node", b"{}", 0o644, "file", None),
            ]
        ),
        _build_tar(
            [
                (f"{TOP_DIR}/link", b"{}", 0o644, "symlink", "../outside"),
                (f"{TOP_DIR}/link/child", b"{}", 0o644, "file", None),
            ]
        ),
        _build_tar(
            [
                (f"{TOP_DIR}/link/child", b"{}", 0o644, "file", None),
                (f"{TOP_DIR}/link", b"{}", 0o644, "symlink", "../outside"),
            ]
        ),
    ]

    called = False

    def blocked_extract_source_archive(
        archive_path: Path,
        destination: Path,
        planned: list[tuple[tarfile.TarInfo, str, str, str | None]],
    ) -> None:
        nonlocal called
        called = True
        raise AssertionError("extraction seam should not run after ambiguous paths")

    monkeypatch.setattr(ss, "_extract_source_archive", blocked_extract_source_archive)
    for index, payload in enumerate(bad_payloads):
        called = False
        with pytest.raises(ss.SourceSnapshotError, match="ambiguous archive path"):
            ss.materialize_source_snapshot(
                REPOSITORY,
                COMMIT,
                tmp_path / f"ancestry-{index}",
                session=FakeSession([FakeResponse(chunks=[payload])]),
                policy=_policy(),
            )
        assert not called
        _assert_no_source_snapshot_staging(tmp_path)


def test_root_metadata_capture_limit_is_enforced_in_full_materializer_path(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(ss, "_SOURCE_STREAM_CHUNK_SIZE", 4)
    payload = _build_tar(
        [
            (
                f"{TOP_DIR}/plugin.json",
                b"y" * (ss._SOURCE_METADATA_BYTE_LIMIT + 1),
                0o644,
                "file",
                None,
            ),
            (f"{TOP_DIR}/package.json", b"{}", 0o644, "file", None),
            (f"{TOP_DIR}/bin/run.sh", b"{}", 0o755, "file", None),
        ]
    )
    destination = tmp_path / "metadata-limit"
    with pytest.raises(
        ss.SourceSnapshotError,
        match="metadata file too large for bounded capture",
    ):
        ss.materialize_source_snapshot(
            REPOSITORY,
            COMMIT,
            destination,
            session=FakeSession([FakeResponse(chunks=[payload])]),
            policy=_policy(
                max_single_file_bytes=ss._SOURCE_METADATA_BYTE_LIMIT + 2,
                max_uncompressed_bytes=(ss._SOURCE_METADATA_BYTE_LIMIT + 2) * 2,
            ),
        )
    assert not destination.exists()
    _assert_no_source_snapshot_staging(tmp_path)


def test_extract_regular_member_uses_chunked_reads_and_closes_stream(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(ss, "_SOURCE_STREAM_CHUNK_SIZE", 4)
    payload = _build_tar(
        [
            (
                f"{TOP_DIR}/plugin.json",
                b"x" * 17,
                0o644,
                "file",
                None,
            ),
        ]
    )
    archive_path = tmp_path / "archive.tar.gz"
    archive_path.write_bytes(payload)
    with tarfile.open(archive_path, "r:*") as archive:
        member = next(
            m
            for m in archive.getmembers()
            if m.isfile() and m.name.endswith("plugin.json")
        )
        stream = archive.extractfile(member)

        assert stream is not None
        read_sizes: list[int] = []

        class GuardedStream:
            def read(self, size: int = -1):
                if size <= 0:
                    raise AssertionError("read must use explicit positive size")
                read_sizes.append(size)
                return stream.read(size)

            def close(self) -> None:
                stream.close()

        destination = tmp_path / "extracted"
        destination.mkdir()
        entry, metadata = ss._extract_regular_member(
            archive_stream=GuardedStream(),
            destination_parent=destination,
            member=member,
            normalized_path=member.name,
            size=member.size,
            capture_metadata=True,
        )
    assert entry.path == "plugin.json"
    assert entry.mode == "100644"
    assert entry.size_bytes == 17
    assert entry.git_blob_sha1 == _git_blob_sha1(b"x" * 17)
    assert metadata == b"x" * 17
    assert len(read_sizes) >= 3
    assert read_sizes[0] == 4
    assert all(chunk_size > 0 for chunk_size in read_sizes)


def test_extract_regular_member_enforces_metadata_capture_limit(tmp_path):
    oversized = b"y" * (ss._SOURCE_METADATA_BYTE_LIMIT + 1)
    payload = _build_tar(
        [
            (
                f"{TOP_DIR}/plugin.json",
                oversized,
                0o644,
                "file",
                None,
            ),
        ]
    )

    archive_path = tmp_path / "oversized.tar.gz"
    archive_path.write_bytes(payload)
    with tarfile.open(archive_path, "r:*") as archive:
        member = next(
            m
            for m in archive.getmembers()
            if m.isfile() and m.name.endswith("plugin.json")
        )
        stream = archive.extractfile(member)
        assert stream is not None

        destination = tmp_path / "too-large-metadata"
        destination.mkdir()
        with pytest.raises(
            ss.SourceSnapshotError,
            match="metadata file too large for bounded capture",
        ):
            ss._extract_regular_member(
                archive_stream=stream,
                destination_parent=destination,
                member=member,
                normalized_path=member.name,
                size=member.size,
                capture_metadata=True,
            )


def test_midstream_read_failure_cleans_staging_and_destination(tmp_path):
    payload = _build_tar(
        [
            (f"{TOP_DIR}/plugin.json", b"{0}" * 100, 0o644, "file", None),
        ]
    )
    archive_path = tmp_path / "archive.tar.gz"
    archive_path.write_bytes(payload)
    destination = tmp_path / "snapshot"

    class FailingStream:
        def __init__(self, inner: Any):
            self.inner = inner
            self.calls = 0

        def read(self, size: int):
            self.calls += 1
            if self.calls > 1:
                raise RuntimeError("forced failure")
            return self.inner.read(size)

        def close(self) -> None:
            self.inner.close()

    class GuardedArchive:
        def __init__(self, file_path: Any, mode: str):
            self._archive = original_open(file_path, mode)

        def __enter__(self):
            return self

        def __exit__(self, *exc: Any) -> None:
            self._archive.__exit__(*exc)

        def getmembers(self):
            return self._archive.getmembers()

        def extractfile(self, member: tarfile.TarInfo):
            stream = self._archive.extractfile(member)
            if stream is None:
                return None
            return FailingStream(stream)

    original_open = tarfile.open

    def open_guarded(file_path: Any, mode: str, *args: Any, **kwargs: Any):
        if mode != "r:*":
            return original_open(file_path, mode, *args, **kwargs)
        return GuardedArchive(file_path, mode)

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(tarfile, "open", open_guarded)
        with pytest.raises(RuntimeError, match="forced failure"):
            ss.materialize_source_snapshot(
                REPOSITORY,
                COMMIT,
                destination,
                session=FakeSession([FakeResponse(chunks=[payload])]),
                policy=_policy(),
            )
    finally:
        monkeypatch.undo()

    assert not destination.exists()
    _assert_no_source_snapshot_staging(tmp_path)
