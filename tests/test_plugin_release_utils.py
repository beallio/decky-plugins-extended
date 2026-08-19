import subprocess
import sys
from pathlib import Path

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
        "https://github.com:/owner/repo",
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


@pytest.mark.parametrize(
    "repository_path",
    [
        "owner/repo%3Fquery",
        "owner/repo%23fragment",
        "owner/repo%252Fextra",
        "%2E%2E/repo",
        "owner/%2E",
        "owner/repo%00control",
    ],
)
def test_github_url_parsers_reject_decoded_delimiters_and_traversal_atoms(
    repository_path,
):
    repository_url = f"https://github.com/{repository_path}"
    release_asset_url = (
        f"https://github.com/{repository_path}/releases/download/v1/plugin.zip"
    )

    with pytest.raises(ValueError, match="GitHub repository URL"):
        pru.parse_github_repository_url(repository_url)
    with pytest.raises(ValueError, match="GitHub repository URL"):
        pru.canonicalize_github_repository_url(repository_url)
    with pytest.raises(ValueError, match="GitHub release asset URL"):
        pru.parse_github_release_asset_url(release_asset_url)
    with pytest.raises(ValueError, match="GitHub release asset URL"):
        pru.canonicalize_github_release_asset_repository_url(release_asset_url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/Owner/Repo/releases/download/v1.2.3/plugin.zip",
        "https://GITHUB.COM/Owner/Repo/releases/download/release-1/Plugin%20Name.ZIP",
    ],
)
def test_github_release_asset_url_extracts_canonical_repository(url):
    assert pru.parse_github_release_asset_url(url) == ("owner", "repo")
    assert (
        pru.canonicalize_github_release_asset_repository_url(url)
        == "https://github.com/owner/repo"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo/releases/download/v1/plugin.zip",
        "https://user@github.com/owner/repo/releases/download/v1/plugin.zip",
        "https://github.com:443/owner/repo/releases/download/v1/plugin.zip",
        "https://github.com/owner/repo/releases/download/v1/plugin.zip?raw=1",
        "https://github.com/owner/repo/releases/download/v1/plugin.zip#asset",
        "https://github.com.example/owner/repo/releases/download/v1/plugin.zip",
        "https://github.com/owner/repo.git/releases/download/v1/plugin.zip",
        "https://github.com/owner%2Frepo/releases/download/v1/plugin.zip",
        "https://github.com/owner/repo/releases/tag/v1/plugin.zip",
        "https://github.com/owner/repo/releases/download//plugin.zip",
        "https://github.com/owner/repo/releases/download/v1/plugin%2Fpart.zip",
        "https://github.com/owner/repo/releases/download/v1/plugin.zip/extra",
        "https://github.com/owner/repo/releases/download/v1/plugin.zip/",
        "https://github.com/owner/repo/releases/download/v1",
        "https://objects.githubusercontent.com/owner/repo/releases/download/v1/plugin.zip",
    ],
)
def test_github_release_asset_url_rejects_hostile_or_non_asset_urls(url):
    with pytest.raises(ValueError, match="GitHub release asset URL"):
        pru.parse_github_release_asset_url(url)


def test_repository_url_parser_remains_repo_only_after_asset_parser_is_added():
    with pytest.raises(ValueError, match="GitHub repository URL"):
        pru.parse_github_repository_url(
            "https://github.com/owner/repo/releases/download/v1/plugin.zip"
        )


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


class _FakeResponse:
    def __init__(
        self,
        *,
        payload=None,
        links=None,
        headers=None,
        chunks=(),
        error=None,
        status_code=200,
        text="",
    ):
        self._payload = payload
        self.links = links or {}
        self.headers = headers or {}
        self._chunks = chunks
        self._error = error
        self.status_code = status_code
        self.text = text
        self.iterated = False
        self.closed = False
        self.requested_chunk_size = None

    def raise_for_status(self):
        if self._error:
            raise self._error

    def json(self):
        return self._payload

    def iter_content(self, chunk_size):
        self.iterated = True
        self.requested_chunk_size = chunk_size
        for chunk in self._chunks:
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk

    def close(self):
        self.closed = True


class _FakeSession:
    def __init__(self, responses):
        self._responses = iter(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return next(self._responses)


class _BudgetClock:
    def __init__(self, *, monotonic=0.0, wall_time=1_000.0):
        self.monotonic_value = monotonic
        self.wall_time_value = wall_time
        self.sleeps = []

    def monotonic(self):
        return self.monotonic_value

    def wall_time(self):
        return self.wall_time_value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.monotonic_value += seconds
        self.wall_time_value += seconds


def test_get_releases_consumes_every_pagination_link():
    second_url = "https://api.github.com/repositories/1/releases?per_page=100&page=2"
    first = _FakeResponse(payload=[{"id": 1}], links={"next": {"url": second_url}})
    second = _FakeResponse(payload=[{"id": 2}])
    session = _FakeSession([first, second])

    assert pru.get_releases("Owner", "Repo", session=session) == [{"id": 1}, {"id": 2}]
    assert session.calls == [
        (
            "https://api.github.com/repos/owner/repo/releases?per_page=100",
            {"timeout": 10},
        ),
        (second_url, {"timeout": 10}),
    ]
    assert first.closed and second.closed


def test_get_releases_later_page_failure_is_not_partial_success():
    first = _FakeResponse(
        payload=[{"id": 1}], links={"next": {"url": "https://api.github.com/page/2"}}
    )
    second = _FakeResponse(error=RuntimeError("page two failed"))

    with pytest.raises(pru.ReleasePaginationError, match="page 2") as exc_info:
        pru.get_releases("owner", "repo", session=_FakeSession([first, second]))
    assert isinstance(exc_info.value.__cause__, RuntimeError)


def test_get_releases_rejects_a_repeated_next_link():
    first_url = "https://api.github.com/repos/owner/repo/releases?per_page=100"
    second_url = "https://api.github.com/page/2"
    first = _FakeResponse(payload=[{"id": 1}], links={"next": {"url": second_url}})
    second = _FakeResponse(payload=[{"id": 2}], links={"next": {"url": first_url}})

    with pytest.raises(pru.ReleasePaginationError, match="cyclic"):
        pru.get_releases("owner", "repo", session=_FakeSession([first, second]))


def test_api_budget_retries_a_rate_limit_reset_that_fits_and_closes_response():
    clock = _BudgetClock()
    limited = _FakeResponse(
        status_code=429,
        headers={"X-RateLimit-Reset": "1003"},
        text="API rate limit exceeded",
    )
    success = _FakeResponse(payload=[])
    session = _FakeSession([limited, success])
    budget = pru.ApiRequestBudget(
        10,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleep=clock.sleep,
    )

    assert pru.get_releases("owner", "repo", session=session, api_budget=budget) == []
    assert clock.sleeps == [3]
    assert limited.closed and success.closed
    assert session.calls[0][1]["timeout"] == 10
    assert session.calls[1][1]["timeout"] == 7


def test_api_budget_rejects_a_rate_limit_wait_that_exceeds_deadline_without_sleeping():
    clock = _BudgetClock()
    limited = _FakeResponse(
        status_code=403,
        headers={"Retry-After": "11"},
        text="secondary rate limit",
    )
    budget = pru.ApiRequestBudget(
        10,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleep=clock.sleep,
    )

    with pytest.raises(pru.ApiDeadlineExceeded, match="remaining API deadline"):
        pru.get_releases(
            "owner", "repo", session=_FakeSession([limited]), api_budget=budget
        )

    assert clock.sleeps == []
    assert limited.closed


def test_api_budget_uses_a_bounded_fallback_for_malformed_rate_limit_headers():
    clock = _BudgetClock()
    limited = _FakeResponse(
        status_code=429,
        headers={"Retry-After": "later", "X-RateLimit-Reset": "not-a-time"},
        text="rate limit",
    )
    budget = pru.ApiRequestBudget(
        30,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleep=clock.sleep,
    )

    with pytest.raises(pru.ApiDeadlineExceeded, match="remaining API deadline"):
        pru.get_releases(
            "owner", "repo", session=_FakeSession([limited]), api_budget=budget
        )

    assert clock.sleeps == []
    assert limited.closed


def test_api_budget_shares_one_deadline_across_release_pagination():
    clock = _BudgetClock()
    second_url = "https://api.github.com/repos/owner/repo/releases?page=2"
    first = _FakeResponse(payload=[{"id": 1}], links={"next": {"url": second_url}})
    second = _FakeResponse(payload=[{"id": 2}])

    class _TimingSession(_FakeSession):
        def get(self, url, **kwargs):
            response = super().get(url, **kwargs)
            clock.monotonic_value += 2
            return response

    session = _TimingSession([first, second])
    budget = pru.ApiRequestBudget(
        5,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleep=clock.sleep,
    )

    assert pru.get_releases("owner", "repo", session=session, api_budget=budget) == [
        {"id": 1},
        {"id": 2},
    ]
    assert session.calls[0][1]["timeout"] == 5
    assert session.calls[1][1]["timeout"] == 3
    assert first.closed and second.closed


def test_api_budget_exhausts_normal_retries_without_leaking_responses():
    clock = _BudgetClock()
    first = _FakeResponse(error=RuntimeError("transient API failure"))
    second = _FakeResponse(error=RuntimeError("persistent API failure"))
    budget = pru.ApiRequestBudget(
        10,
        monotonic=clock.monotonic,
        wall_time=clock.wall_time,
        sleep=clock.sleep,
        max_retries=1,
    )

    with pytest.raises(pru.ReleasePaginationError, match="page 1"):
        pru.get_releases(
            "owner",
            "repo",
            session=_FakeSession([first, second]),
            api_budget=budget,
        )

    assert clock.sleeps == [1]
    assert first.closed and second.closed


def test_download_policy_defaults_are_explicit_and_validated():
    policy = pru.validate_download_policy({})
    assert policy == pru.DownloadPolicy(
        release_max_bytes=67_108_864,
        source_max_bytes=268_435_456,
        connect_timeout_seconds=10,
        read_timeout_seconds=60,
        chunk_size_bytes=1_048_576,
    )
    assert pru.DEFAULT_RELEASE_MAX_BYTES == 67_108_864
    assert pru.DEFAULT_SOURCE_MAX_BYTES == 268_435_456
    assert pru.DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS == 10
    assert pru.DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS == 60
    assert pru.DEFAULT_DOWNLOAD_CHUNK_SIZE_BYTES == 1_048_576


@pytest.mark.parametrize(
    "downloads",
    [
        "invalid",
        {"release_max_bytes": True},
        {"source_max_bytes": 0},
        {"connect_timeout_seconds": -1},
        {"read_timeout_seconds": 1.5},
        {"chunk_size_bytes": "1024"},
    ],
)
def test_download_policy_rejects_invalid_values(downloads):
    with pytest.raises(ValueError, match="download"):
        pru.validate_download_policy({"downloads": downloads})


def _small_download_policy(**overrides):
    downloads = {
        "release_max_bytes": 5,
        "source_max_bytes": 9,
        "connect_timeout_seconds": 2,
        "read_timeout_seconds": 3,
        "chunk_size_bytes": 2,
    }
    downloads.update(overrides)
    return {"downloads": downloads}


def test_bounded_stream_download_exact_limit_succeeds_and_hashes_once(tmp_path):
    response = _FakeResponse(headers={}, chunks=[b"12", b"", b"345"])
    session = _FakeSession([response])
    destination = tmp_path / "plugin.zip"

    result = pru.bounded_stream_download(
        "https://example.com/plugin.zip",
        destination,
        session=session,
        kind="release",
        policy=_small_download_policy(),
    )

    assert destination.read_bytes() == b"12345"
    assert result.path == destination
    assert result.size_bytes == 5
    assert (
        result.sha256
        == "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5"
    )
    assert session.calls[0][1] == {"stream": True, "timeout": (2, 3)}
    assert response.requested_chunk_size == 2
    assert response.closed


def test_bounded_stream_download_rejects_oversized_declared_length_before_reading(
    tmp_path,
):
    response = _FakeResponse(headers={"Content-Length": "6"}, chunks=[b"ignored"])
    destination = tmp_path / "plugin.zip"

    with pytest.raises(pru.DownloadLimitError, match="Content-Length"):
        pru.bounded_stream_download(
            "https://example.com/plugin.zip",
            destination,
            session=_FakeSession([response]),
            kind="release",
            policy=_small_download_policy(),
        )
    assert not response.iterated
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("content_length", [None, "malformed", "-1", "1"])
def test_bounded_stream_download_enforces_streamed_limit_and_cleans_partial(
    tmp_path, content_length
):
    headers = {} if content_length is None else {"Content-Length": content_length}
    response = _FakeResponse(headers=headers, chunks=[b"12345", b"6"])
    destination = tmp_path / "plugin.zip"

    with pytest.raises(pru.DownloadLimitError, match="exceeds 5 bytes"):
        pru.bounded_stream_download(
            "https://example.com/plugin.zip",
            destination,
            session=_FakeSession([response]),
            kind="release",
            policy=_small_download_policy(),
        )
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_bounded_stream_download_cleans_partial_after_stream_failure(tmp_path):
    response = _FakeResponse(chunks=[b"12", RuntimeError("stream failed")])
    destination = tmp_path / "source.tar.gz"

    with pytest.raises(RuntimeError, match="stream failed"):
        pru.bounded_stream_download(
            "https://example.com/source.tar.gz",
            destination,
            session=_FakeSession([response]),
            kind="source",
            policy=_small_download_policy(),
        )
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_bounded_stream_download_uses_source_limit(tmp_path):
    destination = tmp_path / "source.tar.gz"
    response = _FakeResponse(chunks=[b"123456789"])
    result = pru.bounded_stream_download(
        "https://example.com/source.tar.gz",
        destination,
        session=_FakeSession([response]),
        kind="source",
        policy=_small_download_policy(),
    )
    assert result.size_bytes == 9


def test_bounded_stream_download_rejects_unknown_kind_without_request(tmp_path):
    session = _FakeSession([])
    with pytest.raises(ValueError, match="download kind"):
        pru.bounded_stream_download(
            "https://example.com/plugin.zip",
            tmp_path / "plugin.zip",
            session=session,
            kind="other",
            policy=_small_download_policy(),
        )
    assert session.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "audit_plugins.py",
        "generate_json.py",
        "check_for_updates.py",
        "plugin_release_utils.py",
        "security-policy.yml",
        "security-allowlist.yml",
        "security-verdicts.json",
        "semgrep-rules.yml",
        "pyproject.toml",
        "uv.lock",
        "tests/test_catalog_gate.py",
        "scripts/orchestration/run-quality-gates",
        ".github/workflows/plugin-security-audit.yml",
        ".github/workflows/scheduled-security-audit.yml",
        ".github/workflows/future-audit-contract.yml",
    ],
)
def test_select_audit_mode_security_pipeline_changes_select_full_corpus(path):
    assert pru.select_audit_mode([path]) == "all"


def test_select_audit_mode_plugin_list_only_selects_changed_repositories():
    assert pru.select_audit_mode(["additional_plugins.txt"]) == "changed"


def test_select_audit_mode_security_change_wins_over_plugin_list():
    assert (
        pru.select_audit_mode(["additional_plugins.txt", "security-policy.yml"])
        == "all"
    )


def test_select_audit_mode_ignores_unrelated_paths_and_empty_entries():
    assert pru.select_audit_mode(["", "./README.md", "static/index.html"]) == "none"
    assert pru.select_audit_mode(["README.md", "./additional_plugins.txt"]) == "changed"


def test_select_audit_mode_executable_accepts_paths_as_arguments():
    repository_root = Path(pru.__file__).resolve().parent
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "plugin_release_utils",
            "--select-audit-mode",
            "additional_plugins.txt",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=repository_root,
    )
    assert completed.returncode == 0
    assert completed.stdout == "changed\n"
    assert completed.stderr == ""


def test_select_audit_mode_executable_reads_newline_paths_from_stdin():
    repository_root = Path(pru.__file__).resolve().parent
    completed = subprocess.run(
        [sys.executable, "-m", "plugin_release_utils", "--select-audit-mode"],
        input="additional_plugins.txt\nplugin_release_utils.py\n",
        capture_output=True,
        text=True,
        check=False,
        cwd=repository_root,
    )
    assert completed.returncode == 0
    assert completed.stdout == "all\n"
    assert completed.stderr == ""


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
