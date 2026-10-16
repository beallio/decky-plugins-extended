"""Cover store-backed repository discovery and the two-file plugin list."""

import copy
import json
import os

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import pytest
import requests

import audit_plugins
import generate_json
import plugin_release_utils
import store_discovery

GITMODULES = """\
[submodule "plugins/keeper"]
\tpath = plugins/keeper
\turl = https://github.com/Owner/Keeper.git
[submodule "plugins/ssh-remote"]
\turl = git@github.com:Owner/SshRemote.git
\tpath = plugins/ssh-remote
[submodule "plugins/gitlab"]
\tpath = plugins/gitlab
\turl = https://gitlab.com/owner/elsewhere
[submodule "plugins/no-url"]
\tpath = plugins/no-url
"""


def _release(
    *, prerelease=False, draft=False, zips=1, size=10, digest=None, tag="v1.0.0"
):
    asset = {"name": "plugin.zip", "size": size}
    if digest:
        asset["digest"] = f"sha256:{digest}"
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "assets": [dict(asset, name=f"plugin{index}.zip") for index in range(zips)],
    }


def _discover(**overrides):
    kwargs = {
        "gitmodules_text": GITMODULES,
        "store_versions": {"keeper": {"0.9.0"}, "sshremote": {"0.9.0"}},
        "tracked_urls": set(),
        "repo_metadata": lambda owner, repo: {
            "full_name": f"{owner}/{repo}",
            "default_branch": "main",
            "archived": False,
        },
        "plugin_name": lambda owner, repo, branch: {
            "keeper": "Keeper",
            "sshremote": "SshRemote",
        }.get(repo),
        "releases": lambda owner, repo: [_release()],
    }
    kwargs.update(overrides)
    return store_discovery.discover_store_repositories(**kwargs)


def _reasons(result):
    return {subject: reason for subject, reason in result.skipped}


# ---------------------------------------------------------------------------
# .gitmodules parsing and URL normalisation
# ---------------------------------------------------------------------------


def test_parse_gitmodules_reads_blocks_regardless_of_key_order():
    submodules = store_discovery.parse_gitmodules(GITMODULES)

    assert [submodule.name for submodule in submodules] == [
        "plugins/keeper",
        "plugins/ssh-remote",
        "plugins/gitlab",
    ]
    # The ssh block declares url before path, so a positional pairing would
    # mis-associate it with the preceding block.
    assert submodules[1].url == "git@github.com:Owner/SshRemote.git"


def test_parse_gitmodules_rejects_non_string_input():
    with pytest.raises(TypeError):
        store_discovery.parse_gitmodules(None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://github.com/Owner/Repo", "https://github.com/owner/repo"),
        ("https://github.com/Owner/Repo.git", "https://github.com/owner/repo"),
        ("https://github.com/Owner/Repo/", "https://github.com/owner/repo"),
        ("git@github.com:Owner/Repo.git", "https://github.com/owner/repo"),
        ("https://gitlab.com/owner/repo", None),
        ("git@git.example.invalid:owner/repo.git", None),
        ("https://github.com/owner", None),
        ("", None),
        (None, None),
    ],
)
def test_canonical_github_url_normalises_or_rejects(raw, expected):
    assert store_discovery.canonical_github_url(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://gitlab.com/Owner/Repo.git", "https://gitlab.com/Owner/Repo"),
        (
            "git@git.example.invalid:Owner/Repo.git",
            "https://git.example.invalid/Owner/Repo",
        ),
        ("http://gitlab.com/owner/repo", None),
    ],
)
def test_canonical_source_url_normalises_safe_repository_links(raw, expected):
    assert store_discovery.canonical_source_url(raw) == expected


@pytest.mark.parametrize(
    ("releases", "expected"),
    [
        ([_release()], True),
        ([_release(prerelease=True)], False),
        ([_release(draft=True)], False),
        ([_release(zips=0)], False),
        ([_release(zips=2)], False),
        ([_release(prerelease=True), _release()], True),
        ([], False),
        (None, False),
    ],
)
def test_has_contributable_release(releases, expected):
    assert store_discovery.has_contributable_release(releases) is expected


def test_has_contributable_release_ignores_store_published_versions():
    releases = [_release()]  # tag v1.0.0

    assert store_discovery.has_contributable_release(releases, {"1.0.0"}) is False
    assert store_discovery.has_contributable_release(releases, {"0.9.0"}) is True


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_discovery_keeps_store_backed_github_repositories():
    result = _discover()

    assert result.included == [
        "https://github.com/owner/keeper",
        "https://github.com/owner/sshremote",
    ]
    assert (
        _reasons(result)["plugins/gitlab"]
        == "source name 'gitlab' matches no store plugin"
    )
    assert result.sources == {
        "Keeper": ["https://github.com/owner/keeper"],
        "SshRemote": ["https://github.com/owner/sshremote"],
    }


def test_discovery_skips_repositories_already_hand_maintained():
    result = _discover(tracked_urls={"https://github.com/owner/keeper"})

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "already in additional_plugins.txt"
    )


def test_discovery_skips_archived_repositories():
    result = _discover(
        repo_metadata=lambda owner, repo: {
            "full_name": f"{owner}/{repo}",
            "default_branch": "main",
            "archived": repo == "keeper",
        }
    )

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"] == "repository is archived"
    )
    assert result.sources["Keeper"] == ["https://github.com/owner/keeper"]


def test_discovery_records_external_sources_without_adding_them_to_the_audit():
    gitmodules = """\
[submodule "plugins/PowerTools"]
\tpath = plugins/PowerTools
\turl = https://gitlab.com/NGnius/PowerTools
[submodule "plugins/decky-bluetooth-wake-control"]
\tpath = plugins/decky-bluetooth-wake-control
\turl = https://gitlab.com/finewolf-projects/decky-plugin-bluetooth-wake-control.git
"""
    result = _discover(
        gitmodules_text=gitmodules,
        store_versions={"powertools": set(), "bt wake control": set()},
        repo_metadata=lambda *_args: pytest.fail("external sources need no GitHub API"),
        plugin_name=lambda *_args: pytest.fail("external sources need no plugin.json"),
        releases=lambda *_args: pytest.fail("external sources are not audited"),
    )

    assert result.included == []
    assert result.sources == {
        "BT Wake Control": [
            "https://gitlab.com/finewolf-projects/decky-plugin-bluetooth-wake-control"
        ],
        "PowerTools": ["https://gitlab.com/NGnius/PowerTools"],
    }


def test_discovery_matches_unique_names_without_spaces_for_source_links():
    gitmodules = """\
[submodule "plugins/MusicControl"]
\tpath = plugins/MusicControl
\turl = https://github.com/owner/MusicControl
"""
    result = _discover(
        gitmodules_text=gitmodules,
        store_versions={
            "music control": {"0.9.0"},
            "musiccontrol": {"1.0.0"},
        },
        plugin_name=lambda *_args: "Music Control",
        releases=lambda *_args: [],
    )

    assert result.sources == {
        "Music Control": ["https://github.com/owner/musiccontrol"],
        "musiccontrol": ["https://github.com/owner/musiccontrol"],
    }


def test_discovery_skips_when_metadata_is_unavailable():
    result = _discover(
        repo_metadata=lambda owner, repo: (
            None
            if repo == "keeper"
            else {"full_name": f"{owner}/{repo}", "default_branch": "main"}
        )
    )

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "repository metadata unavailable"
    )


def test_discovery_adopts_the_renamed_repository_identity():
    # Worklist preparation compares metadata full_name against the configured
    # URL and reports an identity mismatch, so a stale submodule URL must be
    # rewritten here rather than tracked as-is.
    result = _discover(
        repo_metadata=lambda owner, repo: {
            "full_name": "neworg/keeper" if repo == "keeper" else f"{owner}/{repo}",
            "default_branch": "main",
            "archived": False,
        },
        plugin_name=lambda owner, repo, branch: {
            "keeper": "Keeper",
            "sshremote": "SshRemote",
        }.get(repo),
    )

    assert "https://github.com/neworg/keeper" in result.included
    assert "https://github.com/owner/keeper" not in result.included
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "renamed upstream, tracking https://github.com/neworg/keeper instead"
    )


def test_discovery_skips_names_the_official_store_does_not_publish():
    # The generator merges into an upstream entry by lowercased name, so an
    # unmatched name would publish a second entry beside the store's own.
    result = _discover(store_versions={"sshremote": {"0.9.0"}})

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "plugin.json name 'Keeper' matches no store plugin"
    )


def test_discovery_skips_repositories_without_a_plugin_json_name():
    result = _discover(
        plugin_name=lambda owner, repo, branch: (
            None if repo == "keeper" else "SshRemote"
        )
    )

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "no plugin.json name on the default branch"
    )


def test_discovery_skips_prerelease_only_repositories():
    result = _discover(
        releases=lambda owner, repo: (
            [_release(prerelease=True)] if repo == "keeper" else [_release()]
        )
    )

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "no stable single-zip release beyond what the official store "
        "already publishes"
    )


def test_discovery_collapses_two_submodules_onto_one_repository():
    duplicated = GITMODULES + (
        '[submodule "plugins/keeper-again"]\n'
        "\tpath = plugins/keeper-again\n"
        "\turl = https://github.com/owner/keeper/\n"
    )

    result = _discover(gitmodules_text=duplicated)

    assert result.included.count("https://github.com/owner/keeper") == 1
    assert "duplicate submodule target" in _reasons(result).values()


def test_discovery_skips_repositories_the_store_has_caught_up_to():
    # Every stable release is already published by the store, so the catalog
    # would defer all of them and the repository would add corpus but no entry.
    result = _discover(
        store_versions={"keeper": {"1.0.0"}, "sshremote": {"0.9.0"}},
    )

    assert result.included == ["https://github.com/owner/sshremote"]
    assert (
        _reasons(result)["https://github.com/owner/keeper"]
        == "no stable single-zip release beyond what the official store "
        "already publishes"
    )
    assert result.sources["Keeper"] == ["https://github.com/owner/keeper"]


def test_discovery_records_the_store_versions_to_defer_to():
    result = _discover(
        store_versions={"keeper": {"0.9.0", "0.8.0"}, "sshremote": {"0.9.0"}}
    )

    assert result.versions == {
        "https://github.com/owner/keeper": ["0.8.0", "0.9.0"],
        "https://github.com/owner/sshremote": ["0.9.0"],
    }


def test_render_versions_is_sorted_and_newline_terminated():
    rendered = store_discovery.render_versions(
        {
            "https://github.com/owner/b": ["2.0.0"],
            "https://github.com/owner/a": ["1.0.0"],
        }
    )

    assert rendered.endswith("\n")
    assert list(json.loads(rendered)) == [
        "https://github.com/owner/a",
        "https://github.com/owner/b",
    ]


def test_render_sources_is_sorted_and_newline_terminated():
    rendered = store_discovery.render_sources(
        {
            "Plugin B": ["https://github.com/owner/b"],
            "Plugin A": ["https://github.com/owner/a"],
        }
    )

    assert rendered.endswith("\n")
    assert list(json.loads(rendered)) == ["Plugin A", "Plugin B"]


def test_discovery_lets_only_one_repository_claim_a_plugin_name():
    # An original and a maintainer fork both resolve to one plugin name; the
    # catalog can merge only one source into that entry.
    forked = GITMODULES + (
        '[submodule "plugins/keeper-fork"]\n'
        "\tpath = plugins/keeper-fork\n"
        "\turl = https://github.com/forker/keeper\n"
    )

    result = _discover(
        gitmodules_text=forked,
        plugin_name=lambda owner, repo, branch: {
            "keeper": "Keeper",
            "sshremote": "SshRemote",
        }.get(repo),
    )

    assert result.included == [
        "https://github.com/owner/keeper",
        "https://github.com/owner/sshremote",
    ]
    assert (
        _reasons(result)["https://github.com/forker/keeper"]
        == "plugin name 'Keeper' already tracked via https://github.com/owner/keeper"
    )
    assert result.sources["Keeper"] == [
        "https://github.com/forker/keeper",
        "https://github.com/owner/keeper",
    ]


def test_release_size_classifier_is_digest_independent_and_release_local():
    limit = 1000

    assert (
        plugin_release_utils.release_exceeds_download_limit(_release(size=10), limit)
        is False
    )
    assert (
        plugin_release_utils.release_exceeds_download_limit(_release(size=2000), limit)
        is True
    )
    assert (
        plugin_release_utils.release_exceeds_download_limit(
            _release(size=2000, digest="a" * 64), limit
        )
        is True
    )
    assert (
        plugin_release_utils.release_exceeds_download_limit(
            _release(size=2000, zips=2), limit
        )
        is False
    )


def test_discovery_keeps_repositories_with_oversized_releases():
    result = _discover(
        releases=lambda owner, repo: (
            [_release(size=2000, tag="v1.1.0"), _release(tag="v1.0.0")]
            if repo == "keeper"
            else [_release()]
        )
    )

    assert result.included == [
        "https://github.com/owner/keeper",
        "https://github.com/owner/sshremote",
    ]
    assert "https://github.com/owner/keeper" not in _reasons(result)


def test_render_list_emits_a_generated_header_and_sorted_body():
    rendered = store_discovery.render_list(
        ["https://github.com/owner/b", "https://github.com/owner/a"]
    )

    lines = rendered.splitlines()
    assert lines[0].startswith("# store_plugins.txt -- GENERATED FILE")
    assert "SteamDeckHomebrew/decky-plugin-database" in rendered
    assert lines[-2:] == [
        "https://github.com/owner/b",
        "https://github.com/owner/a",
    ]
    assert rendered.endswith("\n")


def test_read_tracked_urls_ignores_comments_and_normalises(tmp_path):
    listing = tmp_path / "additional_plugins.txt"
    listing.write_text(
        "# comment\n\nhttps://github.com/Owner/Repo/\ngit@github.com:Owner/Other.git\n",
        encoding="utf-8",
    )

    assert store_discovery.read_tracked_urls(str(listing)) == {
        "https://github.com/owner/repo",
        "https://github.com/owner/other",
    }


def test_read_tracked_urls_tolerates_a_missing_file(tmp_path):
    assert store_discovery.read_tracked_urls(str(tmp_path / "absent.txt")) == set()


# ---------------------------------------------------------------------------
# Both readers consume the union of the two lists
# ---------------------------------------------------------------------------


def _write_lists(tmp_path, primary, discovered=None):
    (tmp_path / "additional_plugins.txt").write_text(
        "".join(f"{url}\n" for url in primary), encoding="utf-8"
    )
    if discovered is not None:
        (tmp_path / "store_plugins.txt").write_text(
            "# generated\n" + "".join(f"{url}\n" for url in discovered),
            encoding="utf-8",
        )


def test_generator_reads_both_plugin_lists(monkeypatch, tmp_path):
    _write_lists(
        tmp_path,
        ["https://github.com/owner/hand"],
        ["https://github.com/owner/derived"],
    )
    monkeypatch.chdir(tmp_path)

    assert generate_json.read_repo_urls() == [
        "https://github.com/owner/hand",
        "https://github.com/owner/derived",
    ]


def test_generator_tolerates_a_missing_generated_list(monkeypatch, tmp_path):
    _write_lists(tmp_path, ["https://github.com/owner/hand"])
    monkeypatch.chdir(tmp_path)

    assert generate_json.read_repo_urls() == ["https://github.com/owner/hand"]


def test_auditor_unions_both_plugin_lists(monkeypatch, tmp_path):
    _write_lists(
        tmp_path,
        ["https://github.com/owner/hand"],
        ["https://github.com/owner/derived"],
    )
    monkeypatch.chdir(tmp_path)

    assert audit_plugins.read_all_repo_urls() == [
        "https://github.com/owner/hand",
        "https://github.com/owner/derived",
    ]


def test_auditor_drops_a_repository_listed_in_both_files(monkeypatch, tmp_path):
    # Worklist preparation raises on a repeated repository, so the union has to
    # reconcile an overlap instead of forwarding it.
    _write_lists(
        tmp_path,
        ["https://github.com/Owner/Shared"],
        ["https://github.com/owner/shared/", "https://github.com/owner/derived"],
    )
    monkeypatch.chdir(tmp_path)

    assert audit_plugins.read_all_repo_urls() == [
        "https://github.com/owner/shared",
        "https://github.com/owner/derived",
    ]


def test_auditor_tolerates_a_missing_generated_list(monkeypatch, tmp_path):
    _write_lists(tmp_path, ["https://github.com/owner/hand"])
    monkeypatch.chdir(tmp_path)

    assert audit_plugins.read_all_repo_urls() == ["https://github.com/owner/hand"]


def test_generated_list_change_selects_changed_audit_mode():
    assert plugin_release_utils.select_audit_mode(["store_plugins.txt"]) == "changed"
    assert (
        plugin_release_utils.select_audit_mode(["additional_plugins.txt"]) == "changed"
    )
    assert plugin_release_utils.select_audit_mode(["README.md"]) == "none"


# ---------------------------------------------------------------------------
# The store-version map is one committed source of truth
# ---------------------------------------------------------------------------


def test_load_store_versions_canonicalises_and_tolerates_absence(tmp_path):
    assert plugin_release_utils.load_store_versions(str(tmp_path / "absent.json")) == {}

    path = tmp_path / "store_versions.json"
    path.write_text(
        json.dumps({"https://github.com/Owner/Repo/": ["1.0.0", "0.9.0", ""]}),
        encoding="utf-8",
    )

    assert plugin_release_utils.load_store_versions(str(path)) == {
        "https://github.com/owner/repo": {"1.0.0", "0.9.0"}
    }


def test_load_store_versions_rejects_malformed_documents(tmp_path):
    path = tmp_path / "store_versions.json"

    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(ValueError):
        plugin_release_utils.load_store_versions(str(path))

    path.write_text(
        json.dumps({"https://github.com/owner/repo": "1.0.0"}), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        plugin_release_utils.load_store_versions(str(path))


def test_load_store_sources_canonicalises_and_tolerates_absence(tmp_path):
    assert plugin_release_utils.load_store_sources(str(tmp_path / "absent.json")) == {}

    path = tmp_path / "store_sources.json"
    path.write_text(
        json.dumps(
            {
                "Official Plugin": [
                    "https://github.com/Owner/Repo/",
                    "https://github.com/owner/repo",
                    "https://gitlab.com/Owner/Repo.git",
                ]
            }
        ),
        encoding="utf-8",
    )

    assert plugin_release_utils.load_store_sources(str(path)) == {
        "Official Plugin": [
            "https://github.com/owner/repo",
            "https://gitlab.com/Owner/Repo",
        ]
    }


def test_load_store_sources_rejects_malformed_documents(tmp_path):
    path = tmp_path / "store_sources.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(ValueError):
        plugin_release_utils.load_store_sources(str(path))

    path.write_text(json.dumps({"Official Plugin": "owner/repo"}), encoding="utf-8")
    with pytest.raises(ValueError):
        plugin_release_utils.load_store_sources(str(path))


# ---------------------------------------------------------------------------
# Official catalog snapshot continuation
# ---------------------------------------------------------------------------


def _catalogs(*, from_snapshot=False):
    return store_discovery.store_catalog.OfficialCatalogs(
        stable=[
            {
                "id": 1,
                "name": "Keeper",
                "versions": [{"name": "0.9.0"}],
            }
        ],
        testing=[
            {
                "id": 1,
                "name": "Keeper",
                "versions": [{"name": "1.0.0"}],
            }
        ],
        captured_at="2026-10-16T12:00:00Z",
        from_snapshot=from_snapshot,
    )


def _discovery_paths(tmp_path):
    paths = {
        "output": tmp_path / "store_plugins.txt",
        "versions": tmp_path / "store_versions.json",
        "sources": tmp_path / "store_sources.json",
        "catalogs": tmp_path / "store_catalogs.json",
        "github_output": tmp_path / "github-output.txt",
    }
    return paths


def _discovery_args(paths, *, check=False):
    args = [
        "--output",
        str(paths["output"]),
        "--versions-output",
        str(paths["versions"]),
        "--sources-output",
        str(paths["sources"]),
        "--catalogs-output",
        str(paths["catalogs"]),
    ]
    if check:
        args.append("--check")
    return args


def _write_preserved_discovery_outputs(paths):
    paths["output"].write_text(
        store_discovery.render_list(["https://github.com/owner/keeper"]),
        encoding="utf-8",
    )
    paths["versions"].write_text(
        store_discovery.render_versions({"https://github.com/owner/keeper": ["0.9.0"]}),
        encoding="utf-8",
    )
    paths["sources"].write_text(
        store_discovery.render_sources({"Keeper": ["https://github.com/owner/keeper"]}),
        encoding="utf-8",
    )
    paths["catalogs"].write_text(
        store_discovery.store_catalog.render_snapshot(_catalogs()),
        encoding="utf-8",
    )


def _use_catalogs(monkeypatch, catalogs):
    def fetch_json(url):
        if catalogs.from_snapshot:
            raise requests.ConnectionError("official catalog endpoints unavailable")
        channel = (
            catalogs.stable
            if url == store_discovery.g.PLUGINS_URL
            else catalogs.testing
        )
        return copy.deepcopy(channel)

    monkeypatch.setattr(store_discovery.g, "fetch_json", fetch_json)


def test_offline_discovery_preserves_outputs_and_reports_not_refreshed(
    monkeypatch, tmp_path
):
    paths = _discovery_paths(tmp_path)
    _write_preserved_discovery_outputs(paths)
    before = {
        path: path.read_bytes()
        for path in paths.values()
        if path != paths["github_output"]
    }
    _use_catalogs(monkeypatch, _catalogs(from_snapshot=True))
    monkeypatch.setenv("GITHUB_OUTPUT", str(paths["github_output"]))
    monkeypatch.setattr(
        store_discovery,
        "fetch_gitmodules",
        lambda: pytest.fail("offline discovery must not query GitHub"),
    )

    with pytest.warns(store_discovery.store_catalog.StoreCatalogWarning):
        assert store_discovery.main(_discovery_args(paths)) == 0

    assert {
        path: path.read_bytes()
        for path in paths.values()
        if path != paths["github_output"]
    } == before
    assert paths["github_output"].read_text(encoding="utf-8") == "refreshed=false\n"


def test_check_offline_discovery_fails_without_changing_outputs(monkeypatch, tmp_path):
    paths = _discovery_paths(tmp_path)
    _write_preserved_discovery_outputs(paths)
    before = {
        path: path.read_bytes()
        for path in paths.values()
        if path != paths["github_output"]
    }
    _use_catalogs(monkeypatch, _catalogs(from_snapshot=True))
    monkeypatch.setenv("GITHUB_OUTPUT", str(paths["github_output"]))

    assert store_discovery.main(_discovery_args(paths, check=True)) == 1
    assert {
        path: path.read_bytes()
        for path in paths.values()
        if path != paths["github_output"]
    } == before
    assert paths["github_output"].read_text(encoding="utf-8") == "refreshed=false\n"


@pytest.mark.parametrize(
    ("broken", "error"),
    [
        ("missing-list", FileNotFoundError),
        ("missing-versions", FileNotFoundError),
        ("missing-sources", FileNotFoundError),
        ("invalid-url", ValueError),
        ("invalid-versions", ValueError),
        ("invalid-sources", ValueError),
    ],
)
def test_offline_discovery_rejects_missing_or_invalid_preserved_outputs(
    monkeypatch, tmp_path, broken, error
):
    paths = _discovery_paths(tmp_path)
    _write_preserved_discovery_outputs(paths)
    target_key = {
        "missing-list": "output",
        "missing-versions": "versions",
        "missing-sources": "sources",
        "invalid-url": "output",
        "invalid-versions": "versions",
        "invalid-sources": "sources",
    }[broken]
    target = paths[target_key]
    if broken.startswith("missing-"):
        target.unlink()
    elif broken == "invalid-url":
        target.write_text("not-a-repository-url\n", encoding="utf-8")
    elif broken == "invalid-versions":
        target.write_text(json.dumps({"https://github.com/owner/keeper": "1.0"}))
    else:
        target.write_text(json.dumps([]), encoding="utf-8")

    _use_catalogs(monkeypatch, _catalogs(from_snapshot=True))

    with pytest.raises(error):
        store_discovery.main(_discovery_args(paths))


def test_non_catalog_discovery_error_remains_fatal(monkeypatch, tmp_path):
    paths = _discovery_paths(tmp_path)
    _use_catalogs(monkeypatch, _catalogs())

    def fail_fetch_gitmodules():
        raise RuntimeError("GitHub API unavailable")

    monkeypatch.setattr(store_discovery, "fetch_gitmodules", fail_fetch_gitmodules)

    with pytest.raises(RuntimeError, match="GitHub API unavailable"):
        store_discovery.main(_discovery_args(paths))


def test_healthy_discovery_persists_raw_catalog_pair_and_metadata(
    monkeypatch, tmp_path
):
    paths = _discovery_paths(tmp_path)
    catalogs = _catalogs()
    _use_catalogs(monkeypatch, catalogs)
    monkeypatch.setenv("GITHUB_OUTPUT", str(paths["github_output"]))
    monkeypatch.setattr(
        store_discovery,
        "fetch_gitmodules",
        lambda: (
            '[submodule "plugins/keeper"]\n    url = https://github.com/owner/keeper\n'
        ),
    )
    monkeypatch.setattr(store_discovery, "read_tracked_urls", lambda: set())
    monkeypatch.setattr(
        store_discovery,
        "_repo_metadata",
        lambda owner, repo: {
            "full_name": f"{owner}/{repo}",
            "default_branch": "main",
            "archived": False,
        },
    )
    monkeypatch.setattr(
        store_discovery, "_plugin_name", lambda owner, repo, branch: "Keeper"
    )
    monkeypatch.setattr(
        store_discovery,
        "_releases",
        lambda owner, repo: [_release(tag="v2.0.0")],
    )

    assert store_discovery.main(_discovery_args(paths)) == 0

    assert (
        paths["output"]
        .read_text(encoding="utf-8")
        .endswith("https://github.com/owner/keeper\n")
    )
    assert plugin_release_utils.load_store_versions(str(paths["versions"])) == {
        "https://github.com/owner/keeper": {"0.9.0", "1.0.0"}
    }
    assert plugin_release_utils.load_store_sources(str(paths["sources"])) == {
        "Keeper": ["https://github.com/owner/keeper"]
    }
    persisted = store_discovery.store_catalog.load_snapshot(str(paths["catalogs"]))
    assert persisted.stable == catalogs.stable
    assert persisted.testing == catalogs.testing
    assert paths["github_output"].read_text(encoding="utf-8") == "refreshed=true\n"
