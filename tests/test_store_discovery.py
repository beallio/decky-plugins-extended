"""Cover store-backed repository discovery and the two-file plugin list."""

import json
import os

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import pytest

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
    assert _reasons(result)["plugins/gitlab"].startswith("not a GitHub repository")


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
