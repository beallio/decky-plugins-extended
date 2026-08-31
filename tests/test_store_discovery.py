"""Cover store-backed repository discovery and the two-file plugin list."""

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


def _release(*, prerelease=False, draft=False, zips=1):
    return {
        "tag_name": "v1.0.0",
        "prerelease": prerelease,
        "draft": draft,
        "assets": [{"name": f"plugin{index}.zip"} for index in range(zips)],
    }


def _discover(**overrides):
    kwargs = {
        "gitmodules_text": GITMODULES,
        "store_names": {"keeper", "sshremote"},
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
def test_has_stable_eligible_release(releases, expected):
    assert store_discovery.has_stable_eligible_release(releases) is expected


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
    result = _discover(store_names={"sshremote"})

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
        == "no stable release with exactly one zip asset"
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
