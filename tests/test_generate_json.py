import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("GITHUB_TOKEN", "test-token")

import generate_json


class GenerateJsonTests(unittest.TestCase):
    def test_build_version_object_requires_exactly_one_zip(self):
        release = {"tag_name": "v1.0.0", "assets": []}

        self.assertIsNone(generate_json.build_version_object(release))

    def test_build_version_object_skips_dual_casing_zips(self):
        dual_zip_release = {
            "tag_name": "v1.2.0",
            "assets": [
                {"name": "plugin.zip", "browser_download_url": "http://ex.com/1.zip"},
                {"name": "Plugin.ZIP", "browser_download_url": "http://ex.com/2.zip"},
            ],
        }
        self.assertIsNone(generate_json.build_version_object(dual_zip_release))

    def test_build_version_object_rehashes_same_version_and_url(self):
        artifact = "https://example.invalid/plugin.zip"
        known_hash = "a" * 64
        current_hash = "b" * 64
        release = {
            "tag_name": "v1.2.3",
            "published_at": "2026-01-02T00:00:00Z",
            "assets": [{"name": "plugin.zip", "browser_download_url": artifact}],
        }
        existing = {
            "versions": [{"name": "1.2.3", "artifact": artifact, "hash": known_hash}]
        }

        with patch.object(
            generate_json, "calculate_hash", return_value=current_hash
        ) as calculate_hash:
            version = generate_json.build_version_object(release, existing)

        calculate_hash.assert_called_once_with(artifact, policy=None)
        self.assertEqual(version["hash"], current_hash)
        self.assertEqual(version["artifact"], artifact)

    def test_build_version_object_passes_non_default_download_policy(self):
        artifact = "https://example.invalid/plugin.zip"
        current_hash = "b" * 64
        policy = {
            "downloads": {
                "release_max_bytes": 7,
                "source_max_bytes": 11,
                "connect_timeout_seconds": 2,
                "read_timeout_seconds": 3,
                "chunk_size_bytes": 2,
            }
        }
        release = {
            "tag_name": "v1.2.3",
            "assets": [{"name": "plugin.zip", "browser_download_url": artifact}],
        }

        with patch.object(
            generate_json, "calculate_hash", return_value=current_hash
        ) as calculate_hash:
            version = generate_json.build_version_object(release, policy=policy)

        calculate_hash.assert_called_once_with(artifact, policy=policy)
        self.assertEqual(version["hash"], current_hash)

    def test_calculate_hash_delegates_to_bounded_release_stream(self):
        artifact = "https://example.invalid/plugin.zip"
        current_hash = "b" * 64
        policy = {
            "downloads": {
                "release_max_bytes": 7,
                "source_max_bytes": 11,
                "connect_timeout_seconds": 2,
                "read_timeout_seconds": 3,
                "chunk_size_bytes": 2,
            }
        }

        class Result:
            sha256 = current_hash

        with patch.object(
            generate_json, "bounded_stream_download", return_value=Result()
        ) as bounded_download:
            observed_hash = generate_json.calculate_hash(artifact, policy=policy)

        args, kwargs = bounded_download.call_args
        self.assertEqual(args[0], artifact)
        self.assertEqual(Path(args[1]).name, "release.zip")
        self.assertIs(kwargs["session"], generate_json.anon_session)
        self.assertEqual(kwargs["kind"], "release")
        self.assertIs(kwargs["policy"], policy)
        self.assertEqual(observed_hash, current_hash)

    def test_build_version_object_accepts_only_exact_github_digest(self):
        artifact = "https://example.invalid/plugin.zip"
        current_hash = "b" * 64
        valid = {
            "tag_name": "v1.2.3",
            "assets": [
                {
                    "name": "plugin.zip",
                    "browser_download_url": artifact,
                    "digest": "sha256:" + "A" * 64,
                }
            ],
        }

        with patch.object(generate_json, "calculate_hash") as calculate_hash:
            version = generate_json.build_version_object(valid)

        calculate_hash.assert_not_called()
        self.assertEqual(version["hash"], "a" * 64)

        for malformed in (
            "sha256:" + "a" * 63,
            "sha512:" + "a" * 64,
            "prefix-sha256:" + "a" * 64,
            "sha256:" + "g" * 64,
        ):
            with self.subTest(malformed=malformed):
                release = copy.deepcopy(valid)
                release["assets"][0]["digest"] = malformed
                with patch.object(
                    generate_json, "calculate_hash", return_value=current_hash
                ) as calculate_hash:
                    version = generate_json.build_version_object(release)
                calculate_hash.assert_called_once_with(artifact, policy=None)
                self.assertEqual(version["hash"], current_hash)

    def test_normalize_version_extracts_version_from_prefixed_tags(self):
        cases = {
            "v1.2.3": "1.2.3",
            "1.2.3": "1.2.3",
            "Release-0.7.1": "0.7.1",
            "decky-romm-sync-v0.29.0": "0.29.0",
            "panel-de-control-v0.30.1": "0.30.1",
            "v2.0.0-beta.1": "2.0.0-beta.1",
            "0.1": "0.1",
            "1.04": "1.04",
            # Nothing version-shaped: keep the tag rather than drop the release.
            "latest": "latest",
        }

        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                self.assertEqual(generate_json.normalize_version(tag), expected)

    def test_resolve_plugin_name_prefers_plugin_json(self):
        # Decky matches installed plugins on the plugin.json name, so it wins.
        self.assertEqual(
            generate_json.resolve_plugin_name(
                {"name": "SDH-Ludusavi"}, {"name": "sdh-ludusavi"}
            ),
            "SDH-Ludusavi",
        )
        self.assertEqual(
            generate_json.resolve_plugin_name(None, {"name": "sdh-ludusavi"}),
            "sdh-ludusavi",
        )
        self.assertEqual(
            generate_json.resolve_plugin_name({}, {"name": "sdh-ludusavi"}),
            "sdh-ludusavi",
        )
        self.assertIsNone(generate_json.resolve_plugin_name(None, {}))

    def test_resolve_tags_promotes_the_root_flag(self):
        # The store card shows its root warning off a 'root' tag, not off flags.
        plugin_json = {
            "publish": {"tags": ["vpn", "network"]},
            "flags": ["root", "_root", "debug"],
        }

        self.assertEqual(
            generate_json.resolve_tags(plugin_json, {"keywords": ["ignored"]}),
            ["network", "root", "vpn"],
        )

    def test_resolve_tags_falls_back_to_keywords(self):
        self.assertEqual(
            generate_json.resolve_tags(
                {"publish": {}}, {"keywords": ["deck", "plugin"]}
            ),
            ["deck", "plugin"],
        )
        self.assertEqual(
            generate_json.resolve_tags(None, {"keywords": "utility"}), ["utility"]
        )
        self.assertEqual(generate_json.resolve_tags(None, {}), [])
        # A root plugin with no tags at all still gets the marker.
        self.assertEqual(generate_json.resolve_tags({"flags": ["root"]}, {}), ["root"])

    def test_resolve_description_prefers_publish_description(self):
        plugin_json = {"publish": {"description": "Store copy"}}
        pkg = {"description": "Developer copy"}
        repo_info = {"description": "Repo copy"}

        self.assertEqual(
            generate_json.resolve_description(plugin_json, pkg, repo_info), "Store copy"
        )
        self.assertEqual(
            generate_json.resolve_description({"publish": {}}, pkg, repo_info),
            "Developer copy",
        )
        self.assertEqual(
            generate_json.resolve_description(None, {"description": "  "}, repo_info),
            "Repo copy",
        )
        self.assertEqual(generate_json.resolve_description(None, {}, {}), "")

    def test_resolve_image_url_prefers_publish_image(self):
        plugin_json = {"publish": {"image": "https://example.invalid/store.png"}}

        with patch.object(generate_json, "image_is_usable", return_value=True):
            self.assertEqual(
                generate_json.resolve_image_url(plugin_json, "owner", "repo"),
                "https://example.invalid/store.png",
            )

    def test_resolve_image_url_falls_back_to_repo_card(self):
        fallback = "https://opengraph.githubassets.com/1/owner/repo"
        template = "https://opengraph.githubassets.com/1/SteamDeckHomebrew/PluginLoader"

        with patch.object(
            generate_json, "image_is_usable", return_value=True
        ) as usable:
            # Missing, empty, and the unedited template placeholder.
            self.assertEqual(
                generate_json.resolve_image_url(None, "owner", "repo"), fallback
            )
            self.assertEqual(
                generate_json.resolve_image_url({"publish": {}}, "owner", "repo"),
                fallback,
            )
            self.assertEqual(
                generate_json.resolve_image_url(
                    {"publish": {"image": "  "}}, "owner", "repo"
                ),
                fallback,
            )
            self.assertEqual(
                generate_json.resolve_image_url(
                    {"publish": {"image": template}}, "owner", "repo"
                ),
                fallback,
            )
            usable.assert_not_called()

        # A dead link is replaced too.
        with patch.object(generate_json, "image_is_usable", return_value=False):
            self.assertEqual(
                generate_json.resolve_image_url(
                    {"publish": {"image": "https://example.invalid/gone.png"}},
                    "owner",
                    "repo",
                ),
                fallback,
            )

    def test_image_is_usable_distinguishes_dead_from_transient(self):
        class Response:
            def __init__(self, status_code, content_type="image/png"):
                self.status_code = status_code
                self.headers = {"content-type": content_type}

            def close(self):
                pass

        cases = [
            (Response(200), True),
            (Response(200, "text/html"), False),  # a 404 page served as 200
            (Response(404, "text/plain"), False),
            (
                Response(429, "text/html"),
                True,
            ),  # rate limited, not proof of a dead link
            (Response(503, "text/html"), True),
        ]
        for response, expected in cases:
            with self.subTest(
                status=response.status_code, ctype=response.headers["content-type"]
            ):
                with (
                    patch.object(
                        generate_json.anon_session, "head", return_value=response
                    ),
                    patch.object(
                        generate_json.anon_session, "get", return_value=response
                    ),
                ):
                    self.assertIs(
                        generate_json.image_is_usable("https://example.invalid/x.png"),
                        expected,
                    )

    def test_image_is_usable_keeps_url_on_network_error(self):
        with patch.object(
            generate_json.anon_session,
            "head",
            side_effect=generate_json.requests.RequestException("boom"),
        ):
            self.assertTrue(
                generate_json.image_is_usable("https://example.invalid/x.png")
            )

    def test_get_plugin_json_returns_none_when_absent(self):
        class Response:
            status_code = 404

            def raise_for_status(self):
                raise AssertionError("must not raise for an optional missing file")

        with patch.object(generate_json.session, "get", return_value=Response()):
            self.assertIsNone(generate_json.get_plugin_json("owner", "repo", "main"))

    def test_sort_versions_orders_by_semver_not_date(self):
        versions = [
            # Newest by date but an old branch: must not end up first.
            {"name": "1.0.1", "created": "2026-06-01T00:00:00Z"},
            {"name": "2.0.0", "created": "2026-01-01T00:00:00Z"},
            {"name": "2.0.0-beta.2", "created": "2025-12-01T00:00:00Z"},
            {"name": "2.0.0-beta.10", "created": "2025-12-02T00:00:00Z"},
            # A rolling tag with no version in it sorts last, whatever its date.
            {"name": "nightly", "created": "2026-07-01T00:00:00Z"},
        ]

        self.assertEqual(
            [v["name"] for v in generate_json.sort_versions(versions)],
            ["2.0.0", "2.0.0-beta.10", "2.0.0-beta.2", "1.0.1", "nightly"],
        )

    def test_official_latest_version_uses_semver_order_not_position(self):
        entry = {
            "versions": [
                {"name": "1.0.0", "created": "2026-12-31T00:00:00Z"},
                {"name": "2.0.0", "created": "2025-01-01T00:00:00Z"},
            ]
        }
        original_order = copy.deepcopy(entry["versions"])

        self.assertEqual(generate_json.official_latest_version(entry), "2.0.0")
        self.assertEqual(entry["versions"], original_order)

    def test_official_latest_version_handles_empty_and_missing_entries(self):
        for entry in (None, {}, {"versions": []}):
            with self.subTest(entry=entry):
                self.assertIsNone(generate_json.official_latest_version(entry))

    def test_annotate_official_version_prefixes_description_when_newer_exists(self):
        entry = {
            "description": "Original copy",
            "versions": [{"name": "2.0.0"}],
        }

        self.assertTrue(generate_json.annotate_official_version(entry, "1.0.0"))
        self.assertEqual(
            entry["description"],
            "Official store has 1.0.0; this store has 2.0.0. Original copy",
        )
        self.assertIn("Original copy", entry["description"])

    def test_annotate_official_version_skips_when_official_is_newest(self):
        entry = {
            "description": "Original copy",
            "versions": [{"name": "2.0.0"}],
        }
        original_entry = copy.deepcopy(entry)

        self.assertFalse(generate_json.annotate_official_version(entry, "2.0.0"))
        self.assertEqual(entry, original_entry)

    def test_annotate_official_version_is_idempotent(self):
        entry = {
            "description": "Official store has useful plugins.",
            "versions": [{"name": "2.0.0"}],
        }
        note = "Official store has 1.0.0; this store has 2.0.0."

        self.assertTrue(generate_json.annotate_official_version(entry, "1.0.0"))
        self.assertFalse(generate_json.annotate_official_version(entry, "1.0.0"))
        self.assertEqual(entry["description"].count(note), 1)
        self.assertIn("Official store has useful plugins.", entry["description"])

    def test_annotate_official_version_leaves_version_names_untouched(self):
        entry = {
            "description": "Original copy",
            "versions": [
                {"name": "2.0.0", "hash": "a" * 64},
                {"name": "1.0.0", "hash": "b" * 64},
            ],
        }
        original_versions = copy.deepcopy(entry["versions"])

        self.assertTrue(generate_json.annotate_official_version(entry, "1.0.0"))
        self.assertEqual(entry["versions"], original_versions)

    def test_parse_semver_handles_partial_and_invalid_versions(self):
        self.assertEqual(generate_json.parse_semver("1.2.3")[:3], (1, 2, 3))
        self.assertEqual(generate_json.parse_semver("0.1")[:3], (0, 1, 0))
        self.assertEqual(generate_json.parse_semver("3")[:3], (3, 0, 0))
        # Build metadata is ignored, as compare-versions ignores it.
        self.assertEqual(generate_json.parse_semver("1.2.3+build.5")[:3], (1, 2, 3))
        self.assertIsNone(generate_json.parse_semver("nightly"))
        self.assertIsNone(generate_json.parse_semver("dev-build"))
        self.assertIsNone(generate_json.parse_semver(""))

    def test_merge_plugin_versions_updates_and_sorts_versions(self):
        plugin = {
            "versions": [
                {
                    "name": "1.0.0",
                    "hash": "a" * 64,
                    "artifact": "https://example.invalid/old.zip",
                    "created": "2025-01-01T00:00:00Z",
                    "downloads": 10,
                    "updates": 4,
                }
            ]
        }
        new_versions = [
            {
                "name": "1.0.0",
                "hash": "b" * 64,
                "artifact": "https://example.invalid/new.zip",
                "created": "2026-01-01T00:00:00Z",
                "downloads": 0,
                "updates": 0,
            },
            {
                "name": "2.0.0",
                "hash": "c" * 64,
                "artifact": "https://example.invalid/2.zip",
                "created": "2026-02-01T00:00:00Z",
                "downloads": 0,
                "updates": 0,
            },
        ]

        generate_json.merge_plugin_versions(plugin, new_versions)

        self.assertEqual(
            [version["name"] for version in plugin["versions"]], ["2.0.0", "1.0.0"]
        )
        self.assertEqual(plugin["versions"][1]["hash"], "b" * 64)
        self.assertEqual(plugin["versions"][1]["downloads"], 10)
        self.assertEqual(plugin["versions"][1]["updates"], 4)

    def test_copy_static_files_publishes_storefront_assets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "static"
            destination = Path(temp_dir) / "public"
            source.mkdir()
            destination.mkdir()
            (source / "index.html").write_text("<h1>hi</h1>", encoding="utf-8")
            (source / "storefront.css").write_text("body {}", encoding="utf-8")
            (source / "storefront.js").write_text("export {};", encoding="utf-8")
            (source / "nested").mkdir()

            copied = generate_json.copy_static_files(str(source), str(destination))

            self.assertEqual(copied, ["index.html", "storefront.css", "storefront.js"])
            self.assertEqual(
                (destination / "index.html").read_text(encoding="utf-8"), "<h1>hi</h1>"
            )
            self.assertTrue((destination / "storefront.css").is_file())
            self.assertTrue((destination / "storefront.js").is_file())

    def test_build_storefront_metadata_keeps_per_version_provenance(self):
        stable = [
            {"name": "Official Plugin", "visible": True},
            {"name": "Extended One", "visible": True},
            {"name": "extended one", "visible": True},
            {"name": "Hidden Stable", "visible": False},
        ]
        testing = [
            {"name": "official plugin", "visible": True},
            {"name": "Extended Two", "visible": True},
            {"name": "Hidden Test", "visible": False},
        ]
        contributions = [
            {
                "name": "Official Plugin",
                "version": {
                    "name": "2.0.0",
                    "hash": "b" * 64,
                    "tag": "2.0.0",
                    "repository": "owner/two",
                    "source_url": "https://github.com/owner/two",
                },
            },
            {
                "name": "official plugin",
                "version": {
                    "name": "1.0.0",
                    "hash": "a" * 64,
                    "tag": "1.0.0",
                    "repository": "owner/one",
                    "source_url": "https://github.com/owner/one",
                },
            },
            {
                "name": "Extended One",
                "version": {
                    "name": "1.0.0",
                    "hash": "c" * 64,
                    "tag": "1.0.0",
                    "repository": "owner/extended",
                    "source_url": "https://github.com/owner/extended",
                },
            },
        ]

        metadata = generate_json.build_storefront_metadata(
            stable,
            testing,
            {"OFFICIAL PLUGIN".casefold()},
            contributions,
            "enforce",
        )

        self.assertEqual(metadata["schema_version"], 1)
        self.assertEqual(metadata["stable_count"], 3)
        self.assertEqual(metadata["testing_count"], 2)
        self.assertEqual(metadata["stable_extended_count"], 1)
        self.assertEqual(metadata["testing_extended_count"], 1)
        self.assertEqual(
            metadata["plugins"]["official plugin"]["provenance"], "official"
        )
        self.assertEqual(metadata["plugins"]["extended one"]["provenance"], "extended")
        self.assertEqual(
            [
                version["hash"]
                for version in metadata["plugins"]["official plugin"]["versions"]
            ],
            ["a" * 64, "b" * 64],
        )

    def test_storefront_metadata_empty_output_and_writer_are_deterministic(self):
        empty = generate_json.build_storefront_metadata([], [], set(), [], "enforce")
        self.assertEqual(
            empty,
            {
                "schema_version": 1,
                "enforcement_mode": "enforce",
                "stable_count": 0,
                "testing_count": 0,
                "stable_extended_count": 0,
                "testing_extended_count": 0,
                "plugins": {},
            },
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first.json"
            second = Path(temp_dir) / "second.json"
            generate_json.write_storefront_metadata(first, empty)
            generate_json.write_storefront_metadata(second, empty)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_copy_static_files_without_a_static_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(
                generate_json.copy_static_files(
                    str(Path(temp_dir) / "missing"), temp_dir
                ),
                [],
            )

    def test_validate_plugin_schema_rejects_bad_hash(self):
        plugins = [
            {
                "id": 1,
                "name": "Example",
                "versions": [
                    {
                        "name": "1.0.0",
                        "hash": "too-short",
                        "artifact": "https://example.invalid/plugin.zip",
                    }
                ],
            }
        ]

        with self.assertRaisesRegex(AssertionError, "Invalid hash length"):
            generate_json.validate_plugin_schema(plugins, "stable")

    def test_main_separates_stable_and_testing_releases_and_ids(self):
        base_stable = [
            {
                "id": 7,
                "name": "OfficialStable",
                "versions": [
                    {
                        "name": "1.0.0",
                        "hash": "a" * 64,
                        "artifact": "https://example.invalid/official-stable.zip",
                    }
                ],
            }
        ]
        base_testing = [
            {
                "id": 11,
                "name": "OfficialTesting",
                "versions": [
                    {
                        "name": "1.0.0",
                        "hash": "b" * 64,
                        "artifact": "https://example.invalid/official-testing.zip",
                    }
                ],
            }
        ]
        repo_info = {
            "default_branch": "main",
            "description": "Repository description",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        # The store entry must be keyed on the plugin.json name, not this one.
        plugin_json = {"name": "Custom Plugin"}
        package = {
            "name": "custom-plugin",
            "author": {"name": "Decky Author"},
            "description": "Plugin description",
            "keywords": "utility",
        }
        releases = [
            {"tag_name": "v2.0.0-beta.1", "prerelease": True},
            {"tag_name": "v1.0.0", "prerelease": False},
        ]

        def fetch_json(url):
            if url == generate_json.PLUGINS_URL:
                return copy.deepcopy(base_stable)
            return copy.deepcopy(base_testing)

        def build_version_object(release, existing_plugin=None, policy=None):
            del existing_plugin, policy
            name = release["tag_name"].lstrip("v")
            return {
                "name": name,
                "hash": ("c" if release["prerelease"] else "d") * 64,
                "artifact": f"https://example.invalid/{name}.zip",
                "created": "2026-01-01T00:00:00Z",
                "downloads": 0,
                "updates": 0,
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            (workdir / "additional_plugins.txt").write_text(
                "# ignored\nhttps://github.com/example/custom-plugin\n",
                encoding="utf-8",
            )
            old_cwd = Path.cwd()
            try:
                os.chdir(workdir)
                with (
                    patch.object(generate_json, "fetch_json", side_effect=fetch_json),
                    patch.object(
                        generate_json, "get_repo_info", return_value=repo_info
                    ),
                    patch.object(
                        generate_json, "get_package_json", return_value=package
                    ),
                    patch.object(
                        generate_json, "get_plugin_json", return_value=plugin_json
                    ),
                    patch.object(generate_json, "get_releases", return_value=releases),
                    patch.object(
                        generate_json,
                        "build_version_object",
                        side_effect=build_version_object,
                    ),
                ):
                    generate_json.main()
            finally:
                os.chdir(old_cwd)

            stable = json.loads(
                (workdir / "public/plugins.json").read_text(encoding="utf-8")
            )
            testing = json.loads(
                (workdir / "public/testing_plugins.json").read_text(encoding="utf-8")
            )

        stable_plugin = next(
            plugin for plugin in stable if plugin["name"] == "Custom Plugin"
        )
        testing_plugin = next(
            plugin for plugin in testing if plugin["name"] == "Custom Plugin"
        )
        self.assertEqual(stable_plugin["id"], 8)
        # Testing IDs are synced to their stable counterpart, so this is 8 and
        # not the 12 that the independent testing ID space would have assigned.
        self.assertEqual(testing_plugin["id"], stable_plugin["id"])
        self.assertEqual(
            [version["name"] for version in stable_plugin["versions"]], ["1.0.0"]
        )
        self.assertEqual(
            [version["name"] for version in testing_plugin["versions"]],
            ["2.0.0-beta.1", "1.0.0"],
        )
        self.assertEqual(testing_plugin["author"], "Decky Author")
        self.assertEqual(testing_plugin["tags"], ["utility"])
        # No publish.image in this plugin.json, so both entries get the repo card.
        self.assertEqual(
            stable_plugin["image_url"],
            "https://opengraph.githubassets.com/1/example/custom-plugin",
        )
        self.assertEqual(testing_plugin["image_url"], stable_plugin["image_url"])

    def test_main_publishes_storefront_metadata_for_same_name_repositories(self):
        base_stable = [
            {
                "id": 7,
                "name": "Shared Plugin",
                "versions": [
                    {
                        "name": "0.9.0",
                        "hash": "f" * 64,
                        "artifact": "https://example.invalid/official.zip",
                    }
                ],
            }
        ]
        repository_releases = {
            ("owner", "one"): [
                {
                    "tag_name": "v2.0.0",
                    "prerelease": False,
                    "metadata_hash": "b" * 64,
                }
            ],
            ("owner", "two"): [
                {
                    "tag_name": "v1.0.0",
                    "prerelease": False,
                    "metadata_hash": "a" * 64,
                }
            ],
        }
        repo_info = {
            "default_branch": "main",
            "description": "Repository description",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        package = {"name": "shared-plugin", "author": "Decky Author"}
        plugin_json = {"name": "Shared Plugin"}

        def fetch_json(url):
            if url == generate_json.PLUGINS_URL:
                return copy.deepcopy(base_stable)
            return []

        def build_version_object(release, existing_plugin=None, policy=None):
            del existing_plugin, policy
            name = release["tag_name"].lstrip("v")
            return {
                "name": name,
                "hash": release["metadata_hash"],
                "artifact": f"https://example.invalid/{name}.zip",
                "created": "2026-01-01T00:00:00Z",
                "downloads": 0,
                "updates": 0,
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            (workdir / "additional_plugins.txt").write_text(
                "\n".join(
                    (
                        "https://github.com/owner/one",
                        "https://github.com/owner/two",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            static = workdir / "static"
            static.mkdir()
            for name in ("index.html", "storefront.css", "storefront.js"):
                (static / name).write_text(name, encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(workdir)
                with (
                    patch.object(generate_json, "fetch_json", side_effect=fetch_json),
                    patch.object(
                        generate_json, "get_repo_info", return_value=repo_info
                    ),
                    patch.object(
                        generate_json, "get_package_json", return_value=package
                    ),
                    patch.object(
                        generate_json, "get_plugin_json", return_value=plugin_json
                    ),
                    patch.object(
                        generate_json,
                        "get_releases",
                        side_effect=lambda owner, repo: repository_releases[
                            (owner, repo)
                        ],
                    ),
                    patch.object(
                        generate_json,
                        "build_version_object",
                        side_effect=build_version_object,
                    ),
                ):
                    generate_json.main()
            finally:
                os.chdir(old_cwd)

            storefront = json.loads(
                (workdir / "public/storefront.json").read_text(encoding="utf-8")
            )
            stable = json.loads(
                (workdir / "public/plugins.json").read_text(encoding="utf-8")
            )
            published = {path.name for path in (workdir / "public").iterdir()}

        self.assertEqual(storefront["schema_version"], 1)
        self.assertEqual(
            storefront["plugins"]["shared plugin"]["provenance"], "official"
        )
        self.assertEqual(
            storefront["plugins"]["shared plugin"]["versions"],
            [
                {
                    "name": "1.0.0",
                    "hash": "a" * 64,
                    "tag": "1.0.0",
                    "repository": "owner/two",
                    "source_url": "https://github.com/owner/two",
                },
                {
                    "name": "2.0.0",
                    "hash": "b" * 64,
                    "tag": "2.0.0",
                    "repository": "owner/one",
                    "source_url": "https://github.com/owner/one",
                },
            ],
        )
        self.assertTrue(
            {
                "plugins.json",
                "testing_plugins.json",
                "storefront.json",
                "audit.json",
                "index.html",
                "storefront.css",
                "storefront.js",
            }.issubset(published)
        )
        self.assertFalse(any("storefront" in entry for entry in stable))

    def test_main_annotates_merged_entries_with_the_official_version(self):
        base_stable = [
            {
                "id": 7,
                "name": "Merged Plugin",
                "description": "Official description",
                "versions": [
                    {
                        "name": "1.0.0",
                        "hash": "a" * 64,
                        "artifact": "https://example.invalid/official.zip",
                    }
                ],
            },
            {
                "id": 8,
                "name": "Unconfigured Plugin",
                "description": "Unconfigured description",
                "versions": [
                    {
                        "name": "1.0.0",
                        "hash": "b" * 64,
                        "artifact": "https://example.invalid/unconfigured.zip",
                    }
                ],
            },
        ]
        repo_info = {
            "default_branch": "main",
            "description": "Repository description",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        plugin_json = {"name": "Merged Plugin"}
        package = {
            "name": "merged-plugin",
            "author": {"name": "Decky Author"},
            "description": "Plugin description",
            "keywords": "utility",
        }
        releases = [{"tag_name": "v2.0.0", "prerelease": False}]

        def fetch_json(url):
            if url == generate_json.PLUGINS_URL:
                return copy.deepcopy(base_stable)
            return []

        def build_version_object(release, existing_plugin=None, policy=None):
            del existing_plugin, policy
            return {
                "name": release["tag_name"].lstrip("v"),
                "hash": "c" * 64,
                "artifact": "https://example.invalid/2.0.0.zip",
                "created": "2026-01-01T00:00:00Z",
                "downloads": 0,
                "updates": 0,
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            workdir = Path(temp_dir)
            (workdir / "additional_plugins.txt").write_text(
                "https://github.com/example/merged-plugin\n", encoding="utf-8"
            )
            old_cwd = Path.cwd()
            try:
                os.chdir(workdir)
                with (
                    patch.object(generate_json, "fetch_json", side_effect=fetch_json),
                    patch.object(
                        generate_json, "get_repo_info", return_value=repo_info
                    ),
                    patch.object(
                        generate_json, "get_package_json", return_value=package
                    ),
                    patch.object(
                        generate_json, "get_plugin_json", return_value=plugin_json
                    ),
                    patch.object(generate_json, "get_releases", return_value=releases),
                    patch.object(
                        generate_json,
                        "build_version_object",
                        side_effect=build_version_object,
                    ),
                ):
                    generate_json.main()
            finally:
                os.chdir(old_cwd)

            stable = json.loads(
                (workdir / "public/plugins.json").read_text(encoding="utf-8")
            )

        merged = next(plugin for plugin in stable if plugin["name"] == "Merged Plugin")
        unconfigured = next(
            plugin for plugin in stable if plugin["name"] == "Unconfigured Plugin"
        )
        self.assertTrue(
            merged["description"].startswith(
                "Official store has 1.0.0; this store has 2.0.0."
            )
        )
        self.assertEqual(unconfigured["description"], "Unconfigured description")


if __name__ == "__main__":
    unittest.main()
