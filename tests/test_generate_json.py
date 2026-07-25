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

    def test_build_version_object_reuses_known_hash(self):
        artifact = "https://example.invalid/plugin.zip"
        known_hash = "a" * 64
        release = {
            "tag_name": "v1.2.3",
            "published_at": "2026-01-02T00:00:00Z",
            "assets": [{"name": "plugin.zip", "browser_download_url": artifact}],
        }
        existing = {
            "versions": [{"name": "1.2.3", "artifact": artifact, "hash": known_hash}]
        }

        with patch.object(generate_json, "calculate_hash") as calculate_hash:
            version = generate_json.build_version_object(release, existing)

        calculate_hash.assert_not_called()
        self.assertEqual(version["hash"], known_hash)
        self.assertEqual(version["artifact"], artifact)

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
            generate_json.resolve_plugin_name({"name": "SDH-Ludusavi"}, {"name": "sdh-ludusavi"}),
            "SDH-Ludusavi",
        )
        self.assertEqual(generate_json.resolve_plugin_name(None, {"name": "sdh-ludusavi"}), "sdh-ludusavi")
        self.assertEqual(generate_json.resolve_plugin_name({}, {"name": "sdh-ludusavi"}), "sdh-ludusavi")
        self.assertIsNone(generate_json.resolve_plugin_name(None, {}))

    def test_resolve_tags_promotes_the_root_flag(self):
        # The store card shows its root warning off a 'root' tag, not off flags.
        plugin_json = {"publish": {"tags": ["vpn", "network"]}, "flags": ["root", "_root", "debug"]}

        self.assertEqual(
            generate_json.resolve_tags(plugin_json, {"keywords": ["ignored"]}),
            ["network", "root", "vpn"],
        )

    def test_resolve_tags_falls_back_to_keywords(self):
        self.assertEqual(
            generate_json.resolve_tags({"publish": {}}, {"keywords": ["deck", "plugin"]}),
            ["deck", "plugin"],
        )
        self.assertEqual(generate_json.resolve_tags(None, {"keywords": "utility"}), ["utility"])
        self.assertEqual(generate_json.resolve_tags(None, {}), [])
        # A root plugin with no tags at all still gets the marker.
        self.assertEqual(generate_json.resolve_tags({"flags": ["root"]}, {}), ["root"])

    def test_resolve_description_prefers_publish_description(self):
        plugin_json = {"publish": {"description": "Store copy"}}
        pkg = {"description": "Developer copy"}
        repo_info = {"description": "Repo copy"}

        self.assertEqual(generate_json.resolve_description(plugin_json, pkg, repo_info), "Store copy")
        self.assertEqual(generate_json.resolve_description({"publish": {}}, pkg, repo_info), "Developer copy")
        self.assertEqual(generate_json.resolve_description(None, {"description": "  "}, repo_info), "Repo copy")
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

        with patch.object(generate_json, "image_is_usable", return_value=True) as usable:
            # Missing, empty, and the unedited template placeholder.
            self.assertEqual(generate_json.resolve_image_url(None, "owner", "repo"), fallback)
            self.assertEqual(generate_json.resolve_image_url({"publish": {}}, "owner", "repo"), fallback)
            self.assertEqual(
                generate_json.resolve_image_url({"publish": {"image": "  "}}, "owner", "repo"), fallback
            )
            self.assertEqual(
                generate_json.resolve_image_url({"publish": {"image": template}}, "owner", "repo"), fallback
            )
            usable.assert_not_called()

        # A dead link is replaced too.
        with patch.object(generate_json, "image_is_usable", return_value=False):
            self.assertEqual(
                generate_json.resolve_image_url(
                    {"publish": {"image": "https://example.invalid/gone.png"}}, "owner", "repo"
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
            (Response(200, "text/html"), False),   # a 404 page served as 200
            (Response(404, "text/plain"), False),
            (Response(429, "text/html"), True),    # rate limited, not proof of a dead link
            (Response(503, "text/html"), True),
        ]
        for response, expected in cases:
            with self.subTest(status=response.status_code, ctype=response.headers["content-type"]):
                with (
                    patch.object(generate_json.anon_session, "head", return_value=response),
                    patch.object(generate_json.anon_session, "get", return_value=response),
                ):
                    self.assertIs(generate_json.image_is_usable("https://example.invalid/x.png"), expected)

    def test_image_is_usable_keeps_url_on_network_error(self):
        with patch.object(
            generate_json.anon_session, "head", side_effect=generate_json.requests.RequestException("boom")
        ):
            self.assertTrue(generate_json.image_is_usable("https://example.invalid/x.png"))

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

        self.assertEqual([version["name"] for version in plugin["versions"]], ["2.0.0", "1.0.0"])
        self.assertEqual(plugin["versions"][1]["hash"], "b" * 64)
        self.assertEqual(plugin["versions"][1]["downloads"], 10)
        self.assertEqual(plugin["versions"][1]["updates"], 4)

    def test_validate_plugin_schema_rejects_bad_hash(self):
        plugins = [{
            "id": 1,
            "name": "Example",
            "versions": [{
                "name": "1.0.0",
                "hash": "too-short",
                "artifact": "https://example.invalid/plugin.zip",
            }],
        }]

        with self.assertRaisesRegex(AssertionError, "Invalid hash length"):
            generate_json.validate_plugin_schema(plugins, "stable")

    def test_main_separates_stable_and_testing_releases_and_ids(self):
        base_stable = [{
            "id": 7,
            "name": "OfficialStable",
            "versions": [{
                "name": "1.0.0",
                "hash": "a" * 64,
                "artifact": "https://example.invalid/official-stable.zip",
            }],
        }]
        base_testing = [{
            "id": 11,
            "name": "OfficialTesting",
            "versions": [{
                "name": "1.0.0",
                "hash": "b" * 64,
                "artifact": "https://example.invalid/official-testing.zip",
            }],
        }]
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

        def build_version_object(release, existing_plugin=None):
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
                    patch.object(generate_json, "get_repo_info", return_value=repo_info),
                    patch.object(generate_json, "get_package_json", return_value=package),
                    patch.object(generate_json, "get_plugin_json", return_value=plugin_json),
                    patch.object(generate_json, "get_releases", return_value=releases),
                    patch.object(generate_json, "build_version_object", side_effect=build_version_object),
                ):
                    generate_json.main()
            finally:
                os.chdir(old_cwd)

            stable = json.loads((workdir / "public/plugins.json").read_text(encoding="utf-8"))
            testing = json.loads((workdir / "public/testing_plugins.json").read_text(encoding="utf-8"))

        stable_plugin = next(plugin for plugin in stable if plugin["name"] == "Custom Plugin")
        testing_plugin = next(plugin for plugin in testing if plugin["name"] == "Custom Plugin")
        self.assertEqual(stable_plugin["id"], 8)
        # Testing IDs are synced to their stable counterpart, so this is 8 and
        # not the 12 that the independent testing ID space would have assigned.
        self.assertEqual(testing_plugin["id"], stable_plugin["id"])
        self.assertEqual([version["name"] for version in stable_plugin["versions"]], ["1.0.0"])
        self.assertEqual(
            [version["name"] for version in testing_plugin["versions"]],
            ["2.0.0-beta.1", "1.0.0"],
        )
        self.assertEqual(testing_plugin["author"], "Decky Author")
        self.assertEqual(testing_plugin["tags"], ["utility"])
        # No publish.image in this plugin.json, so both entries get the repo card.
        self.assertEqual(
            stable_plugin["image_url"], "https://opengraph.githubassets.com/1/example/custom-plugin"
        )
        self.assertEqual(testing_plugin["image_url"], stable_plugin["image_url"])


if __name__ == "__main__":
    unittest.main()
