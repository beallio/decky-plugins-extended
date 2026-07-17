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
        package = {
            "name": "CustomPlugin",
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
                    patch.object(generate_json, "get_releases", return_value=releases),
                    patch.object(generate_json, "build_version_object", side_effect=build_version_object),
                ):
                    generate_json.main()
            finally:
                os.chdir(old_cwd)

            stable = json.loads((workdir / "public/plugins.json").read_text(encoding="utf-8"))
            testing = json.loads((workdir / "public/testing_plugins.json").read_text(encoding="utf-8"))

        stable_plugin = next(plugin for plugin in stable if plugin["name"] == "CustomPlugin")
        testing_plugin = next(plugin for plugin in testing if plugin["name"] == "CustomPlugin")
        self.assertEqual(stable_plugin["id"], 8)
        self.assertEqual(testing_plugin["id"], 12)
        self.assertEqual([version["name"] for version in stable_plugin["versions"]], ["1.0.0"])
        self.assertEqual(
            [version["name"] for version in testing_plugin["versions"]],
            ["2.0.0-beta.1", "1.0.0"],
        )
        self.assertEqual(testing_plugin["author"], "Decky Author")
        self.assertEqual(testing_plugin["tags"], ["utility"])


if __name__ == "__main__":
    unittest.main()
