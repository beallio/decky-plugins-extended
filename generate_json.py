import os
import sys
import json
import base64
import requests
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Source URLs
PLUGINS_URL = "https://plugins.deckbrew.xyz/plugins"
TESTING_PLUGINS_URL = "https://testing.deckbrew.xyz/plugins"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable is required")


def get_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[403, 429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    })
    return session


def get_anon_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[403, 429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


session = get_session()
anon_session = get_anon_session()


def fetch_json(url):
    resp = anon_session.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_repo_info(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = session.get(url, timeout=10)
    resp.raise_for_status()
    return resp.json()


def get_package_json(owner, repo, branch):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/package.json?ref={branch}"
    resp = session.get(url, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if data.get("encoding") == "base64":
        content = base64.b64decode(data["content"]).decode("utf-8")
        return json.loads(content)
    raise ValueError(f"Unsupported encoding for package.json in {owner}/{repo}")


def get_releases(owner, repo):
    releases = []
    url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100"
    while url:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        releases.extend(resp.json())
        url = resp.links.get("next", {}).get("url")
    return releases


def calculate_hash(download_url):
    print(f"    Downloading to calculate hash: {download_url}")
    resp = anon_session.get(download_url, stream=True, timeout=30)
    resp.raise_for_status()
    h = hashlib.sha256()
    for chunk in resp.iter_content(chunk_size=8192):
        if chunk:
            h.update(chunk)
    return h.hexdigest()


def build_version_object(release, existing_plugin=None):
    tag_name = release.get("tag_name", "1.0.0").lstrip("v")

    zip_assets = [a for a in release.get("assets", []) if a.get("name", "").endswith(".zip")]
    if len(zip_assets) != 1:
        print(f"    Warning: Expected exactly 1 zip asset for {tag_name}, found {len(zip_assets)}. Skipping.")
        return None

    download_url = zip_assets[0].get("browser_download_url")

    # Performance Optimization: Avoid re-hashing if we already know this version
    known_hash = None
    if existing_plugin:
        for v in existing_plugin.get("versions", []):
            if v.get("name") == tag_name and v.get("artifact") == download_url and v.get("hash"):
                known_hash = v.get("hash")
                break

    final_hash = known_hash if known_hash else calculate_hash(download_url)

    return {
        "name": tag_name,
        "hash": final_hash,
        "artifact": download_url,
        "created": release.get("published_at") or release.get("created_at"),
        "downloads": 0,
        "updates": 0
    }


def merge_plugin_versions(existing_plugin, new_versions):
    existing_versions = {v["name"]: v for v in existing_plugin.get("versions", [])}

    for nv in new_versions:
        # Update if it doesn't exist or if the hash has changed
        if nv["name"] not in existing_versions or existing_versions[nv["name"]].get("hash") != nv.get("hash"):
            if nv["name"] in existing_versions:
                idx = existing_plugin["versions"].index(existing_versions[nv["name"]])
                # Preserve existing fields we don't strictly overwrite
                preserved_fields = {k: v for k, v in existing_versions[nv["name"]].items() if k not in ["name", "hash", "artifact", "created"]}
                nv.update(preserved_fields)
                existing_plugin["versions"][idx] = nv
            else:
                existing_plugin.setdefault("versions", []).append(nv)
            existing_versions[nv["name"]] = nv

    existing_plugin["versions"].sort(key=lambda x: x.get("created", ""), reverse=True)


def validate_plugin_schema(plugins, list_type, artifact_required_names=None):
    artifact_required_names = artifact_required_names or set()
    for p in plugins:
        assert "id" in p, f"Missing id in {list_type}"
        assert "name" in p, f"Missing name in {list_type}"
        assert p.get("versions"), f"Plugin {p['name']} has empty versions array in {list_type}"
        for v in p.get("versions", []):
            assert "name" in v, f"Missing version name in {p['name']} ({list_type})"
            assert v.get("hash"), f"Missing or empty hash in {p['name']} version {v['name']} ({list_type})"
            assert len(v["hash"]) == 64, f"Invalid hash length in {p['name']} version {v['name']} ({list_type})"
            if p["name"] in artifact_required_names:
                assert v.get("artifact"), f"Missing artifact URL in {p['name']} version {v['name']} ({list_type})"


def main():
    if not os.path.exists("additional_plugins.txt"):
        print("No additional_plugins.txt found. Exiting.")
        sys.exit(1)

    print("Fetching base JSON lists...")
    plugins = fetch_json(PLUGINS_URL)
    testing_plugins = fetch_json(TESTING_PLUGINS_URL)

    # Maintain independent ID spaces
    max_stable_id = max([p.get("id", 0) for p in plugins]) if plugins else 0
    max_testing_id = max([p.get("id", 0) for p in testing_plugins]) if testing_plugins else 0

    with open("additional_plugins.txt", "r") as f:
        repo_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    errors = []
    custom_plugin_names = set()

    for url in repo_urls:
        try:
            print(f"Processing {url}...")
            parts = url.rstrip('/').split('/')
            owner, repo = parts[-2], parts[-1]

            repo_info = get_repo_info(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            pkg = get_package_json(owner, repo, default_branch)
            plugin_name = pkg.get("name")
            if not plugin_name:
                raise ValueError(f"package.json missing 'name' for {url}")

            existing_stable = next((p for p in plugins if p.get("name") == plugin_name), None)
            existing_testing = next((p for p in testing_plugins if p.get("name") == plugin_name), None)

            releases = get_releases(owner, repo)

            stable_versions = []
            testing_versions = []

            for rel in releases:
                v_obj = build_version_object(rel, existing_testing or existing_stable)
                if not v_obj:
                    continue

                # Testing includes stable + prereleases
                testing_versions.append(v_obj.copy())
                # Stable only includes non-prereleases
                if not rel.get("prerelease"):
                    stable_versions.append(v_obj.copy())

            if not testing_versions:
                print(f"  Warning: No valid releases found for {plugin_name}. Skipping.")
                continue

            custom_plugin_names.add(plugin_name)

            author = pkg.get("author", owner)
            if isinstance(author, dict):
                author = author.get("name", owner)

            tags = pkg.get("keywords", [])
            if isinstance(tags, str):
                tags = [tags]

            # --- TESTING PLUGINS ---
            if existing_testing:
                print(f"  Found in testing plugins. Merging versions...")
                merge_plugin_versions(existing_testing, testing_versions)
            else:
                print(f"  Adding to testing plugins...")
                max_testing_id += 1
                new_testing = {
                    "id": max_testing_id,
                    "name": plugin_name,
                    "author": author,
                    "description": pkg.get("description", repo_info.get("description", "")),
                    "tags": tags,
                    "versions": testing_versions,
                    "visible": True,
                    "image_url": "",
                    "downloads": 0,
                    "updates": 0,
                    "created": repo_info.get("created_at"),
                    "updated": repo_info.get("updated_at")
                }
                testing_plugins.append(new_testing)

            # --- STABLE PLUGINS ---
            if stable_versions:
                if existing_stable:
                    print(f"  Found in stable plugins. Merging versions...")
                    merge_plugin_versions(existing_stable, stable_versions)
                else:
                    print(f"  Adding to stable plugins...")
                    max_stable_id += 1
                    new_stable = {
                        "id": max_stable_id,
                        "name": plugin_name,
                        "author": author,
                        "description": pkg.get("description", repo_info.get("description", "")),
                        "tags": tags,
                        "versions": stable_versions,
                        "visible": True,
                        "image_url": "",
                        "downloads": 0,
                        "updates": 0,
                        "created": repo_info.get("created_at"),
                        "updated": repo_info.get("updated_at")
                    }
                    plugins.append(new_stable)
            else:
                print(f"  No stable releases found for {plugin_name}. Skipping stable plugins.")

        except Exception as e:
            errors.append(f"Failed to process {url}: {e}")

    if errors:
        print("\n=== ERRORS ===")
        for e in errors:
            print(e)
        sys.exit(1)

    print("Validating generated plugin schemas...")
    validate_plugin_schema(plugins, "stable", custom_plugin_names)
    validate_plugin_schema(testing_plugins, "testing", custom_plugin_names)

    os.makedirs("public", exist_ok=True)
    with open("public/plugins.json", "w") as f:
        json.dump(plugins, f, indent=2)
    with open("public/testing_plugins.json", "w") as f:
        json.dump(testing_plugins, f, indent=2)

    print("Successfully generated JSON files in the 'public' directory.")


if __name__ == "__main__":
    main()
