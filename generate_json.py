import os
import re
import sys
import json
import base64
import shutil
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


def get_repo_json(owner, repo, branch, filename, required=True):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}?ref={branch}"
    resp = session.get(url, timeout=10)
    if resp.status_code == 404 and not required:
        return None
    resp.raise_for_status()
    data = resp.json()
    if data.get("encoding") == "base64":
        content = base64.b64decode(data["content"]).decode("utf-8")
        return json.loads(content)
    raise ValueError(f"Unsupported encoding for {filename} in {owner}/{repo}")


def get_package_json(owner, repo, branch):
    return get_repo_json(owner, repo, branch, "package.json")


def get_plugin_json(owner, repo, branch):
    return get_repo_json(owner, repo, branch, "plugin.json", required=False)


def resolve_plugin_name(plugin_json, pkg):
    """Decky identifies an installed plugin by the name in its plugin.json:
    find_plugin_folder() matches on it, and checkForPluginUpdates() compares it
    against the store entry's name. A catalog keyed on the package.json name
    ("sdh-ludusavi" vs "SDH-Ludusavi") therefore never matches what is installed,
    so updates are never offered. Prefer plugin.json and keep package.json as the
    fallback for repositories that do not ship one on the default branch."""
    return (plugin_json or {}).get("name") or (pkg or {}).get("name")


# The plugin template ships this as the placeholder store image. Repositories
# that never edited it would render the loader's repo card instead of their own.
TEMPLATE_IMAGE_REPO = "SteamDeckHomebrew/PluginLoader"


def image_is_usable(url):
    """Reject images that are provably gone. A transient failure (rate limiting,
    a 5xx, a timeout) is not proof, so keep the URL rather than flipping the
    catalog to the fallback on a bad build."""
    try:
        resp = anon_session.head(url, timeout=15, allow_redirects=True)
        if resp.status_code >= 400:
            # Some hosts refuse HEAD; confirm with a GET before believing it.
            resp = anon_session.get(url, timeout=15, stream=True)
            resp.close()
    except requests.RequestException as e:
        print(f"    Warning: could not check image {url} ({e}). Keeping it.")
        return True

    if resp.status_code == 200:
        return resp.headers.get("content-type", "").startswith("image/")
    if resp.status_code in (404, 403, 410):
        return False
    print(f"    Warning: image check for {url} returned {resp.status_code}. Keeping it.")
    return True


def resolve_tags(plugin_json, pkg):
    """The store card decides whether to show the "runs as root" warning by
    looking for a 'root' tag (PluginCard: storePlugin.tags.some(t => t ===
    'root')), but a plugin declares that in plugin.json's flags. Mirror the
    official catalog: publish.tags plus 'root' when flagged, sorted, with
    package.json keywords only as a fallback -- those are usually template
    boilerplate ('plugin-template', 'deck') rather than curated tags."""
    plugin_json = plugin_json or {}
    publish = plugin_json.get("publish") or {}

    tags = publish.get("tags") or (pkg or {}).get("keywords") or []
    if isinstance(tags, str):
        tags = [tags]
    tags = [str(tag).strip() for tag in tags if str(tag).strip()]

    if "root" in (plugin_json.get("flags") or []):
        tags.append("root")

    # 'debug' is a loader-side flag; it never appears in the official catalog.
    return sorted({tag for tag in tags if tag != "debug"})


def resolve_description(plugin_json, pkg, repo_info):
    """publish.description is the store-facing copy; package.json's description
    is aimed at developers and is sometimes not even in English."""
    publish = (plugin_json or {}).get("publish") or {}
    for candidate in (publish.get("description"), (pkg or {}).get("description"), (repo_info or {}).get("description")):
        if candidate and candidate.strip():
            return candidate.strip()
    return ""


def resolve_image_url(plugin_json, owner, repo):
    """Store card images come from plugin.json's publish.image, the same field
    the official store ingests. Fall back to the repository's OpenGraph card,
    which GitHub renders for every repo, so no entry is left with a blank image."""
    plugin_json = plugin_json or {}
    publish = plugin_json.get("publish") or {}
    candidate = (publish.get("image") or plugin_json.get("image") or "").strip()
    fallback = f"https://opengraph.githubassets.com/1/{owner}/{repo}"

    if not candidate:
        return fallback
    if TEMPLATE_IMAGE_REPO in candidate and f"{owner}/{repo}" != TEMPLATE_IMAGE_REPO:
        print(f"    Note: {owner}/{repo} still has the template placeholder image. Using its repo card.")
        return fallback
    if not image_is_usable(candidate):
        print(f"    Note: {owner}/{repo} publish.image is unreachable. Using its repo card.")
        return fallback
    return candidate


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


# Matches the version inside a release tag: "v1.2.3", "Release-0.7.1",
# "decky-romm-sync-v0.29.0" all yield the bare version.
VERSION_IN_TAG = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?")


def normalize_version(tag_name):
    """Decky runs store version strings through compare-versions' validate()
    before offering an update, and anything that is not semver-shaped is
    discarded -- a plugin tagged "Release-0.7.1" can never show an update. Pull
    the version out of the tag, falling back to the bare tag when it holds
    nothing version-shaped."""
    match = VERSION_IN_TAG.search(tag_name)
    if match:
        return match.group(0)
    return tag_name.lstrip("v")


def build_version_object(release, existing_plugin=None):
    tag_name = normalize_version(release.get("tag_name", "1.0.0"))

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

    final_hash = None
    
    # Check if GitHub natively provided the SHA-256 (recent GitHub feature)
    github_digest = zip_assets[0].get("digest")
    if github_digest and github_digest.startswith("sha256:"):
        final_hash = github_digest.split(":")[1]
        
    if not final_hash:
        final_hash = known_hash if known_hash else calculate_hash(download_url)

    return {
        "name": tag_name,
        "hash": final_hash,
        "artifact": download_url,
        "created": release.get("published_at") or release.get("created_at"),
        "downloads": 0,
        "updates": 0
    }


SEMVER = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def parse_semver(name):
    """Returns (major, minor, patch, prerelease_identifiers) or None. Prerelease
    identifiers are compared per semver: numeric ones numerically, so beta.10
    outranks beta.9. Build metadata is ignored, as compare-versions ignores it."""
    match = SEMVER.match((name or "").strip())
    if not match:
        return None

    major, minor, patch, prerelease = match.groups()
    identifiers = []
    for part in (prerelease or "").split(".") if prerelease else []:
        identifiers.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return int(major), int(minor or 0), int(patch or 0), identifiers


def version_sort_key(version):
    """Decky only ever reads versions[0] -- checkForPluginUpdates compares it
    against the installed version and the install dropdown defaults to it -- so
    the highest version has to sort first. Ordering by release date instead puts
    a late hotfix to an old branch on top, and floats rolling tags ("nightly",
    "dev-build") above every real release, where validate() then rejects them and
    no update is ever offered. Versions with no parseable number sort last."""
    parsed = parse_semver(version.get("name", ""))
    created = version.get("created") or ""
    if parsed is None:
        return (0, 0, 0, 0, 0, [], created)

    major, minor, patch, prerelease = parsed
    # A prerelease ranks below the release it leads to: 1.0.0 > 1.0.0-beta.1.
    return (1, major, minor, patch, 0 if prerelease else 1, prerelease, created)


def sort_versions(versions):
    versions.sort(key=version_sort_key, reverse=True)
    return versions


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

    sort_versions(existing_plugin["versions"])


def read_repo_urls(path="additional_plugins.txt"):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def copy_static_files(source="static", destination="public"):
    """public/ is build output and gitignored, so the landing page lives in
    static/ and is copied in on every build alongside the generated catalogs."""
    if not os.path.isdir(source):
        return []

    copied = []
    for name in sorted(os.listdir(source)):
        path = os.path.join(source, name)
        if os.path.isfile(path):
            shutil.copy2(path, os.path.join(destination, name))
            copied.append(name)

    if copied:
        print(f"Copied {len(copied)} static file(s): {', '.join(copied)}")
    return copied


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

    repo_urls = read_repo_urls()

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
            plugin_json = get_plugin_json(owner, repo, default_branch)
            plugin_name = resolve_plugin_name(plugin_json, pkg)
            if not plugin_name:
                raise ValueError(f"No 'name' in plugin.json or package.json for {url}")
            if plugin_json is None:
                print(f"  Warning: no plugin.json on {default_branch}; falling back to the package.json name '{plugin_name}'.")

            existing_stable = next((p for p in plugins if p.get("name", "").lower() == plugin_name.lower()), None)
            existing_testing = next((p for p in testing_plugins if p.get("name", "").lower() == plugin_name.lower()), None)

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

            sort_versions(stable_versions)
            sort_versions(testing_versions)

            custom_plugin_names.add(plugin_name)

            author = pkg.get("author", owner)
            if isinstance(author, dict):
                author = author.get("name", owner)

            tags = resolve_tags(plugin_json, pkg)
            description = resolve_description(plugin_json, pkg, repo_info)

            # Only for entries this generator creates: plugins that merge into an
            # upstream entry keep the store's own CDN image.
            image_url = resolve_image_url(plugin_json, owner, repo)

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
                    "description": description,
                    "tags": tags,
                    "versions": testing_versions,
                    "visible": True,
                    "image_url": image_url,
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
                        "description": description,
                        "tags": tags,
                        "versions": stable_versions,
                        "visible": True,
                        "image_url": image_url,
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
        # A single unreachable repo must not blackhole the whole feed. Only bail
        # out if nothing at all resolved, which points at a systemic failure.
        if not custom_plugin_names:
            print("No plugins resolved successfully. Aborting.")
            sys.exit(1)
        print(f"Continuing with {len(custom_plugin_names)} successfully processed plugin(s).")

    # Ensure all testing plugin IDs match their stable counterparts exactly
    for testing_plugin in testing_plugins:
        stable_plugin = next((p for p in plugins if p.get("name", "").lower() == testing_plugin.get("name", "").lower()), None)
        if stable_plugin:
            testing_plugin["id"] = stable_plugin["id"]

    print("\nValidating plugin schemas...")
    validate_plugin_schema(plugins, "stable", custom_plugin_names)
    validate_plugin_schema(testing_plugins, "testing", custom_plugin_names)

    os.makedirs("public", exist_ok=True)
    with open("public/plugins.json", "w") as f:
        json.dump(plugins, f, indent=2)
    with open("public/testing_plugins.json", "w") as f:
        json.dump(testing_plugins, f, indent=2)
        
    # Write Cloudflare Pages _headers file for Decky Loader CORS preflight
    with open("public/_headers", "w") as f:
        f.write("/*\n  Access-Control-Allow-Origin: *\n  Access-Control-Allow-Methods: GET, OPTIONS\n  Access-Control-Allow-Headers: X-Decky-Version\n")

    copy_static_files()

    print("Successfully generated JSON files in the 'public' directory.")


if __name__ == "__main__":
    main()
