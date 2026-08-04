import base64
import hashlib
import json
import os
import shutil
import sys
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from audit_plugins import classification_for, load_policy, load_verdicts
from plugin_release_utils import (
    get_zip_asset,
    has_exactly_one_zip,
    normalize_version,
    version_sort_key,
)
from plugin_release_utils import (
    parse_semver as parse_semver,  # re-export for external callers of generate_json.parse_semver
)

# Source URLs
PLUGINS_URL = "https://plugins.deckbrew.xyz/plugins"
TESTING_PLUGINS_URL = "https://testing.deckbrew.xyz/plugins"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable is required")


def get_session():
    session = requests.Session()
    retry = Retry(
        total=3, backoff_factor=1, status_forcelist=[403, 429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    return session


def get_anon_session():
    session = requests.Session()
    retry = Retry(
        total=3, backoff_factor=1, status_forcelist=[403, 429, 500, 502, 503, 504]
    )
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
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}?ref={branch}"
    )
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
    print(
        f"    Warning: image check for {url} returned {resp.status_code}. Keeping it."
    )
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
    for candidate in (
        publish.get("description"),
        (pkg or {}).get("description"),
        (repo_info or {}).get("description"),
    ):
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
        print(
            f"    Note: {owner}/{repo} still has the template placeholder image. Using its repo card."
        )
        return fallback
    if not image_is_usable(candidate):
        print(
            f"    Note: {owner}/{repo} publish.image is unreachable. Using its repo card."
        )
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


def build_version_object(release, existing_plugin=None):
    tag_name = normalize_version(release.get("tag_name", "1.0.0"))

    if not has_exactly_one_zip(release):
        zips = [
            a
            for a in release.get("assets", [])
            if a.get("name", "").lower().endswith(".zip")
        ]
        print(
            f"    Warning: Expected exactly 1 zip asset for {tag_name}, found {len(zips)}. Skipping."
        )
        return None

    zip_asset = get_zip_asset(release)
    if zip_asset is None:
        return None
    download_url = zip_asset.get("browser_download_url")

    # Performance Optimization: Avoid re-hashing if we already know this version
    known_hash = None
    if existing_plugin:
        for v in existing_plugin.get("versions", []):
            if (
                v.get("name") == tag_name
                and v.get("artifact") == download_url
                and v.get("hash")
            ):
                known_hash = v.get("hash")
                break

    final_hash = None

    # Check if GitHub natively provided the SHA-256 (recent GitHub feature)
    github_digest = zip_asset.get("digest")
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
        "updates": 0,
    }


def sort_versions(versions):
    versions.sort(
        key=lambda v: version_sort_key(v.get("name", ""), v.get("created") or ""),
        reverse=True,
    )
    return versions


def merge_plugin_versions(existing_plugin, new_versions):
    existing_versions = {v["name"]: v for v in existing_plugin.get("versions", [])}

    for nv in new_versions:
        # Update if it doesn't exist or if the hash has changed
        if nv["name"] not in existing_versions or existing_versions[nv["name"]].get(
            "hash"
        ) != nv.get("hash"):
            if nv["name"] in existing_versions:
                idx = existing_plugin["versions"].index(existing_versions[nv["name"]])
                # Preserve existing fields we don't strictly overwrite
                preserved_fields = {
                    k: v
                    for k, v in existing_versions[nv["name"]].items()
                    if k not in ["name", "hash", "artifact", "created"]
                }
                nv.update(preserved_fields)
                existing_plugin["versions"][idx] = nv
            else:
                existing_plugin.setdefault("versions", []).append(nv)
            existing_versions[nv["name"]] = nv

    sort_versions(existing_plugin["versions"])


def remove_blocked_versions(existing_plugin, blocked_identities):
    """Remove audited artifacts by normalized version and SHA-256 together."""
    if not existing_plugin or not blocked_identities:
        return 0

    versions = existing_plugin.get("versions", [])
    retained = [
        version
        for version in versions
        if (version.get("name"), version.get("hash")) not in blocked_identities
    ]
    removed = len(versions) - len(retained)
    existing_plugin["versions"] = sort_versions(retained)
    return removed


def _release_verdict_entry(repository, release, verdicts):
    zip_asset = get_zip_asset(release)
    if zip_asset is None:
        return {}
    release_id = f"{release.get('tag_name', '')}@{zip_asset.get('id', '')}"
    return verdicts.get(repository.rstrip("/"), {}).get(release_id, {})


def _repository_slug(value):
    parsed = urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.netloc.lower() == "github.com" and len(parts) >= 2:
        return f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
    if not parsed.netloc:
        parts = [part for part in value.rstrip("/").split("/") if part]
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1].removesuffix('.git')}".lower()
    return ""


def catalog_version_is_blocked(version, verdicts):
    """Match an upstream catalog version to a durable BLOCK verdict."""
    repository_slug = _repository_slug(version.get("artifact", ""))
    if not repository_slug:
        return False

    identity = (version.get("name"), version.get("hash"))
    for repository, release_verdicts in verdicts.items():
        if _repository_slug(repository) != repository_slug:
            continue
        for release_id, entry in release_verdicts.items():
            tag_name = release_id.rsplit("@", 1)[0]
            audited_identity = (
                normalize_version(tag_name),
                entry.get("artifact_sha256"),
            )
            if identity == audited_identity and entry.get("classification") == "BLOCK":
                return True
    return False


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
        assert p.get("versions"), (
            f"Plugin {p['name']} has empty versions array in {list_type}"
        )
        for v in p.get("versions", []):
            assert "name" in v, f"Missing version name in {p['name']} ({list_type})"
            assert v.get("hash"), (
                f"Missing or empty hash in {p['name']} version {v['name']} ({list_type})"
            )
            assert len(v["hash"]) == 64, (
                f"Invalid hash length in {p['name']} version {v['name']} ({list_type})"
            )


def main():
    if not os.path.exists("additional_plugins.txt"):
        print("No additional_plugins.txt found. Exiting.")
        sys.exit(1)

    print("Fetching base JSON lists...")
    plugins = fetch_json(PLUGINS_URL)
    testing_plugins = fetch_json(TESTING_PLUGINS_URL)

    # Maintain independent ID spaces
    max_stable_id = max([p.get("id", 0) for p in plugins]) if plugins else 0
    max_testing_id = (
        max([p.get("id", 0) for p in testing_plugins]) if testing_plugins else 0
    )

    repo_urls = read_repo_urls()
    verdicts = load_verdicts()

    # The catalog gate honours security-policy.yml's enforcement mode. Under
    # "report-only" a BLOCK verdict is reported and the release still ships;
    # only "enforce" excludes it. Previously the gate excluded regardless, which
    # contradicted a policy file that has said report-only since it landed, and
    # removed eight legitimate plugins from the live catalog on the first real
    # audit run - every one of them a false positive.
    try:
        enforcement_mode = (load_policy().get("enforcement") or {}).get(
            "mode"
        ) or "report-only"
    except Exception as exc:  # a broken policy must not silently start blocking
        print(
            f"Warning: could not read enforcement mode ({exc}); assuming report-only."
        )
        enforcement_mode = "report-only"
    gating_enforced = enforcement_mode == "enforce"
    print(
        f"Catalog gate: enforcement mode is {enforcement_mode!r}"
        f" ({'excluding' if gating_enforced else 'reporting'} BLOCK verdicts)."
    )

    errors = []
    custom_plugin_names = set()

    for url in repo_urls:
        try:
            print(f"Processing {url}...")
            parts = url.rstrip("/").split("/")
            owner, repo = parts[-2], parts[-1]

            repo_info = get_repo_info(owner, repo)
            default_branch = repo_info.get("default_branch", "main")

            pkg = get_package_json(owner, repo, default_branch)
            plugin_json = get_plugin_json(owner, repo, default_branch)
            plugin_name = resolve_plugin_name(plugin_json, pkg)
            if not plugin_name:
                raise ValueError(f"No 'name' in plugin.json or package.json for {url}")
            if plugin_json is None:
                print(
                    f"  Warning: no plugin.json on {default_branch}; falling back to the package.json name '{plugin_name}'."
                )

            existing_stable = next(
                (
                    p
                    for p in plugins
                    if p.get("name", "").lower() == plugin_name.lower()
                ),
                None,
            )
            existing_testing = next(
                (
                    p
                    for p in testing_plugins
                    if p.get("name", "").lower() == plugin_name.lower()
                ),
                None,
            )

            releases = get_releases(owner, repo)

            stable_versions = []
            testing_versions = []
            blocked_identities = set()
            valid_release_count = 0
            blocked_release_count = 0

            for rel in releases:
                v_obj = build_version_object(rel, existing_testing or existing_stable)
                if not v_obj:
                    continue
                valid_release_count += 1

                verdict = classification_for(url, rel, verdicts)
                if verdict.effective_classification == "BLOCK" and not gating_enforced:
                    rule_ids = ", ".join(verdict.blocking_rule_ids) or "unknown rule"
                    print(
                        f"  [report-only] {plugin_name} release "
                        f"{rel.get('tag_name', '')} is BLOCK ({rule_ids}); shipping anyway."
                    )
                if verdict.effective_classification == "BLOCK" and gating_enforced:
                    blocked_release_count += 1
                    verdict_entry = _release_verdict_entry(url, rel, verdicts)
                    audited_hash = verdict_entry.get("artifact_sha256")
                    if audited_hash:
                        blocked_identities.add((v_obj["name"], audited_hash))
                    rule_ids = ", ".join(verdict.blocking_rule_ids) or "unknown rule"
                    print(
                        f"  Blocking {plugin_name} release {rel.get('tag_name', '')}: {rule_ids}"
                    )
                    continue

                # Testing includes stable + prereleases
                testing_versions.append(v_obj.copy())
                # Stable only includes non-prereleases
                if not rel.get("prerelease"):
                    stable_versions.append(v_obj.copy())

            remove_blocked_versions(existing_stable, blocked_identities)
            remove_blocked_versions(existing_testing, blocked_identities)

            if valid_release_count and blocked_release_count == valid_release_count:
                if existing_stable in plugins:
                    plugins.remove(existing_stable)
                if existing_testing in testing_plugins:
                    testing_plugins.remove(existing_testing)
                print(
                    f"  Warning: All valid releases for {plugin_name} are blocked. Removing it from both catalogs."
                )
                continue

            if not testing_versions:
                print(
                    f"  Warning: No valid releases found for {plugin_name}. Skipping."
                )
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
                print("  Found in testing plugins. Merging versions...")
                merge_plugin_versions(existing_testing, testing_versions)
            else:
                print("  Adding to testing plugins...")
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
                    "updated": repo_info.get("updated_at"),
                }
                testing_plugins.append(new_testing)

            # --- STABLE PLUGINS ---
            if stable_versions:
                if existing_stable:
                    print("  Found in stable plugins. Merging versions...")
                    merge_plugin_versions(existing_stable, stable_versions)
                else:
                    print("  Adding to stable plugins...")
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
                        "updated": repo_info.get("updated_at"),
                    }
                    plugins.append(new_stable)
            else:
                if existing_stable and not existing_stable.get("versions"):
                    plugins.remove(existing_stable)
                print(
                    f"  No stable releases found for {plugin_name}. Skipping stable plugins."
                )

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
        print(
            f"Continuing with {len(custom_plugin_names)} successfully processed plugin(s)."
        )

    # Ensure all testing plugin IDs match their stable counterparts exactly
    for testing_plugin in testing_plugins:
        stable_plugin = next(
            (
                p
                for p in plugins
                if p.get("name", "").lower() == testing_plugin.get("name", "").lower()
            ),
            None,
        )
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
        f.write(
            "/*\n  Access-Control-Allow-Origin: *\n  Access-Control-Allow-Methods: GET, OPTIONS\n  Access-Control-Allow-Headers: X-Decky-Version\n"
        )

    copy_static_files()

    print("Successfully generated JSON files in the 'public' directory.")


if __name__ == "__main__":
    main()
