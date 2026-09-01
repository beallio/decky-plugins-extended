import base64
import html
import json
import os
import shutil
import sys
import tempfile

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from audit_plugins import (
    classification_for,
    effective_stored_classification,
    load_policy,
    load_verdicts,
)
from plugin_release_utils import (
    DISCOVERED_PLUGIN_LIST_FILE,
    PLUGIN_LIST_FILE,
    bounded_stream_download,
    canonicalize_github_release_asset_repository_url,
    canonicalize_github_repository_url,
    get_zip_asset,
    is_release_eligible,
    load_store_versions,
    normalize_github_sha256_digest,
    normalize_version,
    parse_github_repository_url,
    version_sort_key,
)
from plugin_release_utils import get_releases as get_all_releases
from plugin_release_utils import (
    parse_semver as parse_semver,  # re-export for external callers of generate_json.parse_semver
)

# Source URLs
PLUGINS_URL = "https://plugins.deckbrew.xyz/plugins"
TESTING_PLUGINS_URL = "https://testing.deckbrew.xyz/plugins"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


class ArtifactDownloadError(RuntimeError):
    """The current artifact bytes could not be proven within policy."""


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
    return get_all_releases(owner, repo, session=session, timeout=10)


def calculate_hash(download_url, policy=None):
    print(f"    Downloading to calculate hash: {download_url}")
    try:
        with tempfile.TemporaryDirectory(prefix="decky-catalog-hash-") as temp_dir:
            result = bounded_stream_download(
                download_url,
                os.path.join(temp_dir, "release.zip"),
                session=anon_session,
                kind="release",
                policy=policy,
            )
            return result.sha256
    except Exception as exc:
        raise ArtifactDownloadError(
            f"Could not verify current artifact bytes for {download_url}: {exc}"
        ) from exc


def build_version_object(release, existing_plugin=None, policy=None):
    tag_name = normalize_version(release.get("tag_name", "1.0.0"))

    if not is_release_eligible(release, allow_prerelease=True):
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

    del existing_plugin  # Mutable catalog identity is never trusted for current bytes.

    final_hash = None

    # Check if GitHub natively provided the SHA-256 (recent GitHub feature)
    final_hash = normalize_github_sha256_digest(zip_asset.get("digest"))

    if not final_hash:
        final_hash = calculate_hash(download_url, policy=policy)

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


def official_latest_version(entry):
    """The version an upstream catalog entry leads with before this run merges.

    Called before merge_plugin_versions() mutates the entry, so it reports what
    the official store publishes rather than what this catalog assembles.

    The ordering rule must match the one annotate_official_version() applies to
    the merged side. Ranking the official side by created timestamp while
    ranking the merged side by semver lets a late hotfix on an old release
    branch make the note claim credit for a version the official store already
    had. sort_versions() sorts in place, so sort a shallow list copy: the
    element dicts are shared but never written, and the caller's own list order
    is left intact for merge_plugin_versions().
    """
    versions = list((entry or {}).get("versions") or [])
    if not versions:
        return None
    return sort_versions(versions)[0].get("name")


OFFICIAL_VERSION_NOTE_PREFIX = "Official store has "


def annotate_official_version(entry, official_version):
    """Record the official store's newest version in the store-facing copy.

    Decky renders only versions[].name in the version dropdown, and
    PluginCard's installedVersionIndex matches that name against the installed
    plugin's package.json version, so a label there breaks the install button.
    The description is the only other catalog string the store card renders.
    """
    if not entry or not official_version:
        return False
    versions = entry.get("versions") or []
    if not versions:
        return False
    newest = versions[0].get("name")
    if not newest or newest == official_version:
        return False
    description = (entry.get("description") or "").strip()
    note = f"{OFFICIAL_VERSION_NOTE_PREFIX}{official_version}; this store has {newest}."
    if description == note or description.startswith(f"{note} "):
        return False
    entry["description"] = f"{note} {description}".strip()
    return True


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


def drop_emptied_entry(catalog, entry):
    """Remove a catalog entry that the security gate has emptied.

    Called when every eligible release of a configured repository is blocked.
    Removing the whole entry outright would delete a plugin the official store
    still ships: remove_blocked_versions() drops only the exact audited
    identities, and the official store's own artifacts for the surviving
    versions were never audited under this verdict. An entry that still has
    versions therefore stays. An entry the generator would have created never
    reaches a catalog, because the caller skips the repository first.

    Returns True when the entry was removed.
    """
    if entry is None or entry.get("versions") or entry not in catalog:
        return False
    catalog.remove(entry)
    return True


def _release_verdict_entry(repository, release, verdicts):
    zip_asset = get_zip_asset(release)
    if zip_asset is None:
        return {}
    release_id = f"{release.get('tag_name', '')}@{zip_asset.get('id', '')}"
    canonical_repository = canonicalize_github_repository_url(repository)
    return verdicts.get(canonical_repository, {}).get(release_id, {})


def _repository_slug(value):
    try:
        repository = canonicalize_github_release_asset_repository_url(value)
    except ValueError:
        try:
            repository = canonicalize_github_repository_url(value)
        except ValueError:
            return ""
    return "/".join(parse_github_repository_url(repository))


def _log_policy_demotion(plugin, release, blocking_rule_ids):
    if blocking_rule_ids:
        rationale = (
            "stored rule IDs "
            + ", ".join(blocking_rule_ids)
            + " are not currently blockable"
        )
    else:
        rationale = "no blocking rule IDs were recorded"
    print(
        f"  [policy-demotion] {plugin} release {release}: stored BLOCK "
        f"re-derived as MANUAL_REVIEW; {rationale}."
    )


def catalog_version_is_blocked(
    version,
    verdicts,
    blockable_rules=None,
    *,
    release=None,
    current_artifact_sha256=None,
):
    """Return whether an exact current upstream release has a durable BLOCK."""
    if release is None or current_artifact_sha256 is None:
        return False
    try:
        repository = canonicalize_github_release_asset_repository_url(
            version.get("artifact", "")
        )
    except ValueError:
        return False
    verdict = classification_for(
        repository,
        release,
        verdicts,
        blockable_rules,
        current_artifact_sha256=current_artifact_sha256,
    )
    if (
        verdict.identity_status == "CURRENT"
        and verdict.audit_classification == "BLOCK"
        and verdict.effective_classification != "BLOCK"
    ):
        _log_policy_demotion(
            _repository_slug(repository) or repository,
            release.get("tag_name", ""),
            verdict.blocking_rule_ids,
        )
    return (
        verdict.identity_status == "CURRENT"
        and verdict.effective_classification == "BLOCK"
    )


def _read_url_lines(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def read_repo_urls(path=PLUGIN_LIST_FILE, discovered=DISCOVERED_PLUGIN_LIST_FILE):
    """Every configured repository: hand-maintained list, then the generated one.

    The generated store-backed list is optional, so the catalog still builds
    before the first discovery run and in test fixtures that only write the
    hand-maintained file. Lines are returned verbatim rather than canonicalized:
    main() canonicalizes inside its per-repository try block so one malformed
    line is reported as that repository's failure instead of aborting the run.
    """
    urls = _read_url_lines(path)
    if discovered and os.path.exists(discovered):
        urls.extend(_read_url_lines(discovered))
    return urls


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


def _catalog_name_keys(catalog):
    """Return the case-insensitive names present in a catalog snapshot."""
    return {
        str(entry.get("name", "")).strip().casefold()
        for entry in catalog or []
        if isinstance(entry, dict) and str(entry.get("name", "")).strip()
    }


def _visible_catalog_entries(catalog):
    """Return catalog entries published to browser users in their channel."""
    return [
        entry
        for entry in catalog or []
        if isinstance(entry, dict) and entry.get("visible") is not False
    ]


def build_storefront_metadata(
    stable_plugins,
    testing_plugins,
    official_catalog_names,
    contributions,
    enforcement_mode,
):
    """Build deterministic browser-only catalog provenance and status metadata.

    Decky's catalog schema remains unchanged. This sidecar records only the
    configured repositories that supplied an eligible artifact, keyed by the
    plugin's stable case-insensitive identity. Multiple repositories can publish
    distinct artifacts for one name, so versions are kept as records rather
    than overwriting one plugin-level source field.
    """
    official_catalog_names = {
        str(name).strip().casefold()
        for name in official_catalog_names or set()
        if str(name).strip()
    }
    stable_visible = _visible_catalog_entries(stable_plugins)
    testing_visible = _visible_catalog_entries(testing_plugins)
    catalog_names_by_key = {}
    for catalog in (stable_plugins, testing_plugins):
        for entry in catalog or []:
            if not isinstance(entry, dict):
                continue
            catalog_name = str(entry.get("name", "")).strip()
            if catalog_name:
                catalog_names_by_key.setdefault(catalog_name.casefold(), set()).add(
                    catalog_name
                )

    def extended_count(entries):
        return len(
            {
                str(entry.get("name", "")).strip().casefold()
                for entry in entries
                if str(entry.get("name", "")).strip().casefold()
                not in official_catalog_names
                and str(entry.get("name", "")).strip()
            }
        )

    by_plugin = {}
    for contribution in contributions or []:
        if not isinstance(contribution, dict):
            continue
        display_name = str(contribution.get("name", "")).strip()
        version = contribution.get("version")
        if not display_name or not isinstance(version, dict):
            continue
        key = display_name.casefold()
        normalized_name = normalize_version(str(version.get("name", "")).strip())
        normalized_tag = normalize_version(str(version.get("tag", "")).strip())
        record = {
            "name": normalized_name,
            "hash": str(version.get("hash", "")).strip().lower(),
            "tag": normalized_tag,
            "repository": str(version.get("repository", "")).strip(),
            "source_url": str(version.get("source_url", "")).strip(),
        }
        if not all(record.values()):
            continue
        details = by_plugin.setdefault(key, {"names": set(), "versions": []})
        details["names"].add(display_name)
        identity = tuple(
            record[field]
            for field in ("name", "hash", "tag", "repository", "source_url")
        )
        if identity not in {
            tuple(
                item[field]
                for field in ("name", "hash", "tag", "repository", "source_url")
            )
            for item in details["versions"]
        }:
            details["versions"].append(record)

    plugins = {}
    for key in sorted(by_plugin):
        details = by_plugin[key]
        versions = sorted(
            details["versions"],
            key=lambda version: (
                version["hash"],
                version["repository"],
                version["tag"],
                version["name"],
            ),
        )
        plugins[key] = {
            "name": min(details["names"], key=lambda name: (name.casefold(), name)),
            # Python casefold can merge names (for example, Straße and STRASSE)
            # that JavaScript lowercasing cannot. Publish the final catalog
            # spellings as exact lookup identities for the browser instead of
            # asking it to recreate Python's Unicode casefold behavior.
            "catalog_names": sorted(
                catalog_names_by_key.get(key, set()),
                key=lambda name: (name.casefold(), name),
            ),
            "provenance": "official" if key in official_catalog_names else "extended",
            "versions": versions,
        }

    return {
        "schema_version": 1,
        "enforcement_mode": enforcement_mode,
        "stable_count": len(stable_visible),
        "testing_count": len(testing_visible),
        "stable_extended_count": extended_count(stable_visible),
        "testing_extended_count": extended_count(testing_visible),
        "plugins": plugins,
    }


def write_storefront_metadata(path, metadata):
    """Write browser metadata with fixed formatting for reproducible builds."""
    with open(path, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)
        metadata_file.write("\n")


def _public_audit_records(
    verdicts, blockable_rules=None, current_identity_records=None
):
    """Return only the verdict fields that are safe and useful to publish."""
    records = []
    for repository, release_verdicts in verdicts.items():
        if not isinstance(release_verdicts, dict):
            continue
        for release, verdict in release_verdicts.items():
            if not isinstance(verdict, dict):
                continue

            rule_ids = set()
            for field in (
                "blocking_rule_ids",
                "review_rule_ids",
                "warning_rule_ids",
            ):
                values = verdict.get(field) or []
                if isinstance(values, list):
                    rule_ids.update(str(value) for value in values if value)

            stored_classification = str(verdict.get("classification") or "UNKNOWN")
            effective_classification = effective_stored_classification(
                verdict, blockable_rules
            )
            tag, asset_id = str(release).rsplit("@", 1)
            records.append(
                {
                    "repository": str(repository),
                    "release": str(release),
                    "tag": tag,
                    "asset_id": asset_id,
                    "classification": str(effective_classification),
                    "stored_classification": stored_classification,
                    "identity_status": "UNKNOWN",
                    "current_artifact_sha256": None,
                    "stored_artifact_sha256": verdict.get("artifact_sha256"),
                    "fail_open": True,
                    "outcome": "FAIL_OPEN",
                    "rule_ids": sorted(rule_ids),
                    "audited_at": str(verdict.get("audited_at") or ""),
                }
            )

    by_identity = {
        (record["repository"], record["release"]): record for record in records
    }
    for identity in current_identity_records or []:
        key = (identity["repository"], identity["release"])
        record = by_identity.get(key)
        if record is None:
            record = {
                "repository": identity["repository"],
                "release": identity["release"],
                "tag": identity["tag"],
                "asset_id": str(identity["asset_id"]),
                "classification": identity["classification"],
                "stored_classification": identity["stored_classification"],
                "rule_ids": [],
                "audited_at": "",
            }
            records.append(record)
            by_identity[key] = record
        record.update(
            {
                "tag": identity["tag"],
                "asset_id": str(identity["asset_id"]),
                "classification": identity["classification"],
                "stored_classification": identity["stored_classification"],
                "identity_status": identity["identity_status"],
                "current_artifact_sha256": identity["current_artifact_sha256"],
                "stored_artifact_sha256": identity["stored_artifact_sha256"],
                "fail_open": identity["fail_open"],
                "outcome": "FAIL_OPEN" if identity["fail_open"] else "APPLIED",
            }
        )

    # BLOCK is the only tier that can remove a release, so it must always be
    # visually first. Other tiers are labels, not a severity score.
    records.sort(
        key=lambda record: (
            record["classification"] != "BLOCK",
            record["classification"],
            record["repository"].lower(),
            record["release"].lower(),
        )
    )
    return records


def _audit_enforcement_copy(enforcement_mode):
    escaped_mode = html.escape(str(enforcement_mode))
    if enforcement_mode == "enforce":
        return (
            f"<strong>Current enforcement mode: {escaped_mode}.</strong> "
            "Releases with a BLOCK verdict are excluded from the catalogs."
        )
    if enforcement_mode == "report-only":
        return (
            f"<strong>Current enforcement mode: {escaped_mode}.</strong> "
            "No releases are currently excluded from the catalogs because of "
            "audit verdicts; BLOCK results are reported only."
        )
    return (
        f"<strong>Current enforcement mode: {escaped_mode}.</strong> "
        "Consult the repository policy for how this mode affects the catalogs."
    )


def _render_audit_html(records, enforcement_mode):
    cards = []
    for record in records:
        classification = html.escape(record["classification"])
        classification_class = "block" if record["classification"] == "BLOCK" else ""
        stored_classification = html.escape(record["stored_classification"])
        policy_disagreement = ""
        if record["classification"] != record["stored_classification"]:
            policy_disagreement = f"""
            <p class="policy-disagreement"><strong>Stored verdict: {stored_classification}.</strong>
            This verdict predates the current policy; its recorded blocking rule IDs are not currently blockable.</p>"""
        rule_ids = record["rule_ids"]
        rendered_rules = (
            " ".join(f"<code>{html.escape(rule_id)}</code>" for rule_id in rule_ids)
            if rule_ids
            else '<span class="none-recorded">None recorded</span>'
        )
        audited_at = html.escape(record["audited_at"] or "Not recorded")
        current_hash = html.escape(record["current_artifact_sha256"] or "Not verified")
        stored_hash = html.escape(record["stored_artifact_sha256"] or "Not recorded")
        cards.append(
            f"""        <article class="verdict {classification_class}">
            <div class="classification">Effective classification: {classification}</div>{policy_disagreement}
            <dl>
                <dt>Repository</dt>
                <dd>{html.escape(record["repository"])}</dd>
                <dt>Release</dt>
                <dd>{html.escape(record["release"])}</dd>
                <dt>Tag / asset</dt>
                <dd>{html.escape(record["tag"])} / {html.escape(str(record["asset_id"]))}</dd>
                <dt>Identity</dt>
                <dd>{html.escape(record["identity_status"])} — {html.escape(record["outcome"])}</dd>
                <dt>Current hash</dt>
                <dd>{current_hash}</dd>
                <dt>Stored hash</dt>
                <dd>{stored_hash}</dd>
                <dt>Rule IDs</dt>
                <dd class="rules">{rendered_rules}</dd>
                <dt>Audited</dt>
                <dd>{audited_at}</dd>
            </dl>
        </article>"""
        )

    verdict_markup = "\n".join(cards)
    if not verdict_markup:
        verdict_markup = (
            '        <p class="empty">No releases have been audited yet.</p>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plugin Audit Log — Decky Extended Plugins</title>
    <style>
        :root {{ color-scheme: dark; }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: #0d0d0d;
            color: #f7f7f7;
            font-family: system-ui, sans-serif;
            line-height: 1.5;
        }}
        main {{ width: min(100% - 2rem, 960px); margin: 0 auto; padding: 3rem 0; }}
        h1 {{ color: #00ffff; margin-bottom: 0.5rem; }}
        h2 {{ color: #ffff00; margin-top: 2.5rem; }}
        a {{ color: #00ffff; }}
        .intro, .enforcement {{
            padding: 1rem 1.25rem;
            background: #191919;
            border-left: 4px solid #00ffff;
            border-radius: 0.35rem;
        }}
        .enforcement {{ border-color: #ffff00; }}
        .tier-explanation {{ display: grid; gap: 0.75rem; }}
        .tier-explanation p {{ margin: 0; }}
        .verdict {{
            margin: 1rem 0;
            padding: 1.25rem;
            background: #191919;
            border: 2px solid #555;
            border-radius: 0.5rem;
        }}
        .verdict.block {{
            border: 4px solid #ff4d6d;
            box-shadow: 0 0 18px rgba(255, 77, 109, 0.45);
        }}
        .classification {{
            display: inline-block;
            margin-bottom: 0.75rem;
            padding: 0.25rem 0.55rem;
            background: #333;
            color: #fff;
            font-weight: 800;
            letter-spacing: 0.04em;
        }}
        .block .classification {{ background: #ff4d6d; color: #090909; }}
        .policy-disagreement {{
            margin: 0 0 1rem;
            padding: 0.75rem;
            background: #302a16;
            border-left: 4px solid #ffff00;
        }}
        dl {{ display: grid; grid-template-columns: 8rem 1fr; gap: 0.4rem 1rem; margin: 0; }}
        dt {{ font-weight: 700; color: #c9c9c9; }}
        dd {{ margin: 0; overflow-wrap: anywhere; }}
        code {{
            display: inline-block;
            margin: 0 0.3rem 0.3rem 0;
            padding: 0.15rem 0.35rem;
            background: #303030;
            color: #ffff00;
            border-radius: 0.2rem;
        }}
        .none-recorded, .empty {{ color: #bdbdbd; }}
        .empty {{ padding: 2rem; text-align: center; border: 2px dashed #555; }}
        @media (max-width: 600px) {{
            dl {{ grid-template-columns: 1fr; }}
            dt {{ margin-top: 0.45rem; }}
        }}
    </style>
</head>
<body>
    <main>
        <p><a href="index.html">&larr; Decky Extended Plugins</a></p>
        <h1>Plugin Audit Log</h1>
        <p class="intro">This page publishes each release's effective classification under the current policy and keeps any older stored verdict visible when the two disagree. It lists rule IDs only; private evidence and file contents are never published.</p>

        <h2>What the tiers mean</h2>
        <section class="tier-explanation" aria-label="Audit tier explanations">
            <p><strong>BLOCK</strong> means a deterministic structural fact such as a malware signature, archive traversal, a setuid bit, or a zip bomb, with no innocent explanation. It is the only tier that can remove a release.</p>
            <p><strong>MANUAL_REVIEW</strong> means a human should look; it does not mean the plugin is dangerous. Most Decky plugins trip these rules because SteamOS has a read-only root and useful plugins often need sudo, mount, or systemctl.</p>
            <p><strong>Passing does not prove a plugin is safe.</strong> An automated audit can miss harmful behavior.</p>
        </section>

        <h2>Current policy</h2>
        <p class="enforcement">{_audit_enforcement_copy(enforcement_mode)}</p>

        <h2>Audited releases</h2>
{verdict_markup}
    </main>
</body>
</html>
"""


def write_audit_outputs(
    verdicts,
    enforcement_mode,
    destination="public",
    *,
    blockable_rules=None,
    current_identity_records=None,
):
    """Publish human- and machine-readable audit records without evidence."""
    os.makedirs(destination, exist_ok=True)
    records = _public_audit_records(verdicts, blockable_rules, current_identity_records)
    payload = {
        "enforcement_mode": str(enforcement_mode),
        "releases": records,
    }

    with open(os.path.join(destination, "audit.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    with open(os.path.join(destination, "audit.html"), "w", encoding="utf-8") as f:
        f.write(_render_audit_html(records, enforcement_mode))

    print(f"Published audit log with {len(records)} release(s).")


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
    official_catalog_names = _catalog_name_keys(plugins) | _catalog_name_keys(
        testing_plugins
    )

    # Maintain independent ID spaces
    max_stable_id = max([p.get("id", 0) for p in plugins]) if plugins else 0
    max_testing_id = (
        max([p.get("id", 0) for p in testing_plugins]) if testing_plugins else 0
    )

    repo_urls = read_repo_urls()
    verdicts = load_verdicts()
    # Versions the official store already publishes. This catalog defers to the
    # store's own artifact for each one, and the audit skips them for the same
    # reason, so both read this single committed file.
    store_versions = load_store_versions()

    # The catalog gate honours security-policy.yml's current enforcement mode.
    # Under report-only a CURRENT BLOCK is reported and still ships; under the
    # checked-in enforce mode only a CURRENT effective BLOCK is excluded.
    try:
        policy = load_policy()
        enforcement_mode = (policy.get("enforcement") or {}).get(
            "mode"
        ) or "report-only"
        blockable_rules = set(policy.get("blockable_rules") or [])
    except Exception as exc:
        print(f"Fatal: could not load catalog security policy: {exc}")
        raise SystemExit(1) from exc
    gating_enforced = enforcement_mode == "enforce"
    print(
        f"Catalog gate: enforcement mode is {enforcement_mode!r}"
        f" ({'excluding' if gating_enforced else 'reporting'} BLOCK verdicts)."
    )

    errors = []
    custom_plugin_names = set()
    current_identity_records = []
    storefront_contributions = []

    for url in repo_urls:
        try:
            print(f"Processing {url}...")
            url = canonicalize_github_repository_url(url)
            owner, repo = parse_github_repository_url(url)

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

            deferred_versions = store_versions.get(url, set())

            for rel in releases:
                # The official store publishes and ships its own artifact for
                # this version, so republishing our build would replace bytes the
                # store already vets. Skip before build_version_object(), which
                # would otherwise download the asset to hash a version this
                # catalog never offers.
                if normalize_version(rel.get("tag_name", "1.0.0")) in deferred_versions:
                    continue
                v_obj = build_version_object(
                    rel, existing_testing or existing_stable, policy=policy
                )
                if not v_obj:
                    continue
                valid_release_count += 1

                verdict = classification_for(
                    url,
                    rel,
                    verdicts,
                    blockable_rules,
                    current_artifact_sha256=v_obj["hash"],
                )
                zip_asset = get_zip_asset(rel) or {}
                current_identity_records.append(
                    {
                        "repository": url,
                        "release": f"{rel.get('tag_name', '')}@{zip_asset.get('id', '')}",
                        "tag": rel.get("tag_name", ""),
                        "asset_id": zip_asset.get("id", ""),
                        "classification": verdict.effective_classification,
                        "stored_classification": verdict.audit_classification,
                        "identity_status": verdict.identity_status,
                        "current_artifact_sha256": verdict.current_artifact_sha256,
                        "stored_artifact_sha256": verdict.stored_artifact_sha256,
                        "fail_open": verdict.fail_open,
                    }
                )
                if verdict.identity_status != "CURRENT":
                    print(
                        f"  [fail-open:{verdict.identity_status}] {plugin_name} "
                        f"release {rel.get('tag_name', '')}: current hash "
                        f"{verdict.current_artifact_sha256 or 'unavailable'}, stored hash "
                        f"{verdict.stored_artifact_sha256 or 'none'}."
                    )
                if (
                    verdict.identity_status == "CURRENT"
                    and verdict.audit_classification == "BLOCK"
                    and verdict.effective_classification != "BLOCK"
                ):
                    _log_policy_demotion(
                        plugin_name,
                        rel.get("tag_name", ""),
                        verdict.blocking_rule_ids,
                    )
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

                repository_slug = _repository_slug(url)
                if repository_slug:
                    storefront_contributions.append(
                        {
                            "name": plugin_name,
                            "version": {
                                "name": v_obj["name"],
                                "hash": v_obj["hash"],
                                "tag": normalize_version(rel.get("tag_name", "")),
                                "repository": repository_slug,
                                "source_url": f"https://github.com/{repository_slug}",
                            },
                        }
                    )

                # Testing includes stable + prereleases
                testing_versions.append(v_obj.copy())
                # Stable only includes non-prereleases
                if not rel.get("prerelease"):
                    stable_versions.append(v_obj.copy())

            remove_blocked_versions(existing_stable, blocked_identities)
            remove_blocked_versions(existing_testing, blocked_identities)

            if valid_release_count and blocked_release_count == valid_release_count:
                print(
                    f"  Warning: All valid releases for {plugin_name} are blocked. "
                    "Contributing no versions."
                )
                for channel, catalog, entry in (
                    ("stable", plugins, existing_stable),
                    ("testing", testing_plugins, existing_testing),
                ):
                    if drop_emptied_entry(catalog, entry):
                        print(
                            f"    Removed {plugin_name} from {channel}: gating left "
                            "the entry with no versions."
                        )
                    elif entry is not None:
                        print(
                            f"    Kept the official {channel} entry for {plugin_name}: "
                            "its remaining versions carry no BLOCK verdict."
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
                official_testing_version = official_latest_version(existing_testing)
                merge_plugin_versions(existing_testing, testing_versions)
                annotate_official_version(existing_testing, official_testing_version)
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
                    official_stable_version = official_latest_version(existing_stable)
                    merge_plugin_versions(existing_stable, stable_versions)
                    annotate_official_version(existing_stable, official_stable_version)
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

        except ArtifactDownloadError as exc:
            print(f"Fatal artifact identity failure: {exc}")
            raise SystemExit(1) from exc
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

    storefront_metadata = build_storefront_metadata(
        plugins,
        testing_plugins,
        official_catalog_names,
        storefront_contributions,
        enforcement_mode,
    )
    write_storefront_metadata("public/storefront.json", storefront_metadata)

    # Write Cloudflare Pages _headers file for Decky Loader CORS preflight
    with open("public/_headers", "w") as f:
        f.write(
            "/*\n  Access-Control-Allow-Origin: *\n  Access-Control-Allow-Methods: GET, OPTIONS\n  Access-Control-Allow-Headers: X-Decky-Version\n"
        )

    copy_static_files()
    write_audit_outputs(
        verdicts,
        enforcement_mode,
        blockable_rules=blockable_rules,
        current_identity_records=current_identity_records,
    )

    print("Successfully generated JSON files in the 'public' directory.")


if __name__ == "__main__":
    main()
