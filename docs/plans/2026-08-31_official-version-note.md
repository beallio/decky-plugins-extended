# Plan: Annotate merged catalog entries with the official store version (official-version-note)

## Context

Decky Loader's store card renders the plugin name, author, description, and each
`versions[].name` in its version dropdown
(`frontend/src/components/store/PluginCard.tsx:94-122, 201-217` in
`SteamDeckHomebrew/decky-loader` at commit `b4b8be3`). `StorePluginVersion` has
exactly the three fields `name`, `hash`, and `artifact`
(`frontend/src/store.tsx:23-27`). `tags` participate in the store search filter
and identify root plugins (`frontend/src/components/store/Store.tsx:238` and
`frontend/src/components/store/PluginCard.tsx:37`).

This catalog merges newer GitHub releases into the official store's own entries
(`generate_json.py:786-801` finds the upstream entry by lowercased name;
`generate_json.py:918-944` merges into it). A merged entry therefore often lists
a version the official store does not carry yet, and a user cannot tell which
row the official store stopped at.

Annotating `versions[].name` was evaluated and rejected. `installedVersionIndex`
(`PluginCard.tsx:25`) matches `versions[].name` against the installed plugin's
own `package.json` version, so any suffix makes that lookup return `-1`. The
`installType` ladder at `PluginCard.tsx:26-35` then resolves to `DOWNGRADE` for
every row, so the install button would read "Downgrade" instead of "Update". A
one-off survey during scoping compared each store plugin's newest catalog
version against `package.json.version` at the matching release tag and found the
lookup intact for the clear majority of them, so the regression would be newly
introduced rather than pre-existing. That survey is scoping evidence, not a
committed artifact, and the implementer does not need to reproduce it.
Changing the loader is not an option: users run the official loader binary.

`description` is the catalog field that can safely carry this note. It is
rendered at `PluginCard.tsx:116-122`; among the catalog-field reads in the store
UI, it is otherwise used only by the store search filter (`Store.tsx:236`).
Therefore a prefix there does not affect install-state lookup, version sorting,
or the install counter.

Intended outcome: when a configured repository merges a version newer than the
official store's newest into an existing upstream entry, prefix that entry's
`description` with a short note naming both versions. `versions[]` must stay
byte-identical to what the current generator produces.

Files in scope:

- `generate_json.py` — two new module-level helpers plus two call sites in `main`.
- `tests/test_generate_json.py` — unit coverage and `main()` coverage.

Explicitly out of scope: the contents of `additional_plugins.txt`, the
store-repository discovery work, `check_for_updates.py`, and the
all-releases-blocked removal path at `generate_json.py:885-893`.

**Slug used throughout this plan:** `official-version-note`

---

## Orchestration Contract

**Slug:** `official-version-note`

**Plan file:**

```text
docs/plans/2026-08-31_official-version-note.md
```

**Implementation branch:**

```text
feat/official-version-note
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/official-version-note_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/official-version-note_finalized
```

**Review notes:**

```text
docs/review/official-version-note-review-*.md
```

Each review note ends with exactly one status trailer:

```text
STATUS: CHANGES_REQUESTED
```

or:

```text
STATUS: APPROVED
```

---

## Required Agent Protocol

1. Use the **implementer** skill.
2. Work from the repository root.
3. Branch from `dev`.
4. Commit this plan as the first commit on the implementation branch.
5. Follow TDD where behavior changes are testable.
6. Run quality gates before marking any round complete.
7. Do not write your own review.
8. Do not create files under `docs/review/`.
9. Do not delete files under `docs/review/`.
10. Review notes are durable audit records and must be committed.
11. Resolving a review note means:
    - implement the requested changes;
    - run quality gates;
    - commit the code/docs changes;
    - commit the review note itself if it is not already committed;
    - recreate the round-complete marker.
12. After finalization, stop polling and exit cleanly.

---

## Scope discipline

- Implement only the units the plan lists. Do not modify files outside the plan's scope.
- Do not change runtime behavior beyond what the plan specifies. A `refactor` or
  `cleanup` commit must preserve observable behavior.
- Never edit a test's expected value to make a behavior change pass. If a test
  legitimately must change, that change must be required by the plan or a review
  note, and you must record the rationale in the session log.
- If you spot an unrelated improvement, do not make it here — note it in the
  session log for a separate plan.

---

## Setup

Start from `dev`:

```bash
git checkout dev
git pull --ff-only origin dev
git checkout -b feat/official-version-note
```

Commit this plan first:

```bash
git add docs/plans/2026-08-31_official-version-note.md
git commit -m "docs(plan): add official-version-note implementation plan"
```

---

## Implementation Tasks

Work in order. Tasks 1 and 2 are pure functions and must be written test-first.

### Task 1 — `official_latest_version`

Add a module-level helper to `generate_json.py`, placed immediately after
`sort_versions` (currently ends at line 283) and before
`merge_plugin_versions`:

```python
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
```

Return `None` for a missing entry, an entry with no `versions`, and an entry
whose leading version has no `name`. Because both sides of the note now derive
from `plugin_release_utils.version_sort_key`, the note can only appear when this
catalog genuinely contributed the leading version.

### Task 2 — `annotate_official_version`

Add directly after `official_latest_version`:

```python
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
    note = (
        f"{OFFICIAL_VERSION_NOTE_PREFIX}{official_version}; "
        f"this store has {newest}."
    )
    if description == note or description.startswith(f"{note} "):
        return False
    entry["description"] = f"{note} {description}".strip()
    return True
```

Behaviour requirements:

- returns `False` and leaves `entry` untouched when `official_version` is falsy,
  when `versions` is empty, or when `versions[0]["name"]` equals
  `official_version`;
- is idempotent: a second call on an already-annotated entry returns `False` and
  does not prefix twice;
- never writes any key under `entry["versions"]`.

`versions[0]` is correct as the post-merge newest because `merge_plugin_versions`
ends with `sort_versions` (`generate_json.py:308`), and `README.md:104-107`
contracts `versions[0]` as latest.

### Task 3 — wire the two merge call sites in `main`

In `generate_json.main`, capture the official version **before** each
`merge_plugin_versions` call and annotate after it. Do not move
`remove_blocked_versions` (`generate_json.py:882-883`); it already runs earlier,
so a gated official release is correctly excluded from the captured value.

Testing channel, currently lines 918-920:

```python
            if existing_testing:
                print("  Found in testing plugins. Merging versions...")
                official_testing_version = official_latest_version(existing_testing)
                merge_plugin_versions(existing_testing, testing_versions)
                annotate_official_version(existing_testing, official_testing_version)
```

Stable channel, currently lines 942-944:

```python
                if existing_stable:
                    print("  Found in stable plugins. Merging versions...")
                    official_stable_version = official_latest_version(existing_stable)
                    merge_plugin_versions(existing_stable, stable_versions)
                    annotate_official_version(existing_stable, official_stable_version)
```

Do not touch the `else` branches that build `new_testing` / `new_stable`: those
are entries this generator creates, which have no official counterpart and must
keep the description produced by `resolve_description`.

### Task 4 — tests in `tests/test_generate_json.py`

Add to the existing `GenerateJsonTests` class, matching its `unittest` /
`unittest.mock.patch` style. Name them exactly as listed so the verification
steps below can reference them:

1. `test_official_latest_version_uses_semver_order_not_position` — an entry
   whose `versions[0]` is a lower semver than a later element, with `created`
   timestamps that disagree with semver order; assert the semver-leading
   element's name is returned, and assert the entry's own `versions` list order
   is unchanged after the call.
2. `test_official_latest_version_handles_empty_and_missing_entries` — `None` for
   `None`, `{}`, and `{"versions": []}`.
3. `test_annotate_official_version_prefixes_description_when_newer_exists` —
   assert the resulting description equals
   `"Official store has 1.0.0; this store has 2.0.0. Original copy"` and that
   the original text is still present.
4. `test_annotate_official_version_skips_when_official_is_newest` — returns
   `False` and the description is unchanged.
5. `test_annotate_official_version_is_idempotent` — start with the ordinary
   description `"Official store has useful plugins."`; call twice; assert the
   first call returns `True`, the second returns `False`, the generated note
   `"Official store has 1.0.0; this store has 2.0.0."` appears exactly once,
   and the original description is preserved.
6. `test_annotate_official_version_leaves_version_names_untouched` — snapshot
   `copy.deepcopy(entry["versions"])` before the call and assert equality after.
   This is the guard against regressing to a `versions[].name` label.
7. Extend the existing `main()` integration test pattern (see
   `test_main_separates_stable_and_testing_releases_and_ids`, line 437) with
   `test_main_annotates_merged_entries_with_the_official_version`: a base stable
   catalog entry at version `1.0.0` plus a configured repo releasing `2.0.0`;
   assert the written stable entry's description starts with
   `"Official store has 1.0.0; this store has 2.0.0."`, and assert that an
   upstream entry with no configured repository has an unchanged description.

---

## Quality Gates

Run before marking any round complete:

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git status --short
```

The round is not complete unless:

1. all requested implementation work is done;
2. all relevant tests pass;
3. build/typecheck gates pass;
4. review notes have not been deleted;
5. the working tree is clean;
6. all code/docs changes are committed.

---

## Verification

Verification standards for this repository are defined in the orchestration
skill's `references/verification-standards.md`; do not restate them here. Record
actual command output and pass/fail tallies, not conclusions.

### V1 — unit and integration coverage

```bash
set -o pipefail
uv run pytest tests/test_generate_json.py -v
```

Record the pass/fail/error tallies verbatim. All seven tests from Task 4 must
appear in the output by name. Failure looks like a non-zero exit code, or any of
the seven names missing from the verbose listing.

### V2 — idempotence under repeated annotation

```bash
set -o pipefail
uv run pytest tests/test_generate_json.py -k idempotent -v
```

Failure looks like a `0 selected` / `no tests ran` summary, or a description
containing `Official store has ` twice.

### V3 — mutation test: prove the gate before trusting it

Break the implementation and confirm the new tests detect it. Edit
`generate_json.annotate_official_version` so its first statement is
`return False`, then:

```bash
set -o pipefail
if uv run pytest tests/test_generate_json.py -v; then
  echo "MUTATION NOT DETECTED: the suite passed against a no-op annotator"
  exit 1
else
  status=$?
fi
echo "mutation detected, pytest exit status $status"
```

Record which test names failed. At minimum tests 3, 5, and 7 must fail. If
the suite passes, the tests are decoration and must be rewritten before
continuing.

Then revert the mutation (`git checkout -- generate_json.py` is wrong here
because it would discard the feature; restore the deleted line by hand or with
`git diff` review) and re-run V1. Record that the suite is green again.

### V4 — live end-to-end run against the real catalogs

V3 is the mutation control. V4 is the step the verification standards require to
pass only when the implementation works, and it must run after V3. It exercises
the real generator against the live catalogs rather than mocks, so treat V1 and
V2 as the deterministic gate and V4 as corroborating evidence.

```bash
set -o pipefail
repo=$(pwd)
workdir=$(mktemp -d)
cp security-policy.yml security-allowlist.yml security-verdicts.json "$workdir"/
cp -r static "$workdir"/static
printf '%s\n' 'https://github.com/moi952/decky-proton-launch' > "$workdir"/additional_plugins.txt
token=$(gh auth token)
( cd "$workdir" && PYTHONPATH="$repo" GITHUB_TOKEN="$token" python "$repo"/generate_json.py )
```

`moi952/decky-proton-launch` is the `Decky Proton Launch` store entry: on
2026-08-31 the official store carried `0.9.0` and the repository had released
`0.15.0`, so this run must produce an annotation. This pins a live third-party
repository, so the gap can close before the implementer runs the step. If the
official store has caught up, or that repository stops publishing an eligible
single-zip release, substitute any other store plugin whose source repository is
ahead, record which plugin and which versions you used, and change the plugin
name in the assertions below and in V5 to match. Do not weaken the assertions to
make a closed gap pass. Then assert on the output:

```bash
set -o pipefail
desc=$(python - "$workdir/public/plugins.json" <<'PY'
import json, sys
catalog = json.load(open(sys.argv[1]))
entry = next(p for p in catalog if p["name"] == "Decky Proton Launch")
names = [v["name"] for v in entry["versions"]]
assert not any("Official store" in n for n in names), f"version names polluted: {names}"
assert not any("+" in n for n in names), f"version names carry build metadata: {names}"
print(entry["description"])
PY
)
printf 'description: %s\n' "$desc"
case "$desc" in
  "Official store has "*"; this store has "*) echo "annotation present" ;;
  *) echo "FAIL: description is not annotated"; exit 1 ;;
esac
```

The standalone `desc=$(...)` assignment propagates the Python exit status, so a
polluted `versions[].name` fails the step. Failure looks like `FAIL:` output, a
non-zero exit, or an `AssertionError` naming the polluted version list. Record
the printed description verbatim.

Keep `$workdir` until V5 completes.

### V5 — unchanged entries stay unchanged

Using the same `$workdir/public/plugins.json` from V4, confirm a plugin with no
configured repository was not annotated:

```bash
set -o pipefail
python - "$workdir/public/plugins.json" <<'PY'
import json, sys
catalog = json.load(open(sys.argv[1]))
annotated = [p["name"] for p in catalog if p["description"].startswith("Official store has ")]
print("annotated entries:", annotated)
assert annotated == ["Decky Proton Launch"], f"unexpected annotations: {annotated}"
PY
```

Failure looks like any list other than `["Decky Proton Launch"]`. An empty list
means the target was not annotated; an extra name means the annotation leaked
into an entry the generator did not merge into.

After V5, clean up with `rm -rf "$workdir"` and record that
`git status --short` in the repository is unchanged by V4 and V5.

### Deferred and unverified

State these in the session log; they are not resolved by this plan.

1. **No on-device visual confirmation.** The description is rendered by Decky
   Loader at `PluginCard.tsx:116-117` at 13px with `-webkit-line-clamp: 3` (2
   when the entry carries a `root` tag). The note is a prefix so it should
   survive the clamp, but the truncation point was not measured on a real
   device or in a real loader session. Nothing in this repository can verify it.
2. **Note staleness is not addressed.** `check_for_updates.py` decides whether to
   fire the Cloudflare deploy hook by comparing versions, not descriptions. If
   the official store catches up to a version this catalog already listed, and
   the source repository publishes no new release, the stale note can persist
   until some other change triggers a rebuild. Fixing that would mean teaching
   the refresh checker about descriptions, which is out of scope here.
3. **Non-semver upstream version names.** `sort_versions` ranks unparseable
   version names last (`plugin_release_utils.version_sort_key`), so for an
   upstream entry whose newest release is non-semver, `versions[0]` after merge
   may not be the intended newest and the note may be skipped. Not exercised by
   the tests above.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished official-version-note
```

This writes:

```text
/tmp/decky-plugins-extended/official-version-note_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer official-version-note`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/official-version-note-review-*.md
```

When a review note exists or a new review note appears:

1. Read the full review note.
2. If the note ends with:

   ```text
   STATUS: CHANGES_REQUESTED
   ```

   then resume work.

3. Clear the round-complete marker:

   ```bash
   scripts/orchestration/clear-finished official-version-note
   ```

4. Address every requested change.
5. Run quality gates:

   ```bash
   scripts/orchestration/run-quality-gates
   scripts/orchestration/check-review-notes-not-deleted
   ```

6. Commit code/docs fixes.
7. Commit the review-note file itself if it is not already committed:

   ```bash
   git add docs/review/official-version-note-review-*.md
   git commit -m "docs(review): record official-version-note review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished official-version-note
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer official-version-note` after the next review note is created.

---

## Approval Handling

If the latest review note ends with:

```text
STATUS: APPROVED
```

then:

1. Confirm every previous review item has been addressed.
2. Confirm all review notes are committed:

   ```bash
   scripts/orchestration/check-review-notes-committed official-version-note
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize official-version-note
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/official-version-note_finalized
   ```

6. Stop polling and exit cleanly.

---

## Review Rules

Do not write your own review.

Do not create files under:

```text
docs/review/
```

Do not delete files under:

```text
docs/review/
```

Only the orchestrator writes review notes. Your job is to read them, resolve them, commit them as audit records, and continue the loop.

---

## Finalization Rules

Only finalize after a review note with:

```text
STATUS: APPROVED
```

Finalization is performed with:

```bash
scripts/orchestration/finalize official-version-note
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/official-version-note_finished
/tmp/decky-plugins-extended/official-version-note_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
