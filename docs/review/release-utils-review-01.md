# Review — release-utils (round 01)

Branch: `feat/release-utils`
Reviewed against: `docs/plans/2026-08-03_release-utils.md`
Reviewed commits: `47fcf22`, `3d3c344`

## Verdict

The extraction is clean and the core fix is correct. I traced
`select_best_release(..., allow_prerelease=True)` by hand: eligible releases now rank purely
on `version_sort_key`, so `2.0.0-beta.1` → `(1,2,0,0,0,...)` outranks `1.0.0` →
`(1,1,0,0,1,...)` on the major component. That is exactly what the fork got wrong, and
`test_select_best_release_testing_prefers_higher_prerelease` pins it. The stable path still
filters prereleases, pinned by `test_select_best_release_stable_only`. `sort_versions`' new
lambda is behaviourally identical to the old dict-reading `version_sort_key`.

`select_best_release` not being imported by `generate_json.py` is **correct** — the generator
emits every eligible release, not one. Do not "fix" this. The plan's wording about matching the
fork's call sites was wrong on that point; the auditor will be its first consumer.

Blocking on missing verification evidence, plus one behaviour change the missing step was
meant to catch.

## Gate status

`scripts/orchestration/run-quality-gates` → pass: ruff clean, 25 passed / 14 subtests.
Verified by me on the branch, not taken from the session log.

## Required changes

### 1. Verification step 3 was not performed — blocking

The plan required a catalog-output regression negative control: capture
`plugins.json`/`testing_plugins.json` from a fixture run on `dev`, run again on this branch,
diff them, and permit only differences attributable to the `.ZIP` casing rule. The session log
records the final green state only.

This is the step that catches finding 2, which is why it is not optional. Run it and record the
actual diff in the session log.

### 2. Unflagged newly-*ineligible* releases

`has_exactly_one_zip()` is case-insensitive; the code it replaced was case-sensitive:

```python
# before (generate_json.py)
zip_assets = [a for a in release.get("assets", []) if a.get("name", "").endswith(".zip")]
if len(zip_assets) != 1:  # skip
```

A release carrying **both** `plugin.zip` and `Plugin.ZIP` previously matched exactly one asset
and produced a catalog entry. It now matches two and is skipped entirely. That is a release
*disappearing* from the catalog, outside the "only newly eligible" bound the plan set.

Decide and document which behaviour is intended. I think skipping is right — two ZIPs is
genuinely ambiguous, and the old behaviour silently picked whichever was lowercase — but it
must be a recorded decision with a test, not an accident. Add a test asserting the
both-casings release is skipped so the choice is pinned either way.

### 3. Mutation test (verification step 4) was not performed

Revert `select_best_release`'s prerelease ranking to the fork's behaviour (return the highest
*stable* release when one exists) and confirm
`test_select_best_release_testing_prefers_higher_prerelease` goes red. Record the observed
failure output, then restore.

This also discharges verification step 1, which asked for the same red→green evidence against
the fork's unmodified helper. Do one or the other, not both.

### 4. `assert` in a production code path

`generate_json.py`:

```python
zip_asset = get_zip_asset(release)
assert zip_asset is not None
```

`python -O` strips assertions and the next line would then raise `AttributeError` on `None`.
`has_exactly_one_zip()` already guarantees non-`None` here, so the assertion is dead weight.
Delete it, or replace with an explicit `if zip_asset is None: return None`.

## Non-blocking

`generate_json.py` imports `plugin_release_utils` twice, the second solely for
`parse_semver as parse_semver`. Fold it into the first import. If the re-export exists to keep
`generate_json.parse_semver` working for external callers, say so in a comment — the `x as x`
idiom reads as an accident.

STATUS: CHANGES_REQUESTED
