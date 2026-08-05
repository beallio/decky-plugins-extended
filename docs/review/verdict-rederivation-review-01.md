# Review — verdict-rederivation (round 01)

Branch: `feat/verdict-rederivation`
Reviewed against: `docs/plans/2026-08-04_verdict-rederivation.md`
Commits reviewed: `79f5cfa`, `01d971a`

## Verdict

The core of the plan is implemented correctly. Re-derivation is demotion-only, it is applied at
both named trust points, `audit_classification` still reports the stored value, demotions are
logged with rule IDs and no evidence, the audit page shows effective-versus-stored, and
`security-policy.yml` is untouched at `mode: report-only`.

Independently verified, not taken from the session log:

- Quality gates green on the branch: `ruff check` clean, `ruff format --check` 44 files already
  formatted, `pytest` 300 passed / 21 subtests passed. Working tree clean, no deleted review
  notes, `security-policy.yml` line 19 still `mode: report-only`.
- Mutation re-run: replacing `classification_for`'s `effective_classification` with the stored
  value takes `tests/test_verdict_rederivation.py` to 6 failed / 12 passed — the stale-BLOCK,
  empty-rule-ID, committed-store and generator cases go red while every structural
  (`ARCHIVE_TRAVERSAL`) case stays green. The tests do discriminate.

Two changes are required before this can be integrated. The first is a genuine fail-open
regression on the structural path — the exact failure direction this sub-plan exists to prevent
in the opposite direction.

## Gate status

| Gate | Result |
| --- | --- |
| `ruff check` | passed |
| `ruff format --check` | 44 files already formatted |
| `pytest` | 300 passed, 21 subtests passed |
| `check-review-notes-not-deleted` | no deleted review notes |
| `git status --short` | clean |
| `security-policy.yml` | `mode: report-only` |

## Required changes

### 1. `catalog_version_is_blocked` now short-circuits on the first identity match (fail-open)

`generate_json.py:377-394`. The old code scanned every stored entry and returned `True` on *any*
entry whose identity matched and whose classification was `BLOCK`. The new code `continue`s only
on an identity mismatch and then unconditionally `return`s the first match's re-derived answer.

That makes the result depend on dict insertion order, and it can drop a genuinely blockable
verdict. Demonstrated on this branch:

```text
two entries, same (normalized tag, artifact_sha256), one MANUAL_REVIEW and one
BLOCK/ARCHIVE_TRAVERSAL, blockable_rules={ARCHIVE_TRAVERSAL, MALWARE}:

  stale entry first   -> catalog_version_is_blocked == False
  blockable entry first -> catalog_version_is_blocked == True
```

Two entries can share an identity in normal operation: `_release_id` is `tag@asset_id`, so a
re-uploaded asset under the same tag with identical bytes produces a second record with the same
normalized tag and the same `artifact_sha256`. Under this sub-plan's own premise those two
records can also disagree, because one may have been written under an older policy. The
structural-blocking guarantee must not depend on which of them `dict` iteration reaches first.

Required: keep scanning all matching entries. Block if **any** identity-matching entry re-derives
to `BLOCK`. Emit the demotion log only when the final answer is non-blocking, so the log cannot
claim a release was demoted while it is in fact still excluded by a sibling record.

Add a test that seeds both orderings of the two same-identity entries and asserts `True` for
both. The current parametrized cases all use a single entry and cannot catch this.

### 2. Replace the corpus-snapshot assertions with the property they stand for

`tests/test_verdict_rederivation.py:169-172` asserts the store holds exactly 42 releases and
exactly 8 stored `BLOCK`s; `tests/test_verdict_rederivation.py:289` asserts
`output.count("[policy-demotion]") == 8`.

Those literals go red precisely when the thing this sub-plan is waiting for happens. The plan
states the store's stale values "remain on disk until the next audit overwrites them" — after
that audit there are zero stored `BLOCK`s, `stored_blocks` is empty, and
`{result.audit_classification for ...} == {"BLOCK"}` fails against an empty set. A test that
breaks when the corpus is repaired is a maintenance trap, and this repo already set the
precedent against it in `9321cb4` ("assert the rarity property instead of a corpus snapshot").

Required: assert the invariant over whatever the committed store contains — for every stored
`BLOCK`, `effective_classification == "BLOCK"` if and only if `blocking_rule_ids` intersects
`policy["blockable_rules"]`, and `audit_classification` always equals the stored value. Keep the
test meaningful on an empty-BLOCK store rather than skipping it. In the generator test, derive
the expected demotion count from the fixture (`len(...)` over the entries the fixture actually
demotes) instead of the literal `8`.

The 42/8 tallies remain valuable as *evidence* — leave them in the session log, where they are
already recorded, not in an assertion.

## Not required, recorded for the record

- `effective_stored_classification` falls back to `load_policy()` when `blockable_rules is None`,
  so `_public_audit_records` re-reads the policy once per record when called without the
  argument. Both production callers pass the set, so this is test-path only. Leave it.
- `generate_json.main()` never calls `catalog_version_is_blocked`; upstream catalog entries are
  gated in `check_for_updates.py` only. That is pre-existing and out of scope here — Task 2's
  logging on that path correctly surfaces in the update check rather than in catalog generation.
- The `stored_classification` field added to `public/audit.json` has no consumer other than the
  generated page, so the schema addition is safe.

STATUS: CHANGES_REQUESTED
