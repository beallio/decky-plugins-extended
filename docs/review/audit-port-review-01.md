# Review — audit-port (round 01)

Branch: `feat/audit-port`
Reviewed against: `docs/plans/2026-08-03_audit-port.md`
Reviewed commit: `ac0c0bb`

## Verdict

The port is in good shape and the two structural fixes the plan asked for are genuinely done,
not merely claimed. Verified by me on the branch:

- **Cache-before-download ordering is correct.** `load_cached_report_predownload()` runs at
  `audit_plugins.py:2969` and returns at 2977, before `download_zip()` at 2987. The fork
  downloaded first.
- **Workflow cache key is fixed.** `scheduled-security-audit.yml:58` now hashes
  `security-allowlist.yml`. I ran it both ways: appending a line to the allowlist moves the
  fixed command's hash `6efca805eb38578e -> 30f7705ad7eb54f2`, while the fork's command stays
  `be4a01379547500a`. The defect reproduced red and the fix green.
- **`uv.lock` kept `[options]`** (`exclude-newer`, `exclude-newer-span`, `pyludusavi`) and
  gained `pyyaml`. This is what the fork got wrong.
- **Still advisory.** `security-policy.yml:12` is `mode: report-only`, and
  `generate_json.py`/`check_for_updates.py` are untouched. No gating leaked in early. Correct.
- `test_auditor_executes_nothing` is a real negative control: malicious `setup.py` plus a
  `postinstall` hook, asserting the sentinel is never created.

For the record, a multi-minute stall I hit early on was `uv` syncing the newly added PyYAML
over the network, not the test suite. Warm, the suite is ~1.4s. No action needed.

## Gate status

`scripts/orchestration/run-quality-gates` -> pass: ruff clean, 183 passed / 17 subtests in
1.38s. Run by me on `ac0c0bb`, not taken from a session log.

## Required changes

### 1. A failed tag resolution silently disables the tag-moved cache protection

`audit_plugins.py:2929-2932`:

```python
commit_sha, _tree_sha, _tag_err = _resolve_ref_to_commit_and_tree_sha(owner, repo, tag_name)
resolved_tag_commit_sha = commit_sha or ""
```

`_resolve_ref_to_commit_and_tree_sha()` returns `None` on any failure — network error, rate
limit, deleted tag — and `_tag_err` is discarded. The empty string then flows into both the key
and the validation, where `load_cached_report()` guards every check on truthiness
(`audit_plugins.py:2468-2478`):

```python
if (audit_context_hash and data.get("audit_context_hash") != audit_context_hash) or ...
```

So when resolution fails, every such audit collapses onto one shared `""` key slot **and** the
commit-sha mismatch check is skipped entirely. The exact protection this sub-plan added — a
moved tag must force a re-audit — degrades to nothing precisely when GitHub is flaky, and it
does so silently.

Fix: on resolution failure, either refuse to read or write the cache for that release, or
record `AUDIT_ERROR`. Do not cache under an empty commit sha. Add a test that fails today:
force `_resolve_ref_to_commit_and_tree_sha` to return `(None, None, "boom")`, audit two
*different* tags, and assert the second is not served from the first's cache entry.

### 2. Make the cache-key parameters required

`_cache_key()` (2349), `load_cached_report()` (2446) and `save_cached_report()` (2494) all
default `audit_context_hash` and `resolved_tag_commit_sha` to `""`. That default is what makes
finding 1 silent, and it lets any future caller regress to fork behaviour by forgetting an
argument. Make both parameters required (no default). The production caller at 2997 already
passes them, so this is a signature change with no behavioural cost — it just removes the
footgun.

### 3. Record the verification evidence

There is no session log for this sub-plan; `docs/agent_conversations/` contains only
`2026-08-03_release-utils.json`. Plan verification steps 1 and 3 asked for recorded evidence,
including the red-first result for the workflow cache key. I reproduced both myself and the
numbers are in the Verdict above, but the audit trail belongs in the branch, not in my review
note. Add the session log with the actual observed output for steps 1-6.

## Non-blocking

`tests/test_audit_plugins.py` never patches `_resolve_ref_to_commit_and_tree_sha` — 0
occurrences, against 4 in `tests/test_audit_cache_invalidation.py` — yet
`TestAuditRepositoryMocked` documents itself as "all network calls mocked". It happens not to
reach the resolver today, which is why the suite is fast. That is luck, not design: a change to
the call path would silently turn those 153 tests into live `api.github.com` callers. Patch it
in that class's setup so the docstring's claim is enforced.

STATUS: CHANGES_REQUESTED
