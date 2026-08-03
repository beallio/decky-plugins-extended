# Review — audit-scanners (round 01)

Branch: `feat/audit-scanners`
Reviewed against: `docs/plans/2026-08-03_audit-scanners.md`
Reviewed commit: `884b5cc`

## Verdict

Both scanner defects are genuinely fixed, and the redaction approach is better than what the
plan asked for. Verified on the branch:

- **Redaction is centralised**, not sprinkled. `Finding.__post_init__`
  (`audit_plugins.py:153-155`) routes every `evidence` value through `redact_secrets()`, so all
  31 construction sites are covered and the fix cannot be forgotten at a new call site. The plan
  asked for application "wherever `Finding.evidence` is constructed"; this is the stronger form.
- **`_shannon_entropy` is gone** — 0 occurrences, pinned by `test_shannon_entropy_removed`,
  which asserts the attribute does not exist. That closes the dead-detector item properly rather
  than leaving decoration behind.
- **Content comparison is real.** `git_blob_sha1()` (`audit_plugins.py:134-137`) computes Git's
  blob SHA-1, compared against the tag's tree at 2327-2333. I mutation-tested it: forcing
  `if zip_sha != source_sha:` to `if False:` turns `test_modified_same_path_file_detected` red,
  and restoring it green.
- **The CRLF fallback is a good call.** 2331-2333 retries the comparison against
  `raw.replace(b"\r\n", b"\n")` before flagging, avoiding a false positive on every plugin built
  on Windows. The plan did not ask for it.
- **False-positive control works.** `test_normal_plugin_compiled_assets_no_false_positives`
  covers a `dist/` bundle, a sourcemap and a PNG present in the ZIP but absent from source. It
  goes red when blob hashing is neutered, so it is load-bearing.

## Gate status

`scripts/orchestration/run-quality-gates` -> pass: ruff clean, 188 passed / 17 subtests. Run by
me on `884b5cc`.

## Required changes

### 1. Redaction is proven in memory, not on the three report surfaces

The plan's verification step 1 asked for the token to be absent from `security-report.json`,
`security-report.md`, **and** `$GITHUB_STEP_SUMMARY`, with a non-empty precondition on each.
What exists is `test_static_rules_redact_secrets_in_evidence`
(`tests/test_audit_plugins.py:420-427`), which only inspects `f.evidence` on in-memory
`Finding` objects.

That is the weaker claim. The defect being fixed is *secrets reaching report surfaces*; an
in-memory assertion does not prove the rendered outputs are clean. The Markdown renderer or the
job-summary builder could read a different field, re-read the raw source line, or embed
`message` rather than `evidence`, and this test would stay green.

`GITHUB_STEP_SUMMARY` has no coverage at all — the only report-file test
(`tests/test_audit_plugins.py:2431-2439`) asserts the empty-report case and never touches
redaction.

Add an end-to-end test: audit a fixture whose source carries the token on a rule-tripping line,
write all three outputs, assert each exists and is non-empty, then assert the literal token
appears in none of them.

### 2. The centralised redaction is not independently pinned

Disabling `Finding.__post_init__`'s redaction alone breaks **nothing** — I ran it, 157 tests
still pass. The existing test survives because the static-rule path at `audit_plugins.py:1518`
redacts a second time before constructing the `Finding`. Only when I disabled *both* paths did
the test go red.

The `__post_init__` hook is the safety net for the other 30 evidence sites. As things stand,
someone can delete it and no test notices. Add a direct test: construct a `Finding` with a raw
token in `evidence` and assert it comes back redacted. Three lines, and it pins the mechanism
the whole fix rests on.

### 3. Session log missing again

`docs/agent_conversations/` holds `2026-08-03_release-utils.json` and
`2026-08-03_audit-port.json` but nothing for this sub-plan. Second round running where the
evidence had to be reconstructed in review instead of read from the branch. Record the actual
observed output for verification steps 1-5, including mutation results.

## Non-blocking

Pre-existing from the fork port, not introduced here, but this sub-plan is the natural place to
clean it up: `tests/test_audit_plugins.py:2448` reads

```python
"""The Authorization header must use '******', not a redacted placeholder."""
```

and the assertion message at 2457 says `f"Expected '******', got {auth!r}"`. A redaction pass
somewhere in the fork's history ate the literal `Bearer <token>` out of both strings, leaving a
docstring that now states the opposite of what the test checks. Restore the intended wording.

STATUS: CHANGES_REQUESTED
