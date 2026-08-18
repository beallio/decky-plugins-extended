# Review — quota-safe-security-audit (round 04)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on the immutable-worklist foundation. The producer CLI shape, digestless
round-trip, explicit `none` mode, and direct `$GITHUB_OUTPUT` removal are corrected. Independent
mutation testing nevertheless proves that the loader still accepts noncanonical or ineligible
re-fingerprinted documents, and some preparation failures preserve a stale usable target. Keep this
round confined to completing Task 2; do not begin worker or workflow implementation.

## Gate status

- Root reran `scripts/orchestration/run-quality-gates`: actionlint and its three mutation controls
  passed, Ruff check/format passed, and Pytest reported `697 passed, 61 subtests passed in 17.92s`.
- Terra reran the focused worklist/plugin suites: `282 passed, 36 subtests passed`; focused Ruff
  passed.
- Root mutation probes were accepted for `draft=true`, `asset_name=plugin.txt`, a date-only
  timestamp, an arbitrary source-resolution error, an empty selected repository, an ignored
  non-changed `base_ref`, and an omitted `latest_only` field. Terra separately reproduced accepted
  mixed-case repository aliases and preservation of an old worklist after early validation failure.
- The round marker is valid at `13521ede2e2aee8ed7c7aba5de079f95bf06306b`, the tree is clean,
  and `security-verdicts.json` remains unchanged.
- `/tmp/decky-plugins-extended/quota-safe-security-audit-red.log` is still absent. Root's independent
  green transcript is at `/tmp/decky-plugins-extended/root-review-gate.log`; it is not a substitute
  for the requested implementer red evidence.

## Required changes

1. Make failure invalidation cover the entire preparation attempt. Once `output_path` is accepted,
   remove/invalidate any pre-existing target before validating source revision, selection, shard
   count, repositories, deadlines, or injected transports—not only inside the enumeration `try`.
   Add pre-existing-target tests for an invalid source revision, invalid shard count, empty `all`,
   and a later second-repository failure; every case must leave no usable target or temporary file.
2. Make the payload schema exact and non-normalizing. Require every `_PAYLOAD_KEYS` member, including
   explicit `base_commit`/null and `latest_only`; reject missing fields. Require each selected
   repository string to equal its canonical URL rather than accepting mixed-case, trailing-slash,
   or other aliases and returning a different payload. Reject whitespace/uppercase aliases for
   source and resolved commit SHAs instead of stripping or lowercasing them at the validation seam.
3. Persist the resolved base commit, not the symbolic diff ref. Resolve changed mode's `--base-ref`
   once with an argv-only bounded Git command before preparation, require a lowercase 40-hex result,
   and bind that value as `base_commit` in the canonical payload. Preserve it when an empty changed
   selection becomes `none`; use explicit null for modes with no base. Add CLI/module tests for a
   symbolic ref resolving successfully plus timeout, nonzero, malformed, uppercase, and whitespace
   failures. The symbolic ref may still be used only to compute the changed repository set.
4. Enforce loaded-item eligibility and canonical representation even when an attacker recomputes
   the fingerprint. Reject `draft=true`, non-`.zip` names, noncanonical timestamps (require the exact
   GitHub UTC form accepted from release data), empty/uppercase/prefixed digest aliases while keeping
   null valid, and arbitrary or whitespace-bearing `source_resolution_error` strings. Accept only
   the module's documented redacted source-resolution error forms, consistent with repository/tag.
   Add re-fingerprinted negative tests for each case.
5. Preserve existing no-eligible-release evidence. A selected repository with no eligible release
   must not silently yield an `all`, nonempty `changed`, or `repository` worklist with zero items;
   fail preparation without an output or encode the existing identity-complete repository error if
   the schema can do so without inventing an unplanned item identity. Add all three mode cases. Only
   a changed selection containing no repositories may collapse to a zero-item `none` payload.
6. Close the remaining tag/producer integration gaps: accept valid annotated tag records regardless
   of base/peeled record order while still rejecting duplicate identical/conflicting records; reject
   uppercase object-ID aliases rather than normalizing them. Add a real `main()` changed-empty case
   (not a mocked `prepare_audit_worklist`) that proves `none`, exact single-line stdout, no
   `$GITHUB_OUTPUT`, and zero metadata/release/tag calls.
7. Write the new focused tests first and capture their genuine failing invocation/output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-red.log`. Then run the corrected focused
   suites and full repository quality gate, preserve the exact green transcript under the same
   temporary root, keep `security-verdicts.json` unchanged, commit, leave the tree clean, recreate
   the marker, and stop after Task 2.

STATUS: CHANGES_REQUESTED
