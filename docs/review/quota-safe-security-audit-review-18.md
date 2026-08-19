# Review — quota-safe-security-audit (round 18)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B1 is directionally correct and all current tests pass, but one high-severity boundedness and
behavior-equivalence defect remains. Correct the snapshot diff's source reads and strengthen its
isolation tests. Do not begin Task 4B2.

## Gate status

- Commit reviewed: `e37442d12725fcd6fb701f22f6cd444f4e697340`; tree clean, marker
  valid, implementer session absent, and scope is limited to `audit_plugins.py` plus focused tests.
- Root focused audit-plugin suite: `214 passed, 36 subtests passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `852 passed, 61 subtests passed`.
- Two independent Terra reviews confirm the prepared-root Trivy path and snapshot diff are
  network/ref/tree/raw/tar independent, `audit_release()` is unchanged, and symlink entries are
  represented as non-materialized Git blobs.
- No genuine Task-4B1 implementer red/green/full logs were preserved. Root green logs exist, but do
  not relabel or fabricate the missing historical red phase.

## Required changes

1. Remove the unconditional `_snapshot_source_blob()` call. Compute the artifact Git blob hash and
   the existing CRLF-normalized hash first. If either matches the inventory SHA, return to the walk
   without opening or reading any source file. Ordinary non-metadata mismatches need no source
   bytes; record the existing modified-file result directly. Symlink comparisons must use only the
   inventory hash/recorded target and must never open or follow a local path.
2. Only a remaining `plugin.json` or `package.json` mismatch may obtain source bytes for the existing
   build-stamp allowance. Prefer the snapshot's captured root `plugin_json`/`package_json` bytes.
   If a non-root metadata entry genuinely needs a local read, require its exact inventory entry to
   be `kind == "file"`, confine it beneath `source_root`, reject symlink following, and cap the read
   at the same 1 MiB metadata limit used during snapshot creation. A missing, changed, oversized,
   or unreadable local metadata file must fail the consumer with a bounded redacted detail; never
   read an ordinary source blob merely to compare its already captured hash.
3. Add a regression that makes a hash-identical ordinary source file unavailable or makes its open
   fail and proves comparison still passes without a source read. Add a large-entry/read-size
   regression that fails on an unbounded `read()` and proves metadata reads cannot exceed the cap.
   Prove root build-stamp comparison uses captured snapshot bytes even if the local metadata file is
   unavailable, and add a no-follow sentinel covering symlink entries.
4. Extend the prepared-root Trivy isolation test so `_gh_get`, `_resolve_ref_to_tree_sha`,
   `get_repo_file_raw`, `_fetch_source_tree`, and `_download_source_archive` all raise if called,
   while the supplied source directory is still scanned exactly once and no source temporary tree
   is allocated.
5. Write the new boundedness tests first and preserve their genuine round-18 red output, then save
   focused green and complete quality-gate logs with exact tallies. Keep `security-verdicts.json`
   unchanged, commit only this Task-4B1 correction and review response, leave the tree clean,
   recreate the completion marker, and stop for review.

Still deferred: all Task-4B2 cache/source orchestration, Task-4B3 legacy removal, Task-3B worker
integration, aggregation, workflows, scanner bootstrap, and documentation.

STATUS: CHANGES_REQUESTED
