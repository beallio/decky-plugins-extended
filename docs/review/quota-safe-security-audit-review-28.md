# Review — quota-safe-security-audit (round 28)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B3's production removal is accepted: the old REST/raw/API-tarball data plane is gone and
Trivy/diff use only the shared prepared snapshot. The test migration is not accepted. The round
deleted multiple unique build-stamp and false-positive safety contracts instead of porting them to
the snapshot adapter, creating a false-green surface around unchanged but security-sensitive
classification logic. Restore that coverage without reintroducing legacy helpers. Do not begin
Task 3B.

## Gate status

- Commit reviewed: `df23917830b6165b0ddc399111faf9395eb74455`; tree clean, marker
  valid, implementer session absent, `git diff --check` clean, and `security-verdicts.json`
  unchanged at `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.
- Root repo-wide symbol inspection and two independent Terra architecture reviews confirm no
  production reference remains to `get_repo_file_raw`, `_download_source_archive`,
  `_fetch_source_tree`, `_resolve_ref_to_tree_sha`, legacy `compare_source_and_artifact`, or
  `run_trivy(source_repo=...)`. `_resolve_ref_to_commit_and_tree_sha()` correctly remains until
  Task 3B. Ruff finds no dead imports.
- Root focused audit/cache/verdict/worklist/bounded-download suite: `394 passed, 45 subtests
  passed`; log: `/tmp/decky-plugins-extended/root-review-task4b3-round27-focused.log`.
- The implementer focused removal contract passed `33` tests, but its complete quality log is red:
  `838 passed, 63 subtests passed, 5 failed`. Those failures are verdict-push fixtures rejecting
  the implementer session's `/tmp` UV-cache environment, not Task-4B3 behavior, but the log is not a
  successful complete gate and must not be reported as one.
- The snapshot suite retains only one version-only build-stamp allowance. The round deleted direct
  unit contracts for exact package version, debug-flag removal, exact publish-image tag rewriting,
  and rejection of arbitrary versions, unrelated drift, reordered flags, and near-match image URLs.
  Those tests did not depend on the deleted legacy data plane and should not have been removed.
- The round also dropped integration contracts proving non-build `flags` drift and malformed
  metadata yield `MODIFIED_SOURCE_FILE`, normal compiled JS/source-map/PNG and other non-script data
  do not produce ZIP-only findings, native binaries are not double-classified as scripts, and
  Python/shebang/executable-text scripts are detected while a script present in source is not.
  Existing snapshot tests cover only generic modification plus one ELF and one shebang case; they
  are not equivalent to these unique boundaries.

## Required changes

1. Restore the direct `_metadata_diff_is_build_stamped()` unit matrix for: exact package-version
   allowance, exact debug-flag removal, exact `publish.image` branch-to-tag rewrite, arbitrary
   version rejection, unrelated-field drift rejection, reordered/non-debug flags rejection, and
   near-match image URL rejection. These are implementation-policy tests and require no legacy
   helper. Retain the `_shannon_entropy` absence regression unless you can point to an existing
   equivalent; its deletion was unrelated to Task 4B3.
2. Port the report-shape metadata cases through `compare_source_and_artifact_from_snapshot()`:
   combined Decky-stamped plugin metadata and package version changes pass; root/non-debug flags or
   malformed metadata produce `status=found_issue`, the exact modified path, and a
   `MODIFIED_SOURCE_FILE` finding. Use the snapshot's captured metadata/inventory path and retain the
   no-source-filesystem-read guarantees already established.
3. Port the unique ZIP-only heuristic cases through the snapshot adapter: `.py`, shebang, and
   executable-text files are `ZIP_ONLY_SCRIPT`; a matching source script is not; an ELF is
   `ZIP_ONLY_EXECUTABLE` and not also a script; compiled/minified JS, source maps, JSON, CSS, and PNG
   assets remain clean. Preserve exact summary lists, status, and finding rule IDs. Parameterize
   where useful, but do not collapse these into assertions weaker than the removed contracts.
4. Keep the deleted-helper/source-repo absence test, prepared-root Trivy tests, snapshot symlink and
   bounded codeload coverage, and all production removals unchanged. This is a test-migration round;
   make no production change unless a restored contract exposes a real behavior regression, in
   which case stop and explain it in the review response.
5. Because current production is expected to satisfy restored contracts, do not fabricate a normal
   red run. Preserve focused green at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b3-round28-green.log`. Demonstrate the
   restored tests are discriminatory with temporary, reverted mutations (at minimum: an overly
   permissive build-stamp decision and disabled ZIP-only script classification) at
   `...-round28-mutation.log`. Rerun the complete gate in the normal project environment and preserve
   a genuinely green `...-round28-quality.log` with exact tallies. Keep scope to affected tests and
   the review response, keep `security-verdicts.json` unchanged, leave the tree clean, recreate the
   completion marker, and stop for review.

STATUS: CHANGES_REQUESTED
