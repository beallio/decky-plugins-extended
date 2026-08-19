# Review — quota-safe-security-audit (round 29)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B3 is accepted. The production tree no longer contains the legacy
raw-file, source-tarball, source-tree, or duplicate ref-resolution paths, and
the restored tests again fence the exact build-stamp and script-classification
behavior that Task 4B3 must preserve.

Implement **Task 3B only** in this round: expose the validated worklist worker
mode, inject its prepared source identity into the audit path, bind worker
progress/resume to the worklist fingerprint, and atomically checkpoint a shard
manifest. Do not begin Task 5 aggregation or edit workflows yet.

## Gate status

- Reviewed HEAD: `2cb97981e3fe102dba4621a4b0141bb81ed474c5`
- Worktree was clean; the round marker was valid for that HEAD; no implementer
  session remained active.
- Root focused review gate:
  `411 passed, 45 subtests passed` in
  `/tmp/decky-plugins-extended/root-review-task4b3-round28-focused.log`.
- Root complete gate:
  `860 passed, 63 subtests passed` in
  `/tmp/decky-plugins-extended/root-review-gate-task4b3-round28.log`.
- Implementer mutation evidence in
  `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b3-round28-mutation.log`
  proves both restored contract classes are live: rejecting the legitimate
  exact build-stamp metadata produces two failures, and disabling archive-only
  script classification produces three failures.
- Ruff and both GitHub Actions mutations passed.
- `security-verdicts.json` checksum remained
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

## Required changes

1. Add the fail-closed public worker CLI.
   - Add `--worklist PATH` as a mutually exclusive execution mode and
     `--expected-worklist-fingerprint SHA256` as its required companion.
   - Reject the fingerprint argument outside worklist mode. In worklist mode,
     reject `--latest-only`, `--base-ref`, `--prepare-worklist`, every local
     selection mode/argument (`--all`, `--changed`, `--repository`, and an
     explicitly supplied plugins file), and any producer-only argument that
     could change source selection. Preserve existing aggregate and
     verdict-delta mode exclusivity.
   - Load and validate the complete document through
     `audit_worklist.load_expected_worklist_document()` before creating or
     truncating the output report, delta, progress, or shard-manifest path.
     Require the validated document fingerprint to match the expected value,
     and require CLI shard count/index to match its declared shard shape.
     Invalid input is a run-global exit `1` with no partial outputs.
   - Select only with `audit_worklist.select_worklist_shard()`. Preserve the
     validated worklist's source order. Do not convert items through the old
     discovery `AuditWorkItem`/`select_audit_shard()` path.

2. Give `audit_release()` an explicit prepared-source contract.
   - Add internal prepared commit and prepared source-resolution-error inputs.
     Validate them as mutually exclusive and consume exactly the value carried
     by a validated worklist item. A prepared value must suppress
     `_resolve_ref_to_commit_and_tree_sha()` completely; retain that resolver
     only for the existing local/smoke path until its later producer split.
   - Build the release and repository metadata consumed by the audit only from
     the normalized item (`repository`, release/asset IDs and names, URL,
     timestamps/flags, digest, and `repository_archived`). Do not refresh any
     of it.
   - A prepared source-resolution error must create an identity-complete,
     bounded/redacted, checkpointed release-local `AUDIT_ERROR` report. It
     must not fall through to artifact/source/scanner work or become a
     run-global error. Continue safe sibling releases and retain release-error
     exit `4` precedence. Use `CURRENT` identity when the prepared digest is
     valid and otherwise the existing truthful unknown-identity convention.

3. Isolate worklist execution from every discovery and GitHub REST seam.
   - Worklist mode must not call `read_repo_urls`, `get_changed_repos`,
     `build_audit_worklist`, `get_repo_metadata`, `get_releases`, `_gh_get`,
     `_resolve_ref_to_commit_and_tree_sha`, `audit_repository`, or any removed
     raw/tarball/tree/ref helper.
   - A successful uncached worker may use only the one prepared codeload source
     snapshot path plus the selected asset URL and local scanner processes.
     Keep the existing local/smoke selection behavior working, but route its
     discovered values through the same prepared execution core where
     practical; do not add a fallback from worker mode to discovery or ref
     resolution.

4. Bind worker progress and resume to the validated snapshot.
   - In worklist mode use `_load_progress_manifest(progress_path,
     fingerprint)`, `_progress_record(report, fingerprint)`, and
     `_write_progress_manifest(..., fingerprint)` at every release checkpoint.
     Keep legacy v1 progress semantics only for the local path.
   - A resumable identity must match the same worklist fingerprint and the
     prepared source commit/error, repository/release/asset identity, asset
     digest, and current audit context. A v1, malformed, mismatched-fingerprint,
     or otherwise stale record must be ignored safely.
   - Prove that a matching resume completes with all discovery, REST, and ref
     resolvers replaced by raising sentinels. Prepared worklist source identity
     remains the sole resume identity input.

5. Atomically checkpoint `shard-manifest.json` beside the worker outputs.
   - Reuse the Task 3A normalization, write, load, and validation helpers.
     Include the exact validated worklist fingerprint/source revision,
     shard-count/index, deterministic ordered assigned identity set, and
     ordered attempted/report identity sets.
   - Update it with every successful release/report checkpoint and at final
     output. Attempted and report identity lists must remain equal because a
     release-local failure still writes an identity-complete report. Manifest
     checkpoint failure is run-global exit `1`, while already committed sibling
     checkpoints remain intact.
   - Emit a valid empty manifest, empty report, and empty verdict delta for a
     valid shard with no assigned items. Do not route this case through the old
     empty-repository early return.

6. Add a genuine red/green Task 3B contract suite.
   - Cover parser/mode conflicts, missing/mismatched fingerprints, invalid shard
     shape, and validation-before-output fail-closed behavior.
   - Exercise a real uncached eligible release with `--skip-cache`, Trivy and
     source/artifact diff enabled, fake artifact/codeload bytes and scanner
     executables, and raising sentinels for every forbidden seam listed above.
     Assert exactly one codeload source snapshot acquisition/extraction and no
     sentinel call.
   - Cover a prepared source-resolution error followed by a safe sibling,
     redaction/bounds, checkpoint/manifest contents, and final exit `4`.
   - Cover matching and mismatching fingerprint resume, deterministic shard
     assignment/order, a valid empty assigned shard, atomic manifest failure,
     and unchanged local CLI behavior.
   - Record genuine pre-fix failures, the focused green rerun, and the complete
     project gate under `/tmp/decky-plugins-extended/`. Keep actionlint success,
     both workflow mutation checks, Ruff, and the verdict checksum in the final
     handoff.

STATUS: CHANGES_REQUESTED
