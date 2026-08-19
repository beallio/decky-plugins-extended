# Review — quota-safe-security-audit (round 22)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B1 is accepted. Implement Task 4B2 only: cache-before-source ordering and one-snapshot
`audit_release()` orchestration, including source-failure report semantics. Do not remove legacy
helpers, add the public worker CLI, or change aggregation/workflows in this round.

## Gate status

- Accepted Task-4B1 HEAD: `6e9e6c41ff7730eb9f497a8ab2ec926f9c86230f`; tree clean,
  marker valid, implementer session absent, and `security-verdicts.json` unchanged.
- Implementer focused evidence: `227 passed, 36 subtests passed`; complete gate: `865 passed,
  61 subtests passed`, with actionlint mutation controls and Ruff clean.
- Root independently reproduced both tallies. Terra verification confirms the final test-only
  closeout fences invalid captured metadata, real final/ancestor symlink races, and reverse-order
  cleanup of root/ancestor/final descriptors.
- The current `audit_release()` still fetches raw tagged metadata before cache lookup, then Trivy
  fetches its own source tree and diff resolves/fetches tree/raw data. Those are the boundaries this
  round must replace using the already accepted snapshot adapters.

## Required changes

1. Refactor `audit_release()` ordering without changing its public CLI contract: resolve the current
   release commit and compute the audit-context/cache policy first. For a valid GitHub digest, run
   `load_cached_report_predownload()` before creating/materializing source or reading tagged source
   metadata. For a digestless release, stream and hash the artifact exactly once, validate it, then
   run the SHA-keyed cache lookup before any source operation. A valid hit must return with zero
   codeload requests, zero source extraction/materialization, zero tagged-source reads, and zero
   source-consumer calls. Preserve scheduled/explicit cache-bypass behavior and all artifact digest
   validation.
2. On either cache miss, materialize exactly one `audit_source_snapshot.SourceSnapshot` beneath the
   release-owned temporary directory using the canonical repository URL, resolved 40-hex commit,
   existing authenticated session, and current archive limits. Call materialization once only.
   Initialize tagged `plugin.json`/`package.json` from that snapshot's captured root bytes and
   preserve the current metadata paths, ZIP fallback, plugin-name selection, findings, and report
   shape. Remove raw tagged-file calls from this path.
3. Pass that same snapshot's exact `source_root` to the prepared-root `run_trivy()` path and the
   same `SourceSnapshot` object to `compare_source_and_artifact_from_snapshot()`. Never pass
   `source_repo`, call the legacy comparison function, or perform ref/tree/raw/API-tarball source
   work after the one prepared commit. Preserve artifact Trivy/ClamAV/Semgrep execution, scanner
   findings/status shapes, build-stamp allowances, and classification precedence.
4. If source download, redirect validation, extraction, inventory construction, or promotion fails,
   retain a bounded redacted source-preparation detail and continue ZIP inspection/extraction,
   artifact metadata fallback, artifact Trivy findings, ClamAV, Semgrep, allowlisting, and report
   construction. Record an explicit low `PASS_WITH_WARNINGS` source-snapshot finding for tagged
   metadata failure; mark every enabled source-dependent scanner as failed with that detail while
   preserving artifact-only findings. Do not append an unconditional `report.errors` entry.
   Required Trivy or source-artifact-diff failure must yield release-local `AUDIT_ERROR`/exit-4
   precedence unless a structural `BLOCK` wins; optional policy variants must remain publishable
   `PASS_WITH_WARNINGS`. Disabled consumers remain skipped. Preserve the existing optional diff
   incomplete finding without silently treating an unrun comparison as passed.
5. Add a real uncached-success integration fixture using a fake artifact transport and fake
   codeload session but the real snapshot materializer/extractor. Assert one codeload request and
   one extraction, the exact immutable
   `https://codeload.github.com/<owner>/<repo>/tar.gz/<40-hex-commit>` URL, source metadata usage,
   Trivy's exact prepared root, and object identity at the snapshot diff. Set `_gh_get`,
   `_resolve_ref_to_tree_sha`, `get_repo_file_raw`, `_fetch_source_tree`, `_download_source_archive`,
   legacy `compare_source_and_artifact`, and any `api.github.com/.../tarball/...` seam to raise after
   the one prepared commit; assert none fires. Cover both lightweight and annotated resolved-commit
   inputs without re-resolving inside a consumer.
6. Add cache regressions for: digest-backed predownload hit with zero artifact/source/consumer work;
   digestless hit with exactly one artifact stream/hash and zero source/consumer work; cache miss
   with one artifact stream and one source materialization; and cache bypass still performing the
   fresh audit. Add report-level source-preparation-failure cases for required and optional Trivy/
   diff policies, proving artifact scanners and ZIP metadata fallback still run, details are
   redacted/bounded, required failure is `AUDIT_ERROR`/incomplete, optional failure is
   `PASS_WITH_WARNINGS`/completed, and structural `BLOCK` retains precedence.
7. Write the integration/cache/failure tests first and preserve their genuine failing output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b2-round22-red.log`. Preserve focused
   green at `...-round22-green.log` and the complete gate at `...-round22-quality.log`, recording
   exact tallies. Keep scope to `audit_plugins.py`, focused audit/cache/download tests, and the
   review response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate the
   completion marker, and stop for review.

Deferred to Task 4B3: removal of `_download_source_archive`, `_fetch_source_tree`,
`_resolve_ref_to_tree_sha`, and any raw-source helper whose repo-wide callsites are gone. Deferred
to Task 3B: prepared worklist commit/error injection and the public worker API-isolation test.

STATUS: CHANGES_REQUESTED
