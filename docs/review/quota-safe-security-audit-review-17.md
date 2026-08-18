# Review — quota-safe-security-audit (round 17)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4A is accepted. Implement only Task 4B1: snapshot-based source-consumer adapters and their
focused regression tests. Do not change `audit_release()`, cache ordering, worker CLI behavior,
workflows, aggregation, or legacy-helper reachability in this round.

## Gate status

- Accepted Task-4A HEAD: `8578c04a9f9186f5e6724e4739453ebff40c2e6c`; tree clean, marker
  valid, implementer session absent, and `security-verdicts.json` unchanged.
- Root focused source-snapshot suite: `62 passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `843 passed, 61 subtests passed`.
- Independent Terra review confirms the final-promotion race test exercises the native helper and
  fences `os.rename`, `os.replace`, and `shutil.move` fallbacks.
- Architecture review recommends separating pure consumer conversion from cache/source
  orchestration so the API-free boundary is not claimed before `audit_release()` actually uses it.

## Required changes

1. Add a snapshot-based Trivy path that accepts an already materialized source directory and scans
   that exact directory alongside the artifact. It must not allocate a source temporary directory,
   call `_fetch_source_tree()`, or perform any source network/ref/tree/raw operation. Preserve the
   current scanner status, finding shape, scope labels/counts, partial-output parsing, severity, and
   error semantics. Keep the legacy `source_repo` path only as an explicitly transitional path for
   the unchanged `audit_release()` caller.
2. Add a distinctly named snapshot-based source/artifact comparison adapter that consumes a
   `audit_source_snapshot.SourceSnapshot` root and inventory. It must not call `_gh_get`,
   `_resolve_ref_to_tree_sha`, `get_repo_file_raw`, `_fetch_source_tree`, or the legacy REST tarball
   path. Preserve every current summary key and `ref`, path matching precedence, case-insensitive
   matching, leading plugin-directory handling, Git blob hashing, CRLF normalization, build-stamped
   `plugin.json`/`package.json` allowances, finding/report shape, and deterministic sorting.
3. Treat `SourceInventoryEntry` symlinks as Git symlink blobs using their recorded target/hash;
   never materialize or follow them. For build-stamp checks, use the snapshot's captured root
   metadata or a bounded, inventory-authorized local regular-file read. Do not execute repository
   hooks, package managers, or plugin code.
4. Add focused consumer tests covering normal identical/modified files, CRLF equivalence,
   build-stamped metadata, case variants, leading artifact directory, ZIP-only executable/script
   detection, and source symlink inventory behavior. Exercise the new adapters with `_gh_get`,
   `_resolve_ref_to_tree_sha`, `get_repo_file_raw`, `_fetch_source_tree`, and the legacy source
   archive downloader patched to raise. Assert the supplied Trivy source directory is scanned
   exactly once and no source temp tree is allocated or fetched.
5. Preserve a genuine Task-4B1 red log before implementation, then focused green and complete
   quality-gate logs with exact tallies. Keep the changes to `audit_plugins.py`, focused tests, and
   the review response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate the
   completion marker, and stop for review.

Deferred to Task 4B2: cache-before-source ordering, exactly one materialization on an uncached
release, shared snapshot injection into metadata/Trivy/diff, required/optional source-preparation
failure classification, and real `audit_release()` REST-sentinel tests. Deferred to Task 4B3:
legacy source helper removal. Public worker CLI/API isolation remains deferred to Task 3B.

STATUS: CHANGES_REQUESTED
