# Review — quota-safe-security-audit (round 12)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on four remaining Task-4A contracts. The round-11 corrections fixed the earlier
symlink-byte, redirect, ordinary-file streaming, and destructive-cleanup defects, but normal source
tar topology, metadata memory, atomic no-clobber promotion, and authenticated-session isolation are
not yet correct. Do not begin Task 4B or worker integration.

## Gate status

- Commit reviewed: `0a0e24c4775125e752055b1bbbca8ee474489b42`; tree clean, marker valid,
  implementer session absent, and `security-verdicts.json` unchanged.
- Root focused run: `47 passed`. Root complete gate: actionlint mutations rejected, Ruff clean,
  `828 passed, 61 subtests passed`.
- Both independent Terra reviews reproduced the valid-directory rejection, unbounded metadata read,
  and promotion race. Root reproduced a tar containing explicit root/nested directories failing with
  `SourceSnapshotError: ambiguous archive path ... conflicts with ...`.
- No distinct round-11 correction red/green logs were preserved under the requested Task-4A names.
  The green test result is reproducible, but the process evidence is incomplete and must not be
  retroactively fabricated.

## Required changes

1. Correct the whole-path graph so explicit directory entries are valid ancestors. An ordinary tar
   containing `root/`, `root/sub/`, and `root/sub/file` must succeed. Continue rejecting exact
   duplicates/type conflicts and any file or symlink that is an ancestor of another member in either
   member order. Add success cases with explicit root and nested directory headers, plus the existing
   file/symlink ancestor negatives. Extend the fixture builder to emit directories so this cannot
   remain false-green. Inventory must still contain only files/symlinks and materialization must not
   trust archive directory permissions or links.
2. Remove the unbounded second reads of root `plugin.json` and `package.json`. Capture their bytes
   during the same chunked extraction under an explicit 1 MiB (`1_048_576` byte) per-file metadata
   cap, while keeping incremental Git hashing and exact declared-size validation. An allowed
   ordinary source file may
   be large without entering memory; oversized root metadata must fail as a source-snapshot error
   and clean staging. Add a materializer-level guarded test that rejects every `read()`/`read(-1)`,
   proves metadata bytes are assembled only from bounded chunks, and covers the metadata cap.
3. Replace the `exists()`/`os.replace()` check with an atomic no-clobber promotion contract for the
   destination directory. A destination created after initial validation—even an empty directory—
   must cause a fail-closed source-snapshot error and must never be replaced or deleted. Use a true
   atomic no-replace primitive or redesign the ownership/promotion seam; another check followed by
   `os.replace()` is still TOCTOU. Add a race test that creates an empty destination inside the real
   promotion call and then delegates to the actual primitive; assert materialization fails and the
   same destination inode survives. Retain an independent nonempty sentinel case and staging cleanup.
4. Enforce a fresh, unauthenticated underlying source transport. Stripping only
   `session.headers['Authorization']` is insufficient because Requests-style `session.auth` can add
   credentials during preparation. Either create the fresh session inside the source-session seam or
   fail closed on any injected default auth/auth hook while preserving test transport injection.
   Authorization may exist only as the per-request header added after validating an allowed hop.
   Add a realistic session-auth test as well as the existing default-header/caller-header cases;
   prove no default credential is prepared or sent.
5. Add the tests first and preserve a genuine round-12 red log separately from its green log; do not
   overwrite or invent the missing round-11 evidence. Run the corrected focused tests and complete
   quality gate, record real exit/tallies, keep `security-verdicts.json` unchanged, commit only this
   Task-4A correction, leave the tree clean, recreate the completion marker, and stop for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
