# Review — quota-safe-security-audit (round 19)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B1 still needs one fail-closed metadata-fallback correction. The ordinary and symlink
hash-only paths are now clean, but the rare local metadata read is TOCTOU-vulnerable and is not
verified against the immutable inventory. Do not begin Task 4B2.

## Gate status

- Commit reviewed: `54d41e5866fffdb771d3b2370582ca787f60fff7`; tree clean, marker
  valid, implementer session absent, and `security-verdicts.json` unchanged.
- Root focused audit-plugin suite: `217 passed, 36 subtests passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `855 passed, 61 subtests passed`.
- The corrected adapter no longer reads ordinary matching/mismatching source files, uses inventory
  hashes and recorded symlink targets, uses captured root metadata, and caps a local fallback read
  at 1 MiB plus one detection byte. Trivy now has every requested network/ref/raw/tar sentinel.
- Two independent Terra reviews reproduced a final-path symlink swap through the current
  `lstat()`-then-`open()` seam and found missing inventory verification. Round-18 green logs exist;
  its requested pre-fix red log was not preserved. Do not fabricate or relabel it.

## Required changes

1. Validate the inventory path's canonical relative POSIX form before any filesystem access:
   reject absolute paths, empty components, `.`, `..`, backslashes, and non-canonical aliases.
   Do not `lstat()` or open any component before this confinement validation succeeds.
2. Replace path-based `lstat()` followed by `open()` with descriptor-relative no-follow traversal.
   Open `source_root` as a directory without following a final symlink; open every intermediate
   component relative to its parent with directory/no-follow semantics; open the final component
   read-only and no-follow; then `fstat()` the opened descriptor and require a regular file. Close
   every descriptor on success and every failure. Fail closed on platforms that cannot provide the
   required no-follow behavior; never block on or read a FIFO/device/special node.
3. After the bounded read, require exact equality with the selected inventory entry's
   `size_bytes` and `git_blob_sha1` before using the bytes for build-stamp suppression. Apply the
   same size/hash validation to captured root `plugin_json` and `package_json`; captured bytes are
   trusted as transport data, not as an unchecked substitute for the inventory. Any path, node,
   size, or hash invariant failure must return a failed, redacted source-diff status.
4. Add tests that fail the current code for: final-path symlink swap, ancestor/root symlink or
   replacement, FIFO/special final node without blocking, non-canonical traversal rejected before
   any filesystem probe, local fallback size/hash mismatch, and captured-root metadata size/hash
   mismatch. Retain the existing no-read ordinary/symlink cases and bounded-read regression.
5. Preserve a genuine round-19 red log from these new regressions, then focused green and complete
   quality-gate logs with exact tallies. Keep the change within `audit_plugins.py`, focused tests,
   and the review response; keep `security-verdicts.json` unchanged, leave the tree clean, recreate
   the completion marker, and stop for review.

Still deferred: all Task-4B2 cache/source orchestration, Task-4B3 legacy removal, Task-3B worker
integration, aggregation, workflows, scanner bootstrap, and documentation.

STATUS: CHANGES_REQUESTED
