# Review — quota-safe-security-audit (round 11)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on Task 4A. The module is well isolated and the current tests/gates pass, but
several byte-integrity, preflight, redirect-bound, memory-bound, and destination-ownership contracts
remain false. Correct only Task 4A; do not begin consumer or worker integration.

## Gate status

- Commit reviewed: `8f34e8c741c9bb0088f2be13a485c4a6e5489e14`; tree clean, marker valid,
  implementer session absent, and `security-verdicts.json` unchanged.
- Root focused run: `17 passed`. Root complete gate: actionlint mutations rejected, Ruff clean,
  `798 passed, 61 subtests passed`.
- The distinct Task-4A red log is genuine (`8 failed, 9 passed`) and the green log records
  `17 passed`.
- Two independent Terra reviews reproduced the non-UTF-8 symlink hash defect; one reproduced a
  file-ancestor archive writing before `FileExistsError`. Root additionally reproduced an unwrapped
  malformed-port `ValueError`, a returned/unclosed 304, four redirects being allowed, and a
  concurrently created destination being deleted during unrelated failure cleanup.

## Required changes

1. Preserve Git symlink target bytes exactly. `errors="replace"` currently turns a tar target byte
   such as `0xff` into `b"?"`, corrupting `size_bytes` and the Git blob SHA-1. Round-trip tarfile's
   surrogate escapes with `errors="surrogateescape"` (or use an equivalently byte-preserving seam)
   consistently in preflight and inventory construction. Keep non-executed target metadata
   round-trippable and add a non-UTF-8 link-target regression that asserts the original bytes,
   exact size/hash/mode, and no materialized link.
2. Make preflight reject the complete ambiguous path graph before extraction writes anything.
   Track directory, file, and symlink identities and reject any file/symlink that is an ancestor of
   another member or has a descendant already present (including symlink-plus-descendant), as well
   as type conflicts. Reject rather than rewrite ambiguous backslash and Windows-drive forms; retain
   absolute, empty/dot/traversal, duplicate/canonical-alias, depth, and one-top-level defenses. Add
   both member orders for `root/node` plus `root/node/child` and a symlink-ancestor case. Instrument
   the extraction/write seam to prove every such failure occurs before the first member write and is
   reported as `SourceSnapshotError`.
3. Enforce the redirect cap as a hard policy, not an arbitrarily extensible test parameter. Require
   a non-bool integer in `0..3`; reject `4`, negative, bool, float, and string values before staging
   or requesting. Treat every 3xx as redirect-policy input: only 301/302/303/307/308 with a valid
   approved `Location` may advance, while 300/304/305/306 and a fourth redirect must close without
   streaming and raise `RedirectPolicyError`. Catch URL parsing/port-access failures (including a
   nonnumeric port) and convert them to the same typed boundary. Preserve HTTPS/no-userinfo/no-port/
   exact-host validation before each request.
4. Complete the response-ownership tests. For successful direct and redirect chains assert every
   intermediate response and the bounded stream's final response are closed exactly as owned. For
   unsupported status, missing/non-string/malformed location, HTTP, userinfo, explicit/nonnumeric
   port, loop, and unknown host, assert the current response closes, no rejected next-hop request is
   made, no rejected body is iterated, and no snapshot/staging residue remains. Also prove a caller
   Authorization header or authenticated session cannot bypass per-hop credential scoping; never
   use a session-default Authorization as the source transport contract.
5. Do not load every permitted regular file into memory with an unbounded `stream.read()`. The
   current policy permits a 512 MiB file and a 1 GiB expanded source, so this is not a safe bounded
   extraction implementation. Stream each regular file to its staged destination in bounded chunks
   while incrementally counting and computing its Git blob SHA-1, verify the exact declared size,
   and capture only the two required root metadata payloads under the applicable explicit bound.
   Add a guarded archive stream that fails if called with `read()`/`read(-1)` and prove chunked bytes,
   hash, mode, and cleanup on a mid-stream failure.
6. Never recursively delete `destination_path` merely because it exists during an exception. A
   concurrent creator currently loses unrelated data if download/extraction fails. Track only paths
   owned by this invocation, preserve any destination that appears before promotion, and fail closed
   rather than replacing it. Add controlled failures that create a destination with a sentinel both
   before normal failure cleanup and immediately before promotion; the sentinel must survive and no
   staged snapshot may be presented as complete. Retain atomic promotion of a wholly completed
   source tree and cleanup of this invocation's archive/staging paths.
7. Finish the remaining review-10 archive regression fence: absolute and over-depth paths, socket/
   unknown nodes, no-regular-file input, actual promoted regular-file bytes, and cleanup of every
   `source-snapshot-*` staging directory after representative download, invalid-tar, preflight, read,
   and promotion failures. Preserve the existing exact codeload URL/API-tarball rejection,
   inventory order, metadata, limit, special-node, and repeatability tests.
8. Run the corrected focused tests and complete quality gate, save new correction red/green output
   to distinct Task-4A files without overwriting round-10 evidence, keep `security-verdicts.json`
   unchanged, commit only this correction, leave the tree clean, recreate the completion marker,
   and stop for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
