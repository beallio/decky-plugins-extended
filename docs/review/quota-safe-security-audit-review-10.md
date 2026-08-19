# Review — quota-safe-security-audit (round 10)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 3A is functionally complete and independently green. Begin only the first, prerequisite half
of Task 4: immutable source acquisition, safe extraction, and deterministic inventory primitives.
Do not route `audit_release()` or a real `--worklist` worker through these primitives yet; that
integration belongs to Task 4B/3B after the shared source object exists.

## Gate status

- At `12abf84d6c8d7aca9e9c105fbc390fd539384e97`, the focused Task-3A suite passes
  (`161 passed`) and the root-run complete gate passes (`781 passed, 61 subtests passed`).
- The tree is clean, the completion marker is valid, and `security-verdicts.json` remains unchanged.
- A Terra architecture review confirmed that wiring the current `audit_release()` now would not
  prove worker isolation: `_fetch_source_tree()`, raw metadata, and source/artifact tree comparison
  still contain legacy REST consumers. Source materialization must therefore precede worker wiring.
- Process caveat only: the Task-3A red log was overwritten with a green run, so no genuine historical
  red artifact survives for that completed slice. Do not recreate history or block Task 4A on it;
  preserve distinct red and green files for this new slice.

## Required changes

1. Add a narrowly scoped source-snapshot module (prefer `audit_source_snapshot.py`) with immutable
   data records for a source inventory entry and a complete source snapshot. The snapshot must bind
   the canonical lower-case GitHub repository, validated 40-lowercase-hex commit, exact immutable
   codeload URL, downloaded archive SHA-256 and byte count, promoted source root, deterministic
   inventory, and local root `plugin.json`/`package.json` bytes when present. Each inventory entry
   must retain a canonical relative path, kind (`file` or `symlink`), byte count, Git-blob SHA-1,
   normalized Git mode (`100644`, `100755`, or `120000`), and non-executed symlink-target metadata.
   Make the returned inventory immutable and sorted by canonical path.
2. Implement one materialization seam that validates the owner/repository atoms and commit before
   any request, downloads exactly
   `https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>`, safely extracts once into a temporary
   subtree, and atomically promotes only a complete snapshot. Reuse
   `plugin_release_utils.bounded_stream_download()` for the final response body and the existing
   source byte/connect/read/chunk policy. Never execute repository content. On every validation,
   download, tar, inventory, or promotion failure, close responses and remove archive, temporary
   extraction, and incomplete promoted output.
3. Add a fresh, narrowly scoped codeload transport; never use `_gh_session` or place Authorization
   in a session's default headers. Follow at most three redirects manually with
   `allow_redirects=False`, close every intermediate response, and approve each hop before making
   the next request. Permit only HTTPS, no userinfo, the default HTTPS port, and an explicit host
   allowlist initially containing only `codeload.github.com`. Add an Authorization header to a
   request only after that request URL passes the allowlist, and never forward it to a rejected
   host. Reject missing/malformed `Location`, loops, excessive redirects, HTTP downgrades, explicit
   ports, userinfo, and unknown hosts before the final body is streamed. Keep the redirect wrapper
   compatible with the injected `session.get()` interface required by the bounded downloader and
   make its response ownership/cleanup unambiguous.
4. Preflight the entire tar member table before writing any member. Require exactly one nonempty
   top-level directory; canonical safe relative paths; no absolute, traversal, ambiguous, duplicate,
   or over-depth paths; and the existing archive file-count, total-uncompressed-byte, and
   single-file-byte limits. Require at least one regular file. Materialize directories and regular
   files only. Record Git symlinks from their encoded link target but never create them on disk;
   reject hardlinks, devices, FIFOs, sockets, and unknown member types. A symlink target containing
   traversal remains inert metadata and cannot escape. Do not follow archive-controlled filesystem
   links during writes or promotion.
5. Compute regular-file Git blob hashes from exactly the extracted bytes and symlink blob hashes
   from the encoded link-target bytes (`sha1(b"blob " + decimal_length + b"\\0" + payload)`).
   Normalize ordinary file modes from the executable bits only. Ensure the inventory, archive
   digest/size, root metadata bytes, and promoted file bytes are repeatable for identical input.
   Do not partially reuse or modify the legacy `_download_source_archive()`/`_fetch_source_tree()`
   consumers in this slice.
6. Add focused tests (prefer `tests/test_source_snapshot.py`) covering exact URL and identity/commit
   validation; one bounded final-body stream; direct and approved-redirect success; every redirect,
   credential, response-close, and cleanup boundary above; all unsafe/special/limit tar cases;
   duplicate and multiple/no-top-level archives; deterministic order and repeatability; correct
   regular/executable/symlink modes, sizes, and Git hashes; metadata bytes; symlink absence on disk;
   and no completed snapshot after any failure. Assert explicitly that credentials are absent from
   any rejected-host request and that `api.github.com/.../tarball/...` is never requested.
7. Add these tests first and capture a genuine assertion-failure red run in
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4a-red.log`; write green output to a
   distinct `...task4a-green.log`. Then run the focused tests and complete quality gate, retain the
   exact exit status/tallies, keep `security-verdicts.json` unchanged, commit only Task 4A, leave the
   tree clean, recreate the completion marker, and stop for review.

Explicitly deferred: `audit_release()` integration, cache-before-source ordering, Trivy/diff/raw
metadata consumer changes, source-failure classification, legacy helper removal, public worker CLI,
worker API-isolation sentinels, aggregation, and workflows.

STATUS: CHANGES_REQUESTED
