# Review — quota-safe-security-audit (round 14)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on two final Task-4A archive contracts plus promotion regression coverage. The
native no-clobber primitive, path graph, member-count semantics, metadata bound, and all earlier
transport/inventory fixes now work, but header parsing remains pre-limit and explicit empty
directories disappear from the materialized snapshot. Do not begin Task 4B or worker integration.

## Gate status

- Commit reviewed: `b759aa0fe64278247fd6afcf6cb64e1a6ffa66d0`; tree clean, marker valid,
  implementer session absent, and `security-verdicts.json` unchanged.
- Root focused run: `55 passed`. Root complete gate: actionlint mutations rejected, Ruff clean,
  `836 passed, 61 subtests passed`.
- Root and Terra verified `renameat2(RENAME_NOREPLACE)` rejects an existing empty destination,
  preserves its inode, and leaves staging for owned cleanup. Directory headers work before and after
  child entries; file/symlink ambiguity and exact/over member limits also pass.
- One Terra review reproduced `root/empty/` vanishing from a successful snapshot. Another confirmed
  `archive.getmembers()` parses/retains all headers before the later member-limit check.
- Genuine round-13 red, green, and full-gate logs are present with real failure/pass tallies.

## Required changes

1. Enforce `max_files` while parsing, not after `tarfile.getmembers()` has already retained an
   attacker-controlled header list. Iterate the seekable tar lazily (`for member in archive` or an
   equivalent bounded seam), increment the all-header count immediately, and stop at
   `max_files + 1`; retain at most the bounded plan needed by extraction. Do not switch to an
   extraction mode that weakens the complete preflight-before-write boundary. Add an instrumented
   iterator proving no header after the first over-limit member is parsed, plus exact-limit and
   directory-header overflow materializer cases.
2. Retain validated directory entries in the bounded extraction plan and materialize them as safe
   directories, including empty directories, without applying archive-controlled modes/ownership or
   adding directory entries to the file/symlink inventory. Handle explicit root/nested directories
   in either archive order: an already implicitly created parent is harmless, while a standalone
   `root/empty/` must exist in the completed source root. Adjust the top-level-member fence so a
   root directory header is valid but a root file/symlink remains invalid. Add full materialization
   tests for empty root/nested directories and deterministic inventory exclusion.
3. Complete the no-clobber regression fence while the seam is in scope: the early-existing-empty
   destination test must assert zero transport calls; the final-race test must separately create an
   empty destination (no sentinel), delegate to the real `_rename_without_replace`, and prove its
   inode survives; and an unavailable/unsupported `renameat2` result must fail closed without a
   rename fallback or destination output. Keep the existing nonempty sentinel case.
4. Add tests first and preserve genuine round-14 red/green logs. Run focused tests and the complete
   quality gate, record exact exit/tallies, keep `security-verdicts.json` unchanged, commit only this
   Task-4A correction, leave the tree clean, recreate the completion marker, and stop for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
