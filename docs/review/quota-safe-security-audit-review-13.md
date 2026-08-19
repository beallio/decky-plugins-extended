# Review — quota-safe-security-audit (round 13)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on three remaining Task-4A safety defects and two missing end-to-end regression
fences. Round 12 fixed the metadata capture implementation and session-auth behavior, but promotion
still clobbers an empty destination and tar preflight is order-dependent and unbounded for directory
headers. Do not begin Task 4B or worker integration.

## Gate status

- Commit reviewed: `f74dff2d4d08e5e076fa02b6a75b6e8fd41948bb`; tree clean, marker valid,
  implementer session absent, and `security-verdicts.json` unchanged.
- Root focused run: `51 passed`. Root complete gate: actionlint mutations rejected, Ruff clean,
  `832 passed, 61 subtests passed`.
- Root and both Terra reviewers reproduced POSIX `os.rename()` replacing an existing empty
  destination directory. Root and Terra also reproduced a valid directory header following its
  child being rejected, and one regular file plus twelve directory headers passing `max_files=1`.
- Round-12 focused/quality logs are green, but no genuinely red, newly dated round-12 log exists.
  Preserve that fact; do not relabel or overwrite older evidence.

## Required changes

1. Implement a true atomic no-clobber directory promotion. `os.rename()` and `os.replace()` both
   replace an existing empty directory on Linux and are not acceptable. Restore an early destination
   existence rejection to avoid needless download, then use `renameat2(RENAME_NOREPLACE)` or an
   equivalently atomic no-replace primitive for the final race; fail closed with a typed
   `SourceSnapshotError` if the platform cannot provide the guarantee. Do not silently fall back to
   a check/rename sequence. Test an already-existing empty destination before download and a race
   that creates an empty destination inside the real promotion seam, delegates to the true primitive,
   and proves the same inode survives. Retain the independent nonempty-sentinel and cleanup cases.
2. Make directory ancestry order-independent. The graph rule is: exact identities conflict; for an
   existing ancestor of a candidate, reject only when the existing ancestor is a file/symlink; for a
   candidate ancestor of an existing member, reject only when the candidate is a file/symlink.
   Therefore `root/sub/file`, then explicit `root/sub/`, then `root/` is valid, while file/symlink
   ancestry remains invalid in either order. Add directory-before-child and directory-after-child
   materialization successes and keep file/symlink negatives.
3. Bound all tar headers, including directories, under the archive `max_files` member limit, matching
   the release ZIP inspector's fail-closed member-count semantics. Replace the current pairwise
   O(n-squared) path scan with an O(member-count times max-path-depth) prefix-set/trie check (or
   equivalent bounded algorithm). A tar with more than `max_files` directory headers plus one safe
   file must fail before extraction; add exact-limit and over-limit tests. Keep uncompressed byte
   accounting for file/symlink payloads and do not inventory/materialize directory metadata.
4. Add the two missing full-materializer regression fences: (a) oversized root metadata fails at the
   1 MiB cap and removes all staging/destination output without any unbounded read; (b) every
   file/symlink ancestry negative reaches a preflight sentinel and proves the extraction/write seam
   was never entered. Helper-only tests do not establish these lifecycle contracts.
5. Add the tests first and preserve a genuine round-13 assertion-failure log separately from the
   round-13 green log. Do not alter earlier logs. Run focused tests and the complete quality gate,
   record exact exit/tallies, keep `security-verdicts.json` unchanged, commit only this Task-4A
   correction, leave the tree clean, recreate the completion marker, and stop for review.

Still deferred: `audit_release()` and cache integration, Trivy/diff/raw metadata consumers,
source-failure classification, legacy helper removal, public worker CLI/API-isolation, aggregation,
and workflows.

STATUS: CHANGES_REQUESTED
