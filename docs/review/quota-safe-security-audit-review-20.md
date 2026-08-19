# Review — quota-safe-security-audit (round 20)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B1 has one remaining ordering regression plus two test-fidelity gaps. Restore the hash-only
fast path before metadata acquisition, make the bounded-read test exercise the real FD path, and
prove descriptor cleanup. Do not begin Task 4B2.

## Gate status

- Commit reviewed: `56282c1d46b216720820a02564ae2b42499f1c77`; tree clean, marker
  valid, implementer session absent, and `security-verdicts.json` unchanged.
- Root focused audit-plugin suite: `223 passed, 36 subtests passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `861 passed, 61 subtests passed`.
- Descriptor-relative traversal now validates canonical paths before access, opens root/ancestors/
  final node with no-follow semantics, requires a regular final inode, bounds the read, verifies
  inventory size/hash, and closes tracked descriptors in `finally`.
- Both Terra reviews found that metadata acquisition now happens before exact/CRLF hash checks.
  They also found that the bounded-read regression patches `builtins.open`, while production now
  reads via `os.open`/`os.fdopen`, so that test no longer observes the read.
- Round-19 root green logs exist, but the requested genuine implementer red log was not preserved.
  Do not fabricate or relabel it.

## Required changes

1. In `compare_source_and_artifact_from_snapshot()`, compute the artifact Git blob SHA and the
   existing CRLF-normalized SHA immediately after locating the inventory entry. If either matches
   the inventory SHA, continue without acquiring, validating, opening, or reading captured/local
   metadata. Only a remaining `plugin.json`/`package.json` mismatch may obtain source bytes for
   build-stamp suppression. Preserve fail-closed size/hash validation when those bytes are used.
2. Add regressions proving byte-identical root and nested metadata pass without touching captured
   metadata or opening the local source file, including an unavailable nested file and deliberately
   invalid captured bytes. Retain cases proving a mismatching artifact fails closed when the
   captured or local metadata payload disagrees with its inventory entry.
3. Correct the bounded-read regression to instrument the actual production FD read path
   (`os.fdopen`/returned reader or a dedicated bounded FD-reader seam), and assert the main read is
   at most 1 MiB followed by at most the one-byte overflow probe. A future unbounded read must make
   this test fail.
4. Add descriptor-lifecycle coverage proving every FD opened by the helper is closed after both a
   successful nested read and representative failure after descriptors have opened. Replace the
   ineffective `os.lstat` patches in the symlink-swap tests with `os.open`-seam races, or rename
   those tests to honestly describe pre-existing symlink rejection and add a real final-component
   swap regression. Keep root/ancestor/final no-follow and FIFO fail-closed coverage.
5. Write the ordering and read-path tests first and preserve the genuine failing output at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b1-round20-red.log`. Preserve focused
   green at `...-round20-green.log` and the complete gate at `...-round20-quality.log`, with exact
   tallies. Keep the correction within `audit_plugins.py`, focused tests, and the review response;
   keep `security-verdicts.json` unchanged, leave the tree clean, recreate the completion marker,
   and stop for review.

Still deferred: all Task-4B2 cache/source orchestration, Task-4B3 legacy removal, Task-3B worker
integration, aggregation, workflows, scanner bootstrap, and documentation.

STATUS: CHANGES_REQUESTED
