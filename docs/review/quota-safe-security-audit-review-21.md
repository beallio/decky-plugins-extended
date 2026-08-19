# Review — quota-safe-security-audit (round 21)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 4B1 production behavior is accepted. Complete three test-only regression fences before
closing the slice: captured-root fast-path isolation, genuine final/ancestor symlink races, and
nested descriptor cleanup. Do not change production code and do not begin Task 4B2.

## Gate status

- Commit reviewed: `8f59173ff1c09830728f78369e63a01cbc963263`; tree clean, marker
  valid, implementer session absent, and `security-verdicts.json` unchanged.
- Root focused audit-plugin suite: `226 passed, 36 subtests passed`.
- Root complete quality gate: actionlint mutation controls passed, Ruff check/format clean, and
  `864 passed, 61 subtests passed`.
- Root and both Terra reviewers found no remaining Task-4B1 production defect. Hash/CRLF equality
  now short-circuits before metadata access; mismatch-only reads are bounded, descriptor-relative,
  no-follow, regular-only, inventory-bound, and cleanup-protected; both adapters remain API-free.
- The current final-component test starts with a symlink and replaces it with another symlink, the
  lifecycle cases are root-only, and the root fast-path test supplies valid captured bytes. Those
  tests do not fully prove their names/contracts.
- The requested round-20 implementer red/green/quality logs were not preserved despite exact paths;
  root independent focused/full logs are green. Record this process gap and do not fabricate it.

## Required changes

1. Add an exact-hash root `plugin.json` case whose `snapshot.plugin_json` is deliberately invalid
   versus the inventory, and prove the comparison still passes because captured bytes are never
   acquired or validated on the hash fast path. Retain mismatch cases that fail closed.
2. Correct the final-component race test so the inventory-matching `plugin.json` is initially a
   regular file. Inside the patched final `os.open` seam, replace that regular file with a symlink
   immediately before delegating to the real `os.open`; assert fail-closed. Add the analogous
   ancestor race for a nested metadata path by replacing an initially real intermediate directory
   with a symlink at its `os.open` seam. Preserve and clean all displaced test fixtures.
3. Convert the success and inventory-validation-failure FD lifecycle tests to a nested metadata
   path. Assert the root, ancestor directory, and final file descriptors are each opened once and
   closed exactly once in reverse order on both paths; do not rely only on set equality.
4. Because production behavior is already correct, do not invent a red phase. Preserve a distinct
   focused green log at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b1-round21-green.log` and full gate at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-task4b1-round21-quality.log`, recording
   exact tallies. Commit only focused test changes and the review response; keep
   `security-verdicts.json` unchanged, leave the tree clean, recreate the completion marker, and
   stop for review.

Still deferred: all Task-4B2 cache/source orchestration, Task-4B3 legacy removal, Task-3B worker
integration, aggregation, workflows, scanner bootstrap, and documentation.

STATUS: CHANGES_REQUESTED
