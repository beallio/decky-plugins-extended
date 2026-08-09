# Review — close-audit-coverage-and-verdict-integrity-gaps (round 02)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 1 is approved at the reviewer level: decoded repository/release-asset atoms now reject
the identified delimiter, residual-escape, and traversal forms without regressing accepted URLs.
The whole plan still requires changes. This round owns only release-local archive exception
isolation.

## Gate status

- Reviewed commit: `0e3bca343098966d42418c6d9bc118f8c2a2480d`
- Round marker: valid and stamped with the reviewed commit
- Focused release-utility tests: `101 passed`
- Full quality gate: `534 passed, 35 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 2 — keep archive inspection failures release-local

`audit_release()` invokes archive inspection without converting expected unreadable/corrupt archive
exceptions into a completed release-local `AUDIT_ERROR`, and the worklist loop does not isolate an
exception escaping one release. An `OSError` or equivalent archive-read failure can therefore abort
the process, prevent later releases from running, suppress their checkpoints/verdict deltas, and
produce exit 1 rather than publishable exit 4.

Required implementation:

1. Convert expected download/archive-open/read/inspection failures for one release into an
   identity-complete `AuditReport` classified `AUDIT_ERROR`. Preserve repository, tag, release ID,
   asset ID/URL, current artifact hash when known, source identity when known, scanner/error status,
   and a redacted diagnostic.
2. Add a defensive per-release isolation boundary in worklist execution so an expected
   release-local failure cannot stop later work items. Do not catch invalid policy, verdict-store,
   progress-store, aggregation, or output-integrity failures; those remain run-global exit 1.
3. Preserve a prior durable completed verdict for the failed release. First-seen errors create a
   report/checkpoint outcome but no durable verdict. Successful siblings must still checkpoint and
   emit publishable verdict deltas.
4. Add a mixed-worklist regression where release A raises `OSError("unreadable archive")`, release B
   completes successfully, and A already has a durable verdict. Assert B runs and publishes, A's
   verdict is byte-for-byte unchanged, the error report is retained, and the aggregate CLI outcome
   is exit 4 rather than exit 1.
5. Add a negative control proving a run-global integrity error still aborts without publishing safe
   outputs.
6. Run the focused worklist/verdict tests and the full orchestration quality gate. Record exact pass
   totals, commit the atomic slice, leave the tree clean, and mark the round finished.

Do not address any other review inventory item in this round.

STATUS: CHANGES_REQUESTED
