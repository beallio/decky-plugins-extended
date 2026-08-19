# Review — quota-safe-security-audit (round 33)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

The Task 3B manifest-last implementation is accepted in architecture and
runtime behavior. One final test/evidence-only correction is required before
this task can be closed: explicitly fence first-generation interruption and the
full alias matrix, and expose the artifact verifier at the per-artifact
granularity Task 5 can consume later.

Per the user's stop instruction, complete **only these Task 3B closure items**.
Do not begin Task 5 or any later plan task.

## Gate status

- Reviewed HEAD: `e740a3341c9a73aea3701f7364da97eac11868dc`.
- Worktree was clean; the marker was valid for that HEAD; no implementer
  session remained active.
- Terra runtime/architecture reviews accepted manifest v2, manifest-last
  ordering, target-local staging/fsync, resume gating, and no-API recovery.
  Focused runs passed `464 passed, 45 subtests passed` and `435 passed,
  38 subtests passed`; current Ruff check/format were clean.
- Focused red/green and the progress-before-verification production mutation
  are genuine. The saved round-32 format log is a pre-format failure, and no
  complete-gate transcript was supplied.
- `security-verdicts.json` checksum remained
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

## Required changes

1. Add a first-generation interruption contract.
   - Start with no prior report/progress/delta/manifest generation, inject both
     an ordinary `OSError` and a `BaseException` after a data-file replacement
     but before the first manifest commit, and prove no valid manifest exists.
   - On the next worker invocation, prove any partial progress is ignored,
     prepared work is re-audited, a valid v2 generation replaces the partial
     files, and every discovery/REST/ref seam remains a raising sentinel.

2. Fence target aliasing generically rather than through one duplicate pair.
   - Unit-test `_resolve_worker_output_targets()` across every pair among the
     five output targets, plus each target against the worklist path and an
     existing symlink alias. Every case must fail before mutation. Retain a CLI
     no-output control. This prevents future target additions/reordering from
     escaping the current generic distinct-path implementation.

3. Factor a strict single-artifact verification primitive.
   - Task 5 receives report and delta paths, not worker progress/Markdown CLI
     arguments. Add a reusable verifier for one named manifest binding and have
     the all-four worker verifier call it. It must validate the normalized v2
     manifest, reject unknown names, and compare size and SHA-256 before the
     caller parses the artifact.
   - Add focused report-json and verdict-delta controls proving the single-file
     primitive succeeds for exact bytes and rejects swapped/tampered bytes.
     Do not implement Task 5 aggregation in this round.

4. Save genuine focused red/green evidence and run the complete project gate,
   including actionlint mutations, Ruff check/format, all Pytest tests/subtests,
   clean worktree, and unchanged verdict checksum. Do not cite the earlier
   pre-format failure as green.

STATUS: CHANGES_REQUESTED
