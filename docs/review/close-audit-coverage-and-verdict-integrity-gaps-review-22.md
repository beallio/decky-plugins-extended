# Review — close-audit-coverage-and-verdict-integrity-gaps (round 22)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. The round-21 live pass was stopped after a read-only
checkpoint inspection proved the corrected probe still keys physical downloads
by repository/tag/commit and leaves cumulative telemetry at zero. Fix and prove
the probe invariants before starting another live pass.

## Gate status

- Reviewed baseline: `0dd6649277fd8384934251bb3840e3db92419772` plus the
  committed round-21 review note at `efaec86`.
- The round-21 supervisor and implementer were stopped without a marker after
  the live defect was confirmed. The feature worktree retains the implementer's
  partial proof/test edits and untracked transient probe for safe continuation.
- Preserved flawed-pass checkpoint at inspection time: 320 mapped releases,
  311 unique repository/commit identities, 9 redundant alias downloads,
  1,287,183,606 physically downloaded bytes, zero errors, zero limit
  violations, and live cumulative telemetry fields still reporting zero.
- The checkpoint was advancing, so the stop was deliberate to prevent wasting
  the remaining downloads on invalid evidence.

## Required changes

1. Treat the current uncommitted proof/test/probe files as partial implementer
   work. Do not commit the incomplete proof. Keep useful edits, correct them in
   place, and remove the transient root-level
   `source_archive_inventory_probe.py` before the final commit.
2. Key physical source measurements strictly by canonical
   `(repository, resolved_commit_sha)`. Release tag and release ID belong only
   to release-to-source mappings. After freshly resolving a tag, reuse an
   existing matching repository/commit measurement without another bounded
   download; count it as a duplicate alias, not a physical success.
3. Persist cumulative API/helper-call, bounded-download, error, limit, byte, and
   start/end timing telemetry atomically in the checkpoint as work occurs.
   Once any download completes, the corresponding cumulative request/download
   and physical-byte fields must be nonzero and must survive process resumes.
4. Before live work, add/run a hermetic preflight for two distinct release
   IDs/tags that resolve to one repository/commit. It must prove two release
   mappings, one unique physical stream, one alias, one physical byte count,
   correct mapped-release bytes, and preserved counters after checkpoint reload.
5. Add invariant checks on every checkpoint write and before proof generation:
   physical successes equal unique measured repository/commit records; mapped
   releases equal unique mappings plus aliases; physical bytes equal the sum of
   unique records; mapped-release bytes equal the sum over release mappings;
   every mapping references one measured unique record; actual release IDs are
   nonempty and never substituted with tags; error/limit/request counters agree
   with detail records. Fail immediately on divergence.
6. Discard the flawed live checkpoint and begin the corrected live run from a
   new empty checkpoint only after the preflight passes. Add an early live
   self-check before 25 mapped releases and abort if physical downloads differ
   from unique repository/commit measurements or telemetry remains zero. Then
   complete the same source-only bounded inventory from round 21. Do not resume
   the flawed checkpoint, run the full audit, extract/scan archives, or change
   limits.
7. Generate and commit the corrected durable proof and strengthened
   documentation validation only after all round-21 requirements and the new
   invariants pass. Keep warm and hosted-runner validation deferred.
8. Run focused evidence/documentation tests and the complete quality gate,
   commit the atomic correction, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
