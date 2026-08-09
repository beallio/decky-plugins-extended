# Review — close-audit-coverage-and-verdict-integrity-gaps (round 21)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. Round 20 measured complete in-limit source coverage, but the
durable proof mixes physical downloads with cached release aliases and records
only the final resume pass's telemetry. Correct the transient probe and rerun
the source-only inventory from an empty checkpoint so the finalization evidence
is internally auditable.

## Gate status

- Reviewed commit: `0dd6649277fd8384934251bb3840e3db92419772`.
- The round-complete marker is valid and the feature worktree is clean.
- The complete local quality gate passed with `645 passed, 61 subtests passed`;
  focused documentation tests passed (`5 passed`).
- The retained measurements cover 579 unique release keys mapped to 555 unique
  repository/commit archives, with 24 aliases, zero errors, zero over-limit
  records, and maximum size 102,881,863 bytes. The sizes/mappings and evidence
  digests reproduce.
- The proof is nevertheless insufficient: `successful_download_count` reports
  579 rather than 555 physical streams, request count is zero, elapsed time is
  only the 14.63-second resume pass, mapped-release bytes are presented as
  physical streamed bytes, the recorded connect timeout is 30 seconds rather
  than the effective 10 seconds, and 305 release-ID fields contain tags.

## Required changes

1. Correct the transient `/tmp` inventory probe so checkpoint loading rejects a
   mismatched reviewed commit and policy identity. Fresh enumeration must retain
   the actual GitHub release ID separately from the tag.
2. On every run, re-resolve every freshly enumerated release tag to its exact
   commit before accepting any checkpointed size measurement. A cached
   measurement is reusable only after the fresh repository/tag/commit identity
   exactly matches its checkpoint identity.
3. Persist cumulative telemetry in the checkpoint across resumes: production
   helper/API request counts, physical bounded-download calls/successes/errors,
   limit violations, bytes physically streamed, mapped-release bytes, original
   start time, final end time, and full elapsed duration. Record the effective
   values returned by `load_policy()` rather than probe defaults.
4. Delete the prior checkpoint and rerun the corrected source-only probe from an
   empty checkpoint at the reviewed marker. Continue to use
   `bounded_stream_download(kind="source", policy=load_policy())`, delete each
   archive immediately, and do not extract, scan, generate cache/verdict/catalog
   state, change limits, or run the full audit.
5. Replace/correct the durable proof so it distinctly records and reconciles:
   579 release mappings, 555 unique physical streams, 24 duplicate aliases,
   physical streamed bytes, mapped-release bytes, effective policy fields,
   cumulative API/helper-call/error counts, full elapsed time, actual release
   IDs, exact fresh tag-to-commit mappings, and the existing redacted integrity
   hashes/checksums. All counts must be mechanically derivable from the detail
   records.
6. Strengthen the documentation test to open and validate the proof itself:
   reviewed commit, policy checksum/values, release and unique-stream counts,
   mapping coverage, errors/violations, request/download telemetry, digests, and
   plan/projection linkage. Fix the projection to reference the successful proof
   with evidence fields that actually exist rather than a stale blocker field.
7. Close the source-inventory gate only when the corrected empty-checkpoint run
   proves full zero-error, zero-over-limit coverage. Keep warm and hosted-runner
   validation deferred.
8. Run focused evidence/documentation tests and the complete quality gate,
   commit the atomic correction, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
