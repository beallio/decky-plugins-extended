# Review — quota-safe-security-audit (round 32)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Prepared-error redaction and truthful identity fallback are accepted. The
ordinary `OSError` rollback test is also genuine, but best-effort multi-file
rollback cannot provide the required fail-closed publication boundary: process
interruption skips it, a rollback failure leaves a mixed generation, and the
current cleanup then deletes the remaining recovery backups. Replace rollback
with a manifest-last, hash-bound commit record.

This is the final **Task 3B publication correction**. Do not begin Task 5's
aggregate CLI or edit workflows; add only the manifest artifact-binding
primitive that Task 5 will consume later.

## Gate status

- Reviewed HEAD: `b11e9cf686068102963ae749f4cc07098b30684a`.
- Worktree was clean; the marker was valid for that HEAD; no implementer
  session remained active.
- Root complete gate passed independently: actionlint `1.7.12` and all three
  mutation controls, Ruff check/format, and `886 passed, 63 subtests passed` in
  `/tmp/decky-plugins-extended/root-review-task3b-round31-full.log`.
- Terra focused reviews passed `405 passed, 45 subtests passed`, `376 passed,
  38 subtests passed`, and `187 passed`; focused Ruff was clean.
- Round-31 red/green and the redaction mutation control are genuine. The
  implementer omitted its requested complete-gate transcript; root supplied
  the complete gate above.
- `security-verdicts.json` checksum remained
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

## Required changes

1. Make `shard-manifest.json` v2 the single atomic commit record.
   - Keep all existing worklist/assignment/attempt/report fields, and add a
     strict `artifacts` object with exactly `progress`, `report_json`,
     `report_markdown`, and `verdict_delta`. Each entry must contain exactly a
     lowercase SHA-256 of the final bytes and nonnegative `size_bytes`.
     Reject malformed, missing, extra, noncanonical, or duplicate schema data
     in normalization/loading. Do not place absolute paths in the manifest.
   - Update the Task 3A manifest constructors/helpers/tests to schema version
     `2`. Provide a reusable verifier that streams/reads each caller-supplied
     artifact, checks size and digest before parsing or trusting it, and fails
     closed with bounded diagnostics. Task 5 will use this primitive for its
     supplied report/delta paths in a later round; do not implement its CLI now.

2. Publish data first and the manifest last; remove multi-file rollback.
   - Fully generate and validate the four data files in staging. Copy each to a
     target-local temporary file so custom progress/delta paths remain usable
     across filesystems. Atomically replace the four visible data targets
     first, then atomically replace the manifest **last** after its artifact
     hashes describe exactly those final bytes. Fsync each file before rename
     and its containing directory after rename, especially the final manifest
     commit.
   - Do not roll data files back. An `OSError`, `BaseException`, cancellation,
     or process death before manifest replacement must leave the old or absent
     manifest as the only commit record. Its artifact hashes then make any
     partially promoted data non-publishable rather than falsely current. A
     completed manifest replacement must verify the complete new generation.
   - Clean unpromoted temporary files without deleting committed files or the
     prior manifest. Remove the backup/rollback implementation and its
     rollback-error path.

3. Manifest-gate worker resume now.
   - Before trusting v2 progress, load the existing v2 shard manifest and
     verify all four supplied worker artifact paths against its byte size/hash
     bindings. Only a fully verified generation may provide resumable progress.
     A missing/old/malformed manifest, missing file, or any size/hash mismatch
     must ignore progress and re-audit from the prepared worklist without
     discovery/REST/ref resolution. Do not parse unverified progress first.
   - Keep first-run and valid empty-shard behavior. A failed first checkpoint
     has no valid committed generation and remains run-global exit `1`.

4. Reject output aliasing before staging or creating outputs.
   - Resolve the worker's progress, report JSON, report Markdown, delta, and
     manifest targets canonically and require five distinct paths. Also reject
     any target that aliases the validated worklist input. Handle existing
     symlinks safely. Alias failure is run-global exit `1` with no output
     mutation.

5. Add adversarial publication tests.
   - Inject ordinary replacement failure and a `BaseException`/simulated
     interruption after each of the four data-file replacements. Assert the
     prior manifest remains byte-identical and both the reusable verifier and
     worker resume reject the mixed generation; all forbidden discovery/REST/
     ref seams remain raising sentinels.
   - Cover failure before the first manifest (no valid generation), successful
     final manifest publication with custom progress/delta directories, and
     exact v2 hashes/sizes for all four artifacts.
   - Swap/tamper each artifact independently and prove verification fails
     before progress parsing or later coverage/verdict work. Cover malformed
     artifact bindings and duplicate/aliased target paths, including a target
     colliding with the worklist.
   - Replace the old rollback-success test with these commit-record contracts;
     it no longer represents the design.

6. Record focused red/green and a genuine production mutation that removes or
   misorders the manifest-last/hash check. Rerun the complete gate and preserve
   actionlint mutations, Ruff check/format, all Pytest tests/subtests, clean
   worktree, and unchanged verdict checksum.

STATUS: CHANGES_REQUESTED
