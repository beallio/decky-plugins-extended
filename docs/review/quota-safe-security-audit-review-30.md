# Review — quota-safe-security-audit (round 30)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Task 3B's execution core is directionally sound, and the complete project gate
is green. Changes are still required before acceptance because worker option
presence is not fully fail-closed, the prepared-error fast path can probe
scanner executables before returning, and several mandatory adversarial tests
were replaced by weaker seam-level coverage.

Stay on **Task 3B only**. Fix and prove the items below; do not begin Task 5 or
edit workflows.

## Gate status

- Reviewed HEAD: `ca528a3f9d029ffc0e4de6db46b507105a37cf75`.
- Worktree was clean; the round marker was valid for that HEAD; the implementer
  session had exited.
- Root complete gate passed: actionlint `1.7.12` plus all three mutation
  controls, Ruff check/format, and `867 passed, 63 subtests passed`. Transcript:
  `/tmp/decky-plugins-extended/root-review-task3b-round29-full.log`.
- Terra focused reviews passed `386 passed, 45 subtests passed`, `357 passed,
  38 subtests passed`, and `131 passed`; focused Ruff was clean.
- The implementer red log is genuine pre-feature evidence and the focused green
  log reports `389 passed, 38 subtests passed`, but no round-29 full-gate or
  actionlint transcript was supplied.
- `security-verdicts.json` checksum remained
  `d9a53408619078ec2ffb9175b7fbec1e5cbbf523e69579d3647f8c04af76a4d7`.

## Required changes

1. Reject prohibited options by **presence**, including empty values.
   - `--worklist ... --base-ref ""` currently bypasses the truthiness check at
     `audit_plugins.py:6162`. Track whether `--base-ref` was supplied and reject
     it in worker mode regardless of its value.
   - `--all --expected-worklist-fingerprint ""` similarly bypasses the check at
     `audit_plugins.py:6154`. Reject the fingerprint option outside worklist
     mode whenever it was supplied, even when empty; reject an empty value as
     missing/invalid inside worker mode.
   - A bare `--aggregate-verdict-deltas` parses as the default-equivalent empty
     list and bypasses `audit_plugins.py:6168`. Use a distinct unsupplied default
     before later normalization and reject explicit presence in worker mode.
   - Audit the other producer/local/aggregate worker conflicts for the same
     presence-versus-truthiness mistake. Add parameterized parser regressions
     for all prohibited options, including empty-valued forms, and assert that
     no report, progress, delta, or manifest output is created.

2. Make prepared source-resolution errors a true no-work fast path.
   - `audit_release()` currently calls `_scanner_runtime_identities()` at
     `audit_plugins.py:4818` before checking the prepared error at line 4828.
     With enabled scanners, that helper probes executables and invokes version
     subprocesses. Return the identity-complete release-local error before any
     artifact download, source materialization, scanner identity/version probe,
     or scanner execution. An incomplete source-resolution error does not need
     a scanner-derived resumable audit-context identity.
   - Add raising sentinels for `_scanner_runtime_identities`, `download_zip`,
     source materialization, and scanner/source-diff entry points in the direct
     prepared-error contract test. Retain bounded/redacted detail and truthful
     digest-based `CURRENT` versus unknown identity behavior.

3. Add the missing end-to-end prepared-error worker contract.
   - Run worker `main()` over an ordered worklist containing a prepared
     source-resolution error and a safe prepared-commit sibling. Prove the
     error performs no artifact/source/scanner work, the sibling still audits,
     both reports/progress identities are checkpointed, assigned/attempted/
     report manifest identities are exact and ordered, only the successful
     sibling enters the verdict delta, and final exit precedence is `4`.
   - Cover a bounded/redacted prepared error at the closest pre-validation unit
     boundary; the immutable worklist integration should continue to accept
     only its canonical error forms.

4. Replace the mocked-materializer isolation proof with the required real
   acquisition boundary.
   - `test_worker_mode_real_prepared_audit_reuses_one_source_snapshot` currently
     replaces `materialize_source_snapshot()` and `run_trivy()`. It proves
     routing, but it can pass if codeload transport/extraction or scanner
     invocation regresses.
   - Preserve all eight raising discovery/REST/ref sentinels, `--skip-cache`,
     and an uncached eligible release. Feed deterministic tar.gz bytes through
     the fake codeload session used by the production materializer, allow the
     real bounded materialization/extraction code to run, and assert exactly
     one codeload GET/materialization. Exercise source-aware Trivy with a fake
     executable/process response and the real source/artifact-diff adapter (or
     an equivalently strong fake-executable boundary), asserting both consume
     that one extracted snapshot. No network or real scanner may run.

5. Complete resume, sharding, and checkpoint-failure integration coverage.
   - Add worker reruns with v1/missing, malformed, and mismatched-fingerprint
     progress. Prove stale progress is ignored, the audit reruns with the
     prepared commit, v2 fingerprinted progress replaces it, and every
     discovery/REST/ref resolver remains a raising sentinel.
   - Add a multi-item/multi-shard worker integration proving
     `audit_worklist.select_worklist_shard()` selection and canonical source
     order flow into execution and every manifest identity list. Include a
     genuinely unassigned shard from a nonempty worklist, not only a globally
     empty worklist.
   - Strengthen the atomic manifest failure test to two assigned releases: let
     the first checkpoint succeed, fail the second manifest write, assert exit
     `1`, and prove the prior publishable manifest/report checkpoint remains
     intact. A first-write-only failure does not prove safe sibling
     preservation.

6. Preserve verification evidence for this correction round.
   - Record focused red/green output for the presence bug, prepared-error
     scanner probe, and each strengthened adversarial integration case under
     `/tmp/decky-plugins-extended/`.
   - Rerun the complete quality gate and preserve the transcript, including
     actionlint mutations, Ruff check/format, all Pytest tests/subtests, and the
     unchanged verdict checksum.

STATUS: CHANGES_REQUESTED
