# Review — quota-safe-security-audit (round 06)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on one remaining base-object validation defect and its test/evidence cleanup. The
real GitHub digest and case-insensitive ZIP compatibility probes now pass. Do not start Task 3 in
this round.

## Gate status

- Root's full gate passed: actionlint plus mutation controls, Ruff check/format, and
  `723 passed, 61 subtests passed in 19.94s`.
- Genuine round-05 red evidence exists and its focused green suite passed 13 tests.
- Direct probes pass for `sha256:<hex>` normalization, uppercase hex, malformed-as-digestless, and
  `.ZIP` eligibility.
- `_resolve_base_ref_to_commit("HEAD^{tree}", 5)` incorrectly succeeds with tree object
  `dfee2adf6ff26197eb2b748c9c1aaa9c2eddc150`. The command appends `^{}` rather than the required
  `^{commit}`.
- The common `_with_digest()` fixture was changed to write a bare hash. Seventeen producer fixtures
  therefore now exercise digestless normalization instead of the API-shaped digest-backed path.
- The round-05 green log contains only the focused 13-test output, not the requested full-gate
  transcript. The tree is clean, the marker is valid at `c3ef288dbb70b63c753cfec966ac5b82dbecd692`,
  and `security-verdicts.json` is unchanged.

## Required changes

1. Change the exact argv to verify `<base-ref>^{commit}`, not `<base-ref>^{}`. Retain
   `--verify --quiet --end-of-options` and the exact single-line lowercase output check. Add a real
   repository test proving `HEAD` resolves while `HEAD^{tree}` and a blob ref fail; keep the injected
   exact-argv test so a future weakening is visible.
2. Restore `_with_digest()` as the realistic API fixture (`sha256:<hex>`). Keep a separately named
   helper only where deliberately testing an invalid bare upstream digest. Assert the canonical
   round-trip fixture actually contains a non-null lowercase `asset_digest`, so broad worklist tests
   do not silently regress to the digestless path.
3. Run the focused tests and append the complete repository quality-gate output to
   `/tmp/decky-plugins-extended/quota-safe-security-audit-green.log`. Commit only this correction,
   preserve `security-verdicts.json`, leave the tree clean, recreate the marker, and stop after Task 2.

STATUS: CHANGES_REQUESTED
