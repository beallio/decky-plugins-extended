# Review — quota-safe-security-audit (round 02)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Blocking process correction: two supervised continuation attempts consumed their turns rereading
the complete plan and source tree, then exited with no changes and no marker. The branch remains
clean at review round 1. This review narrows the next round to one atomic, independently testable
foundation slice; it does not reduce the final plan scope.

## Gate status

No new gate result exists because no implementation was produced. `git status --short` was clean,
HEAD remained `c251477`, and the implementer was stopped while still on
`feat/quota-safe-security-audit`, before any edit or finalization activity.

## Required changes

For this round only, implement the immutable worklist foundation below. Do not reread or attempt
Tasks 3–9 yet; later committed review notes will sequence those slices.

1. Add the failing focused tests in `tests/test_audit_worklist.py` for canonical worklist
   serialization/fingerprint stability, strict round-trip validation, tampered fingerprint,
   malformed/unknown/extra/missing fields, duplicate identities, deterministic ordering, valid
   empty selection, and producer failure leaving no partial worklist. Capture the slice's genuine
   red result under `/tmp/decky-plugins-extended/` before implementation.
2. Implement the focused `audit_worklist.py` module specified by Task 2: versioned canonical
   payload/root schema, strict normalized fields and eligibility/ownership validation, stable
   SHA-256 fingerprint, unique work identities, atomic write/load, and zero-item support. Keep this
   module acyclic and do not add scan execution to it.
3. Add the `audit_plugins.py --prepare-worklist PATH --source-revision SHA
   --api-deadline-seconds N` producer mode with the selectors and exact single-line stdout contract
   from Task 2. It must enumerate each selected repository exactly once, write only after complete
   repository enumeration, and never scan a release.
4. Resolve selected repository tags once per repository with argv-only
   `git ls-remote --tags`. Cover lightweight/annotated tags, exact tag names, malformed/duplicate
   output, timeout/nonzero transport failure, and individual missing/unusable tags. Repository-wide
   transport failure is run-global with no worklist; an individual unresolved tag is preserved as
   an identity-complete item carrying a release-local source-resolution error.
5. Run the focused new tests plus the pre-existing `tests/test_audit_worklist.py` suite, then the
   complete repository quality gate. Commit this foundation, keep `security-verdicts.json`
   unchanged, leave the tree clean, and recreate the round-complete marker. Stop after this slice;
   do not implement workers, source reuse, aggregation, workflow wiring, API-budget enforcement, or
   scanner bootstrap in this round.

STATUS: CHANGES_REQUESTED
