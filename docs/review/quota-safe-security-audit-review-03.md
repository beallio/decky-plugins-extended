# Review — quota-safe-security-audit (round 03)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on the Task 2 foundation. The new module is a useful start and its focused
unit suite is green, but the producer's public CLI is currently impossible to invoke and several
required corpus contracts are either rejected or under-validated. This round remains limited to
correcting and proving the immutable-worklist foundation; do not begin workers or Tasks 3–9.

## Gate status

- `uv run pytest -q tests/test_audit_worklist.py`: `65 passed in 0.44s`.
- `uv run ruff check audit_worklist.py audit_plugins.py tests/test_audit_worklist.py`: passed in
  the independent focused review.
- Executing the documented producer with both `--prepare-worklist` and `--all` exits 2 in argparse:
  `argument --all: not allowed with argument --prepare-worklist`. The producer cannot run.
- `git diff --check dev...HEAD`: passed; `security-verdicts.json` is unchanged and the tree was
  clean at `88c8892b61c647bc107cd8fc9e5cf03bd7371931`.
- No durable genuine-red log or complete repository quality-gate transcript was produced for this
  slice, so those process requirements remain open.

## Required changes

1. Repair and test the executable CLI contract. `--prepare-worklist PATH` must be orthogonal to a
   required selector (`--all`, `--changed --base-ref REF`, `--repository URL`, optionally with
   `--latest-only`); reject missing, conflicting, or invalid combinations. Add subprocess/main-level
   tests covering every valid shape and the important invalid shapes. On success stdout must be
   exactly one `worklist_fingerprint=<64-lowercase-hex>` line, diagnostics must use stderr, and the
   producer must not write `$GITHUB_OUTPUT` itself or enter any release scan path.
2. Preserve the planned corpus semantics. A missing GitHub asset digest is valid and must round-trip
   in one canonical nullable representation; if present, the digest must remain strict. Implement
   the explicit `none` mode with zero repositories/items, and make an empty changed selection emit
   it. Require exactly one repository in `repository` mode; reject empty selected repositories in
   other modes and all items outside the canonical selected repository list.
3. Make loaded documents strictly canonical, rather than accepting values that normalize into a
   different identity. Require a lowercase 40-hex `source_revision`, the resolved base commit when
   applicable, canonical positive integer IDs and shard count without bool/float/string aliases,
   real booleans, eligible non-draft ZIP assets, exact repository/asset ownership, consistent
   commit-versus-redacted-error fields, valid timestamps, and global repository-then-release item
   ordering. Validate selected repository metadata identity before producing an item. Add focused
   rejection tests for every invariant.
4. Prove the fingerprint binds the complete canonical payload: mutate each bound field family and
   item field in an otherwise valid document, recompute neither fingerprint nor bytes, and assert
   rejection; also assert independently prepared semantic changes alter canonical bytes and the
   fingerprint. Do not limit tamper tests to editing only the declared fingerprint.
5. Complete the tag-resolution and producer failure contracts. Reject identical as well as
   conflicting duplicate `ls-remote` records; cover lightweight and annotated ordering, exact tag
   names, invalid SHAs, timeout, nonzero status, and `OSError`, and assert the exact argv/no-shell
   transport. Assert one metadata call, one release enumeration, and one tag transport per selected
   repository, no scanner call, and no output if a later repository fails. A failed preparation
   must invalidate/remove a pre-existing target so no prior worklist remains usable; test both a
   new and pre-existing target.
6. Add the missing genuine-red evidence under `/tmp/decky-plugins-extended/` for these corrections,
   then run the corrected focused suite and the complete repository quality gate. Record exact
   commands/results in the implementation handoff, keep `security-verdicts.json` unchanged, commit
   the corrections, leave the tree clean, and recreate the round-complete marker. Stop after this
   foundation correction.

STATUS: CHANGES_REQUESTED
