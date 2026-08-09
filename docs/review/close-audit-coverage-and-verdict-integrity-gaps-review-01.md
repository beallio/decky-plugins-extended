# Review — close-audit-coverage-and-verdict-integrity-gaps (round 01)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

The baseline is mechanically green, but URL canonicalization remains bypassable after percent
decoding. This round is intentionally atomic: fix only the decoded-path validation boundary and
its repository/release-asset regressions.

## Gate status

- Reviewed commit: `0eb1962d22408293a46c96e888b2398495064bd9`
- Round marker: valid and stamped with the reviewed commit
- Working tree: clean before this orchestrator-authored review note
- `scripts/orchestration/run-quality-gates`: passed
- `actionlint 1.7.12`: passed, including syntax/expression/dependency mutations
- Ruff and format checks: passed
- Pytest: `528 passed, 35 subtests passed`

## Required changes

### Atomic slice 1 — reject decoded GitHub URL delimiters and traversal atoms

`plugin_release_utils.py` rejects literal query/fragment components and raw `%2f`/`%5c`, but it
decodes owner/repository segments and then serializes them without rejecting decoded URL
delimiters, residual percent escapes, dot segments, or control characters. The current parser can
therefore accept and canonicalize hostile inputs such as:

- `https://github.com/owner/repo%3Fquery` into a URL containing `?query`;
- `https://github.com/owner/repo%23fragment` into a URL containing `#fragment`;
- `https://github.com/owner/repo%252Fextra` into a residual encoded separator;
- `https://github.com/%2E%2E/repo` into a parent-path atom.

Required implementation:

1. After exactly one percent-decoding pass, validate both owner and repository as non-empty GitHub
   path atoms. Reject `.` and `..`, control characters, residual `%`, `?`, `#`, `/`, and `\`.
2. Apply the same decoded-atom validation to repository URLs and GitHub release-asset URLs so the
   two parsers cannot diverge.
3. Preserve the accepted canonical forms already covered by the plan, including the two configured
   repository URLs with one trailing slash.
4. Add focused regressions for all four examples above through both repository parsing and
   release-asset parsing. Assert rejection occurs before any request or downstream URL use.
5. Run the focused release-utility tests, then the full orchestration quality gate. Record exact
   pass totals in the round summary and leave the tree clean and committed before marking finished.

Do not address the remaining review inventory in this round; the orchestrator will issue the next
atomic slice only after reviewing this one.

STATUS: CHANGES_REQUESTED
