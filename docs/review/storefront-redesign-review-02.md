# Review — storefront-redesign (round 02)

Branch: `feat/storefront-redesign`
Reviewed against: `docs/plans/2026-08-31_storefront-redesign.md`

## Verdict

Round 01 resolved the production audit envelope, recovery, accessibility,
responsive layout, centered-content test, and browser-cache findings. Two
identity mismatches remain before integration.

## Gate status

The orchestrator reran the full quality-gates hook successfully at marker SHA
`79f39f5472dae6241c54ec7b6a9f178e82f3f551`: actionlint and three mutations
passed, Ruff check/format passed, Node logic passed 11/11, Playwright passed 7/7
with refreshed desktop/mobile screenshots, and pytest passed 1,103 tests plus
66 subtests. The working tree was clean. Both remaining findings are semantic
identity gaps not exercised by those fixtures.

## Required changes

1. **Resolve case-insensitive merges without losing the producer identity.**
   `metadataPluginFor` compares the metadata display name and catalog display
   name with exact `===`. The generator merges plugin names
   case-insensitively but retains the existing catalog spelling, so official
   `Shared Plugin` plus configured contribution `shared plugin` loses
   provenance, source, audit matching, and Extended-filter membership. Publish
   and consume an unambiguous producer lookup identity, or otherwise preserve
   the generator's case-insensitive merge relationship without relying on
   JavaScript lowercasing for Python-casefolded Unicode keys. Add regressions
   for both ordinary case-only spelling differences and the existing Unicode
   `Straße` case.

2. **Keep audit tag identity case-preserving.** `normalizeVersionName`
   lowercases tags even though Python `normalize_version` preserves case.
   Case-distinct Git tags can therefore alias during exact audit matching and
   attach the wrong CURRENT/APPLIED audit record when artifact hashes coincide.
   Use a separate case-preserving audit-tag normalization path that matches the
   producer, while retaining case-insensitive behavior only where it is
   appropriate for search/version presentation. Add a fixture with
   case-distinct tags and prove only the exact metadata tag matches.

3. **Add version history to the plugin detail dialog.**
   Render every version from the selected catalog in a semantic table with
   Version, Released, Downloads, Updates, and Source columns. Do not include an
   Audit column. Preserve the existing per-version download and update counters
   during browser normalization, and resolve Source from the existing exact
   version metadata when available, with a clear official-catalog fallback.
   Keep the table usable on narrow screens and add Node and Playwright
   regressions for populated and zero-valued counters, source links, the
   official fallback, and the absence of an Audit column.

Re-run the Node and Playwright suites and the complete
`scripts/orchestration/run-quality-gates` hook. Record the final actionlint,
Ruff, Node, Playwright, and pytest tallies.

STATUS: CHANGES_REQUESTED
