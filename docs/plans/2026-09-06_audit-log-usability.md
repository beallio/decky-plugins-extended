# Plan: Make the audit log searchable and navigable (audit-log-usability)

## Context

`audit.html` is a 1.58 MB static page holding 1366 verdict cards across 101
repositories in one flat list, with no JavaScript at all. 99% of the bytes
(1,562,765 of 1,579,012) are the card list, including 10,928 repeated `<dt>`
labels. Finding one plugin means Ctrl+F through the whole document.

The ordering makes it worse. `_public_audit_records` sorts on
`(classification != "BLOCK", classification, repository, release)`, so with
**zero** BLOCK records today everything falls back to alphabetical order by
classification. The page opens with 27 `AUDIT_ERROR` cards, then 1257
`MANUAL_REVIEW`. A single plugin can dominate: `beallio/sdh-ludusavi` is 121
cards, `akazarenn/sdh-gamesync` 111, `hooandee/panel-de-control` 72.

Two of the four tiers that actually appear — `PASS_WITH_WARNINGS` (74 records)
and `AUDIT_ERROR` (27) — are never defined in the page's "What the tiers mean"
section, and `AUDIT_ERROR` is the first label a visitor meets.

The page is produced by `_render_audit_html()` (`generate_json.py:907`), a
Python f-string. Adding search or collapsing to it would mean emitting
JavaScript from inside that f-string.

**Slug:** `audit-log-usability`

## Approach

`audit.json` already exists, is already published beside the page, already
carries every field the HTML renders plus `enforcement_mode`, and is already
fetched by the storefront (`static/storefront.js:705`) for the detail pane. So
the page does not need to bake its records into HTML at all.

Replace the generated page with a static shell in `static/` that renders from
`audit.json` in the browser. That drops the HTML from 1.58 MB to a few KB, puts
the page on the same footing as `index.html`, and turns search, collapsing and
deep-linking into ordinary DOM work.

## Non-goals

- Changing what the audit publishes. The field whitelist in
  `_public_audit_records` stays exactly as it is.
- Summarising releases away. Per-release hashes are the point of the audit;
  they move behind a disclosure, they do not get collapsed into "121 releases,
  same rules".
- Restyling the storefront. The audit page adopts `storefront.css` tokens, it
  does not change them.

---

## Phase 1 — Client-side render, grouped by plugin

The enabling change. Ships on its own.

1. Add `static/audit.html`: the existing prose (intro, tier explanations,
   policy) plus an empty results container, a status region, and a
   `<script type="module" src="audit.js">`. `copy_static_files()` already
   copies everything in `static/`, so no generator change is needed to publish
   it.
2. Add `static/audit.js`, importing shared helpers from `storefront.js` where
   they already exist rather than duplicating them.
3. Group records by repository. Render one row per plugin carrying its worst
   classification, its release count, and a `<details>` disclosure holding the
   per-release cards. Keep the existing BLOCK-first ordering at the group
   level, so a blocked plugin still sorts to the top.
4. Give each group a stable `id` derived from the repository slug — this is
   what Phase 3 links to.
5. Add a one-line summary header above the list, counted from the data:
   `0 blocked · 27 could not be audited · 1257 need review · 101 plugins`.
6. Define `PASS_WITH_WARNINGS` and `AUDIT_ERROR` in the tier section.
7. Delete `_render_audit_html()` and its call site; keep `write_audit_outputs`
   writing `audit.json`.

## Phase 2 — Search and filters

8. A search box filtering groups by plugin name and repository slug, matching
   the storefront's control markup so the two pages feel like one product.
9. A classification filter.
10. A rule-ID filter. With 92% of records at `MANUAL_REVIEW` the tier carries
    little signal; `ARCHIVE_TRAVERSAL` or `NATIVE_BINARY` separate plugins in a
    way the tier cannot.
11. Reflect query and filters in the URL, as the storefront does, so a filtered
    view can be linked. Include the clear-button behaviour already built for
    the catalog search.

## Phase 3 — Deep link from the catalog

12. In `static/storefront.js:1021`, point the existing "Open audit log" link at
    `audit.html#<repo-slug>` instead of bare `audit.html`. The
    `dataset.detailFocus = "open-audit"` hook already there stays as is.
13. On load, expand and scroll to the group named by the fragment.

---

## Quality gates

- `uv run pytest tests/ -q` — currently 1129 passing.
- `npm run test:storefront` — currently 20 node and 11 Playwright tests.
- No new dependencies. No build step. The page must work as a plain static
  file served by Cloudflare Pages.

## Test changes this forces

`tests/test_audit_transparency.py` is security-relevant and needs care:

- `test_public_audit_whitelists_fields_and_never_leaks_evidence` already
  asserts the field whitelist and the absence of `evidence` / `file_contents`
  **on `audit.json`**. That guarantee is unchanged and is where it belongs. Its
  two `assert forbidden not in html` lines become vacuous once the shell holds
  no records; replace them with an assertion that the shell contains no record
  data at all, so the test still fails if records are ever re-baked into HTML.
- `test_block_releases_are_rendered_before_every_other_tier` asserts ordering
  in HTML. That logic moves to `audit.js`; re-assert it as a node test over the
  grouping function.
- `test_enforcement_copy_reflects_policy_mode` asserts enforcement copy in
  HTML. The copy moves client-side, driven by `audit.json`'s existing
  `enforcement_mode` field; re-assert as a node test.
- `test_empty_verdict_store_writes_valid_html_and_json` and
  `test_landing_page_links_to_audit_page` keep working against the static file.

New coverage: a Playwright test loading the real `static/audit.html` against a
stub `audit.json`, covering group collapse, search, a classification filter,
and a `#slug` deep link.

## Verification

Beyond the suites, after deploy:

- `audit.html` transfer size is under ~20 KB.
- Group count matches the distinct repository count in `audit.json` (101).
- Release cards inside a group match that repository's record count
  (`beallio/sdh-ludusavi` = 121).
- The summary header's counts equal a direct tally of `audit.json`.
- Following "Open audit log" from a plugin's detail card lands on that
  plugin's expanded group.

## Risks

- **The page stops working without JavaScript.** Today it is readable with
  scripting off. Mitigation: `audit.json` is a published URL and the shell
  links to it directly, so the raw data stays reachable. Worth an explicit
  `<noscript>` pointing there.
- **A second fetch of a 1.1 MB JSON.** Same-origin and likely already cached
  from the catalog page, and it replaces a 1.58 MB HTML download, so the
  worst case is roughly neutral and the common case is better.
- **Losing a transparency guarantee in the move.** Covered above: the
  whitelist assertion stays on `audit.json`, and the HTML assertion is
  rewritten to catch a regression rather than deleted.
