# Plan: Implement the Cloudflare storefront redesign (storefront-redesign)

## Context

The tracked Cloudflare Pages landing source is `static/index.html`; the build
copies top-level files from `static/` into gitignored `public/` through
`generate_json.copy_static_files`. The current page is a single animated
synthwave panel with two copy buttons. It does not expose the generated plugin
catalog in the browser even though `plugins.json`, `testing_plugins.json`, and
`audit.json` already contain the data needed for a useful storefront.

The approved design reference is
`/tmp/decky-plugins-extended/proposed-store-page.html`. It establishes the
visual direction and interaction hierarchy, but its sample plugin records and
counts are not production data. Implement the same restrained dark storefront
with cyan and magenta brand accents, a sticky header, installation panel,
centered status strip, catalog controls, responsive cards, setup dialog, and
plugin detail dialog. Do not include the sentence “High-signal badges explain
why an entry is in this catalog.” The catalog introduction ends after “Search
by name, author, or purpose.”

The production page must use the real generated catalogs. Stable is the default
channel; Testing loads `testing_plugins.json`. A new generated
`storefront.json` supplies only browser-specific provenance and status metadata
that cannot be derived safely from Decky's catalog schema. Existing
`plugins.json` and `testing_plugins.json` fields, routes, sorting semantics,
CORS headers, D1 count overlay, and install/update POST routes are compatibility
contracts and must remain unchanged.

The current repository-wide quality gate has five pre-existing failures in
`tests/test_audit_documentation.py`: commit `2f48ead` split user and developer
guidance between `README.md` and `Developer.md`, but those tests still require
developer-only audit phrases in the shortened README. Repair that test
ownership as an explicit prerequisite without weakening or deleting any
required contract phrase.

Files in scope:

- `static/index.html` — semantic storefront shell only.
- `static/storefront.css` — responsive design and all visual states.
- `static/storefront.js` — catalog loading, pure view-model helpers, controls,
  dialogs, copy behavior, URL state, rendering, and error handling.
- `generate_json.py` — deterministic `storefront.json` metadata generation.
- `tests/test_generate_json.py` — metadata and static-copy coverage.
- `tests/test_landing_page.py` — semantic/accessibility asset contract.
- `tests/storefront_logic.test.mjs` — Node built-in tests for pure browser logic.
- `tests/storefront_surface.spec.mjs` — mandatory Playwright startup, interaction,
  accessibility, and responsive-layout coverage.
- `package.json` and `package-lock.json` — pinned test-only Playwright dependency;
  no production bundle or build script.
- `scripts/orchestration-hooks/quality-gates` — install the pinned test
  dependency and run both JavaScript suites.
- `tests/test_audit_documentation.py` — only the pre-existing README/Developer
  ownership repair described above.
- `README.md` — concise user-facing mention of the browser catalog and its
  stable/testing behavior.

Do not edit generated files under `public/`. Do not add a frontend framework,
production JavaScript dependency, application build step, analytics,
authentication, submission flow, service worker, or new Cloudflare binding.
The package manifest is test-only and must contain no runtime dependency. Do not
redesign `audit.html`; link to the existing generated audit page.

**Slug used throughout this plan:** `storefront-redesign`

---

## Orchestration Contract

**Slug:** `storefront-redesign`

**Plan file:**

```text
docs/plans/2026-08-31_storefront-redesign.md
```

**Implementation branch:**

```text
feat/storefront-redesign
```

**Round-complete marker:**

```text
/tmp/decky-plugins-extended/storefront-redesign_finished
```

**Finalized marker:**

```text
/tmp/decky-plugins-extended/storefront-redesign_finalized
```

**Review notes:**

```text
docs/review/storefront-redesign-review-*.md
```

Each review note ends with exactly one status trailer:

```text
STATUS: CHANGES_REQUESTED
```

or:

```text
STATUS: APPROVED
```

---

## Required Agent Protocol

1. Use the **implementer** skill.
2. Work from the repository root.
3. Branch from `dev`.
4. Commit this plan as the first commit on the implementation branch.
5. Follow TDD where behavior changes are testable.
6. Run quality gates before marking any round complete.
7. Do not write your own review.
8. Do not create files under `docs/review/`.
9. Do not delete files under `docs/review/`.
10. Review notes are durable audit records and must be committed.
11. Resolving a review note means:
    - implement the requested changes;
    - run quality gates;
    - commit the code/docs changes;
    - commit the review note itself if it is not already committed;
    - recreate the round-complete marker.
12. After finalization, stop polling and exit cleanly.

---

## Scope discipline

- Implement only the units the plan lists. Do not modify files outside the plan's scope.
- Do not change runtime behavior beyond what the plan specifies. A `refactor` or
  `cleanup` commit must preserve observable behavior.
- Never edit a test's expected value to make a behavior change pass. If a test
  legitimately must change, that change must be required by the plan or a review
  note, and you must record the rationale in the session log.
- If you spot an unrelated improvement, do not make it here — note it in the
  session log for a separate plan.

---

## Setup

Start from `dev`:

```bash
git checkout dev
git pull --ff-only origin dev
git checkout -b feat/storefront-redesign
```

Commit this plan first:

```bash
git add docs/plans/2026-08-31_storefront-redesign.md
git commit -m "docs(plan): add storefront-redesign implementation plan"
```

---

## Implementation Tasks

Work in order. Keep the page usable if JavaScript or one optional metadata
request fails: the installation URLs and links remain present in HTML, while
catalog failures produce an explicit retryable error state rather than an empty
grid.

### Task 0 — restore the existing documentation-test baseline

Update only the ownership of assertions in `tests/test_audit_documentation.py`
that currently expect developer-only operational text in `README.md`.

- Keep user-facing catalog setup and safety assertions against `README.md`.
- Assert detailed quality-gate, identity/outcome, worklist, progress,
  preparation-error, quota, and scanner contracts against `Developer.md` and,
  where the test already requires it, `docs/audit-gating-overview.md`.
- Do not remove or shorten the required phrase lists.
- Do not copy the old developer material back into README merely to satisfy the
  tests.

Run `uv run pytest tests/test_audit_documentation.py -v` and record the exact
pass/fail tally before starting storefront work.

### Task 1 — generate deterministic storefront metadata

In `generate_json.py`, add a small pure metadata builder and writer. Capture the
case-insensitive names present in the fetched official stable/testing catalogs
before any repository merges mutate them. Catalog entries can receive versions
from more than one configured repository under the same case-insensitive plugin
name, so provenance must be retained per exact contributed version identity,
not as one last-writer-wins source per plugin.

For each configured repository that successfully contributes an eligible
version, retain the display name, normalized version name, artifact SHA-256,
normalized release tag, canonical repository slug (`owner/repo`), and canonical
GitHub source URL. Store version records in a sorted array so two repositories
cannot overwrite each other even if they publish the same plugin name or
artifact hash.

Write `public/storefront.json` after final catalog validation and before static
copy. Use this schema:

```json
{
  "schema_version": 1,
  "enforcement_mode": "enforce",
  "stable_count": 0,
  "testing_count": 0,
  "stable_extended_count": 0,
  "testing_extended_count": 0,
  "plugins": {
    "casefolded plugin name": {
      "name": "Display Name",
      "provenance": "official",
      "versions": [
        {
          "name": "1.2.3",
          "hash": "sha256",
          "tag": "v1.2.3",
          "repository": "owner/repo",
          "source_url": "https://github.com/owner/repo"
        }
      ]
    }
  }
}
```

Channel counts include only entries whose `visible` field is not false.
Extended counts are unique visible catalog entries in that channel whose
case-insensitive name did not exist in either originally fetched official
catalog; they do not count contributing repositories or raw lines in
`additional_plugins.txt`. Sort plugin-map keys and each version array by hash,
repository, tag, and name before writing so output is deterministic. Do not add
storefront fields to Decky's catalog entries.

Add a regression fixture with two configured repositories contributing
different versions under the same plugin name and prove that both version
identities survive with the correct repository. Also test official versus
extended classification, case-insensitive name matching, channel-specific
invisible entries/counts, deterministic ordering, empty metadata, and `main()`
publishing `storefront.json`. Extend the static-copy test to require
`index.html`, `storefront.css`, and `storefront.js`.

### Task 2 — replace the landing shell and create the design stylesheet

Replace `static/index.html` with semantic markup that references
`storefront.css` and loads `storefront.js` as a module. Reproduce the approved
reference's hierarchy:

1. sticky brand header with Plugins, Audit, and GitHub links;
2. two-column hero with the copy “More plugins. Clearer choices.”;
3. stable/testing installation panel with a prominent copy action and setup
   instructions;
4. a four-cell status strip for catalog status, available count, extended
   community sources, and security policy;
5. catalog heading, search, sort, category chips, result count, loading/error/
   empty states, and card grid;
6. accessible setup and plugin-detail dialogs;
7. compact footer.

The status-strip value and label in every cell must be horizontally centered at
desktop and mobile widths. The catalog paragraph must be exactly “Search by
name, author, or purpose.” and must not contain “High-signal badges”.

Move all presentation into `static/storefront.css`. Preserve a restrained
synthwave identity rather than copying AlphaStore: quiet navy surfaces, cyan
primary actions/focus, magenta brand accents, yellow warnings, subtle static
grid, and no permanent pulsing animation. Include visible `:focus-visible`
styles, `prefers-reduced-motion`, 44px-or-larger primary controls, three/two/one
column card breakpoints, centered status cells, and responsive dialogs. Use
system fonts and inline SVG icons; make no external font or image dependency
for the shell.

Keep stable/testing URLs as real anchor text or other visible HTML fallback so
the page still provides its core install function without JavaScript.

### Task 3 — implement catalog and interaction behavior

Implement `static/storefront.js` without dependencies. Keep transformation
logic in exported pure functions and guard DOM startup with
`typeof document !== "undefined"` so Node can import the module.

Required pure behavior:

- normalize catalog entries defensively;
- parse and remove the generated
  `Official store has X; this store has Y.` prefix from card descriptions while
  retaining X/Y for an “Newer than official” badge and detail note;
- classify one primary badge in this precedence order:
  audit BLOCK/MANUAL_REVIEW context, Testing prerelease, Newer than official,
  Extended only, or no badge;
- filter case-insensitively by name, author, description, and tags;
- map common tags into Library, Utilities, and Media categories while allowing
  direct tag matches;
- sort by updated date, name, or combined downloads/updates without mutating the
  source catalog;
- build a detail view model with latest version name/hash, source link,
  provenance, official-version note, and matching audit outcome. Resolve source
  by plugin name plus exact catalog version hash/name. Accept an audit record
  only when repository and normalized tag match that version identity,
  `identity_status == "CURRENT"`, `outcome == "APPLIED"`, and
  `current_artifact_sha256` equals the catalog hash. Missing or ambiguous
  identity data produces no source-specific audit badge rather than guessing.

Required browser behavior:

- fetch `/storefront.json`, `/audit.json`, and the selected stable/testing
  catalog; tolerate missing optional audit/provenance data but fail visibly when
  the selected catalog cannot load;
- cache successful channel responses and discard stale responses when users
  switch channels quickly;
- keep channel, query, category, and sort in URL search parameters and restore
  them on reload;
- update all counts and cards from real response data; no sample plugin names or
  hard-coded catalog counts remain;
- lazy-load plugin images, reserve image space, and show a deterministic
  monogram fallback after an image error;
- copy through the Clipboard API with a textarea fallback and announce success
  or failure through `aria-live=\"polite\"`;
- implement setup/detail dialog focus entry, focus trapping, Escape close,
  backdrop close, return focus, and background scroll restoration;
- use real anchors for available source and audit actions; omit unavailable
  actions instead of rendering inert buttons;
- preserve search/filter state and focus after the detail dialog closes.

Never inject catalog strings with `innerHTML`. Build dynamic nodes with
`createElement` and assign untrusted text with `textContent`.

### Task 4 — replace landing tests and add browser-logic tests

Rewrite `tests/test_landing_page.py` around the new observable contract instead
of the removed absolute-position utility group. Parse the HTML with the standard
library and assert unique IDs, referenced local assets, visible stable/testing
fallback URLs, semantic navigation, status region, catalog controls, both
dialogs, accessible names, live status output, and the absence of inline event
handlers. Read `storefront.css` and assert responsive breakpoints,
focus-visible styling, and reduced-motion handling. Assert that the catalog
paragraph's normalized text is exactly “Search by name, author, or purpose.”
and that the substring “High-signal badges” is absent from both
`static/index.html` and `static/storefront.js`.

Add `tests/storefront_logic.test.mjs` with `node:test` and
`node:assert/strict`. Import the pure exports from `static/storefront.js` and
cover:

1. official-version note parsing and clean description;
2. badge precedence and exact per-version audit identity matching;
3. stable/testing endpoint selection and channel counts;
4. case-insensitive text and category filtering;
5. updated/name/install sorting without input mutation;
6. detail-model source, hash, provenance, and audit fields under same-name
   repository collisions;
7. malformed/missing catalog and metadata fields;
8. stale channel-response rejection or request-generation behavior.

Add a pinned `@playwright/test` development dependency and commit the generated
lockfile. The package must be private, set `\"type\": \"module\"`, contain no
runtime dependencies, and expose one script that runs both storefront suites.
Add `tests/storefront_surface.spec.mjs`; it must start an HTTP server
for the actual `static/` assets, intercept or serve deterministic stable,
testing, storefront, and audit fixtures, and invoke the real module startup
path. It must cover initial success, catalog failure plus retry, rapid channel
switching, search/filter/sort, image fallback, clipboard fallback, setup/detail
dialogs, focus trapping/Escape/return focus, URL state restoration, and missing
optional metadata. At 1440×1000 and 390×844, use computed styles and bounding
boxes to prove every status value and label is centered in its cell, assert no
horizontal overflow, and save screenshots under
`/tmp/decky-plugins-extended/storefront-redesign/`.

Add `node` and `npm` as fail-closed prerequisites in
`scripts/orchestration-hooks/quality-gates`. Run
`npm ci --ignore-scripts --no-audit --no-fund`, install the pinned Playwright
Chromium build if it is absent, then run the Node and Playwright suites before
pytest. Preserve the existing actionlint, Ruff, and pytest gates.

### Task 5 — user documentation and implementation record

Update README's website section to state that the canonical Cloudflare URL now
offers a browser catalog while the two JSON endpoints remain the Decky Loader
install contract. Keep setup instructions concise and keep Stable recommended
over Testing.

Record the implemented files, exact verification outputs, deferred visual
checks, and the pre-existing documentation-test repair in the required session
log under `docs/agent_conversations/`.

---

## Quality Gates

Run before marking any round complete:

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git status --short
```

The round is not complete unless:

1. all requested implementation work is done;
2. all relevant tests pass;
3. build/typecheck gates pass;
4. review notes have not been deleted;
5. the working tree is clean;
6. all code/docs changes are committed.

---

## Verification

Verification standards for this repository are defined in the orchestration
skill's `references/verification-standards.md`; do not restate them here. Record
actual command output and pass/fail tallies.

### V1 — documentation baseline and Python contracts

Run:

```bash
set -o pipefail
uv run pytest tests/test_audit_documentation.py tests/test_generate_json.py tests/test_landing_page.py -v
```

Failure is a non-zero exit, a collection error, or any test from Tasks 0, 1, or
4 missing from the verbose listing. Record the exact pass/fail/error tally.

### V2 — JavaScript logic, startup, and rendered behavior

Run:

```bash
set -o pipefail
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install chromium
node --check static/storefront.js
node --test tests/storefront_logic.test.mjs
npx playwright test tests/storefront_surface.spec.mjs
```

Failure is a non-zero exit, syntax error, zero collected tests, browser-startup
error, missing behavior group, failed computed-centering/geometric assertion,
or missing desktop/mobile screenshot. Record the Node TAP and Playwright
pass/fail tallies plus screenshot paths.

### V3 — prove the JavaScript behavior gate with a mutation

Temporarily replace the branch in the exported official-version parser that
returns the extracted official/store versions with the ordinary-description
fallback. Run:

```bash
set -o pipefail
node --test tests/storefront_logic.test.mjs
```

The official-version parsing test and badge-precedence test must fail with
assertion diagnostics. If the suite passes, strengthen it before continuing.
Restore the exact implementation by hand; do not use `git checkout --` because
that can discard other feature work. Re-run V2 and record the green TAP tally.

### V4 — generated artifact contract

Run the targeted `main()` integration test added in Task 1 with verbose output.
It must prove that a temporary build publishes parseable `plugins.json`,
`testing_plugins.json`, `storefront.json`, `audit.json`, `index.html`,
`storefront.css`, and `storefront.js`; that `storefront.json` uses schema version
1; and that the original two catalog entries contain no new storefront-only
fields.

Then run:

```bash
set -o pipefail
uv run pytest tests/test_generate_json.py -k storefront -v
```

Failure is a non-zero exit, zero selected tests, a missing artifact, invalid
JSON, or a catalog schema equality failure.

### V5 — local HTTP and responsive surface smoke

The Playwright suite from V2 is mandatory and must use the actual
`static/index.html`, `static/storefront.css`, and `static/storefront.js` startup
path over HTTP. In addition to the Task 4 cases, record direct observations for:

- Stable loading first and Testing selecting its endpoint.
- Search, category chips, and sorting changing visible fixture cards.
- Catalog failure showing a retry control that successfully recovers.
- Every status value and label having centered computed styles and a horizontal
  midpoint within two CSS pixels of its cell midpoint at 1440×1000 and 390×844.
- The catalog introduction being exactly “Search by name, author, or purpose.”
  with no rendered “High-signal badges” substring.
- Setup and detail dialogs trapping focus, closing with Escape, and restoring
  focus.
- Clipboard success or fallback being visibly announced.
- No horizontal overflow at either viewport.

Also request `index.html`, `storefront.css`, `storefront.js`, `plugins.json`,
`testing_plugins.json`, `storefront.json`, and `audit.json` directly from the
test server. Every response must be 200, both JSON catalogs must parse, and all
local assets referenced by `index.html` must resolve. Stop the server and record
the two screenshot paths before continuing.

### V6 — full repository gates

Run after V1 through V5:

```bash
scripts/orchestration/run-quality-gates
scripts/orchestration/check-review-notes-not-deleted
git status --short
```

Record the actionlint, Node, Ruff, and pytest tallies. Failure is any non-zero
command, a deleted review note, test failure, formatting difference, or
non-empty working tree after all intended files are committed.

### Deferred and unverified

- Real Steam Deck gamepad/spatial navigation is not part of this redesign.
- Cloudflare dashboard bindings, DNS, and production deployment are unchanged
  and cannot be proven by a local Pages build.
- Playwright proves the specified rendered states and geometry, but subjective
  visual approval of color, spacing, and content density remains a human review.

---

## Mark Round Complete

When the implementation round is complete and the working tree is clean, run:

```bash
scripts/orchestration/mark-finished storefront-redesign
```

This writes:

```text
/tmp/decky-plugins-extended/storefront-redesign_finished
```

Then exit cleanly. If this process exits, the orchestrator will resume you through
`scripts/orchestration/continue-implementer storefront-redesign`.

---

## Review Polling Loop

After marking the round complete, check existing review notes first, then poll for new review notes if you remain active:

```text
docs/review/storefront-redesign-review-*.md
```

When a review note exists or a new review note appears:

1. Read the full review note.
2. If the note ends with:

   ```text
   STATUS: CHANGES_REQUESTED
   ```

   then resume work.

3. Clear the round-complete marker:

   ```bash
   scripts/orchestration/clear-finished storefront-redesign
   ```

4. Address every requested change.
5. Run quality gates:

   ```bash
   scripts/orchestration/run-quality-gates
   scripts/orchestration/check-review-notes-not-deleted
   ```

6. Commit code/docs fixes.
7. Commit the review-note file itself if it is not already committed:

   ```bash
   git add docs/review/storefront-redesign-review-*.md
   git commit -m "docs(review): record storefront-redesign review notes"
   ```

8. Recreate the round-complete marker:

   ```bash
   scripts/orchestration/mark-finished storefront-redesign
   ```

9. Either continue polling or exit cleanly. If you exit, the orchestrator will resume you with `scripts/orchestration/continue-implementer storefront-redesign` after the next review note is created.

---

## Approval Handling

If the latest review note ends with:

```text
STATUS: APPROVED
```

then:

1. Confirm every previous review item has been addressed.
2. Confirm all review notes are committed:

   ```bash
   scripts/orchestration/check-review-notes-committed storefront-redesign
   ```

3. Confirm the working tree is clean:

   ```bash
   git status --short
   ```

4. Finalize:

   ```bash
   scripts/orchestration/finalize storefront-redesign
   ```

5. Confirm the finalized marker exists:

   ```text
   /tmp/decky-plugins-extended/storefront-redesign_finalized
   ```

6. Stop polling and exit cleanly.

---

## Review Rules

Do not write your own review.

Do not create files under:

```text
docs/review/
```

Do not delete files under:

```text
docs/review/
```

Only the orchestrator writes review notes. Your job is to read them, resolve them, commit them as audit records, and continue the loop.

---

## Finalization Rules

Only finalize after a review note with:

```text
STATUS: APPROVED
```

Finalization is performed with:

```bash
scripts/orchestration/finalize storefront-redesign
```

Do not manually merge into `dev` unless the finalize script fails and the user/orchestrator explicitly instructs you to recover manually.

Leave both markers in place after finalization:

```text
/tmp/decky-plugins-extended/storefront-redesign_finished
/tmp/decky-plugins-extended/storefront-redesign_finalized
```

Any project-specific release step runs from the project's
`scripts/orchestration-hooks/finalize-release` hook, invoked by finalize.
