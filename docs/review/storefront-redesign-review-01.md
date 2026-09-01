# Review — storefront-redesign (round 01)

Branch: `feat/storefront-redesign`
Reviewed against: `docs/plans/2026-08-31_storefront-redesign.md`

## Verdict

The visual direction is close to the approved prototype, and the first round
produced broad automated coverage. It is not ready to integrate. Production
audit data is currently discarded, several recovery/accessibility paths report
incorrect state, mobile header/focus behavior needs correction, and the
repository-wide gate cannot complete on this workstation.

## Gate status

- Implementer record: Node 8 passed, Playwright 5 passed, Python 1,103 passed
  with 66 subtests.
- Orchestrator rerun: actionlint and three mutations passed; Ruff check and
  format passed; `npm ci` passed.
- Orchestrator rerun then failed in `npx playwright install chromium`. The
  download retried five times and failed near 40% with
  `Unknown system error -122` while `/tmp` had limited capacity. No Node,
  Playwright, or pytest result from that rerun can be accepted after this
  failure.
- Working tree was clean at marker SHA
  `4ab5c701576bb1df43f2bc76eb15eebba09d2318`.

## Required changes

1. **Consume the real audit envelope.** `audit.json` publishes releases under
   `payload.releases`, but `static/storefront.js` currently accepts only a bare
   array or `payload.records`. Parse `releases` and update the Playwright fixture
   to use the exact production envelope so current BLOCK/MANUAL_REVIEW badges
   and audit actions are exercised.

2. **Match the producer's tag normalization exactly.** Port
   `generate_json.normalize_version` semantics, including its maximum of three
   numeric components, into the storefront matching helper. Add a regression
   for a tag such as `v1.2.3.4` proving the metadata and CURRENT/APPLIED audit
   record match the same catalog artifact.

3. **Do not label unknown provenance as official.** When `storefront.json` is
   unavailable, unsupported, or lacks a plugin identity, show an unavailable or
   unknown provenance value. Only display “Official catalog” when metadata
   explicitly establishes `official`.

4. **Use one cross-language plugin lookup contract.** The generator uses Python
   `casefold()` keys while JavaScript uses `toLowerCase()`, which fails for names
   such as `Straße`. Publish and consume an unambiguous lookup identity or match
   the serialized display name without guessing. Add a Unicode regression that
   retains source, audit identity, provenance badge, and Extended-only filter
   membership.

5. **Put copy feedback inside the active dialog.** Add visible `aria-live`
   status targets to the setup and detail dialogs. Announce setup URL and
   SHA-256 copy results in the dialog with value-specific text; do not announce
   every copy as “URL copied” in the obscured install panel. Cover success and
   failure paths.

6. **Restore focus after optional-data rerenders.** If metadata/audit completion
   rerenders cards while details are open, closing the dialog must focus the
   replacement trigger for the same plugin. Add a Playwright case that opens
   details before optional responses settle, then closes after rerender and
   verifies focus restoration.

7. **Test the centered content rather than its full-width wrapper.** The current
   Playwright geometry assertion measures `.status-value`, whose width is the
   cell width and therefore passes even with left-aligned flex content. Measure
   the actual dot/text group or text range, assert computed `justify-content:
   center`, and retain the two-pixel midpoint requirement for both viewports.

8. **Give cards a visible, unclipped keyboard focus state.** The global outside
   outline is clipped by `.plugin-card { overflow: hidden; }`. Add an in-card
   focus-visible treatment such as an inset ring or parent `:focus-within`
   border/glow. Playwright must focus a card and assert the rendered focus state.

9. **Preserve the mobile brand instead of clipping it.** At 390px the current
   screenshot truncates “Decky Extended Plugins” while keeping all three text
   navigation links. Match the approved mobile hierarchy by hiding optional nav
   text/links and shortening the brand at the narrow breakpoint. Add a
   screenshot/text-overflow assertion.

10. **Reduce the stacked mobile catalog-heading gap.** The result count is
    separated from the required introduction by the desktop 24px gap. Set the
    mobile gap to approximately 8px, matching the approved reference, and cover
    the computed gap.

11. **Make the browser gate repeatable on this workstation.** Diagnose the
    Playwright `-122` write failure and stop using a capacity-constrained
    temporary download location. A suitable fix is an explicit ignored browser
    cache on the repository's large filesystem, reused across gate runs while
    still installing the pinned build when absent. Do not weaken or skip the
    mandatory browser test. Re-run the entire
    `scripts/orchestration/run-quality-gates` hook successfully and record its
    actual actionlint, Node, Playwright, Ruff, and pytest tallies.

STATUS: CHANGES_REQUESTED
