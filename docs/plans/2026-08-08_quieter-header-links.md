# Plan: Quiet the landing-page audit and GitHub links (quieter-header-links)

## Objective

Reduce the visual prominence of the audit and GitHub links on the Decky Extended
Plugins landing page while keeping both destinations discoverable and accessible.
Place both links in a compact utility group in the container's top-right corner,
give GitHub its conventional mark, use a shield/check icon for the audit link,
and remove the repeated audit URL from the visible URL list.

## Scope

In scope:

- `static/index.html` layout, styling, icons, link labels, and visible URL list.
- A focused regression test for the static landing-page contract.
- A session artifact under `docs/agent_conversations/` recording validation.

Out of scope:

- Changes to generated audit data or `generate_json.py`.
- Changes to the audit page's content or destination.
- Changes to the primary stable/testing copy buttons.
- New image assets or third-party icon dependencies.

## Implementation phases

### 1. Regression contract

Add a focused test that verifies the landing page retains both destinations in
the top-right utility group, includes an accessible conventional GitHub SVG
mark, keeps an accessible audit icon/link, and no longer lists `audit.html` in
the public URL list.

Validation: the new test fails against the current markup for the missing
utility group and still passes the existing landing-page behavior assumptions.

### 2. Landing-page UI

Replace the two large link buttons with a compact `.utility-links` group that
is positioned at the top-right of the page container. Use subdued translucent
styling, preserve visible text labels and keyboard focus states, and add
responsive spacing so the group does not collide with the heading on narrow
screens. Use the official GitHub mark as inline SVG and a shield/check SVG for
the audit destination.

Remove the audit link from the `.urls` list while retaining the audit utility
link itself.

Validation: the focused regression test passes; the generated/static page has
no old GitHub/audit button styles or duplicate audit URL entry.

### 3. Verification and handoff

Run the focused test, the complete test suite, and Ruff. Inspect the diff and
working tree, then commit the plan, implementation, and session artifact as
separate atomic Conventional Commits.

Validation: all tests and lint pass; no unrelated files change; worktree is
clean after the commits.

## Branch and commit strategy

Branch:

```text
feat/quieter-header-links-20260808
```

Commits:

1. `docs(plan): add quieter header links implementation plan`
2. `test(site): cover quieter landing page links`
3. `style(site): quiet audit and GitHub header links`
4. `docs(session): record quieter header links verification`

