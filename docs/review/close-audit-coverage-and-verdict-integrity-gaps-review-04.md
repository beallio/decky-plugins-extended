# Review — close-audit-coverage-and-verdict-integrity-gaps (round 04)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

Atomic slice 2 is accepted after its correction. The whole plan still requires changes. This
round owns only allowlist repository validation and canonicalization during loading.

## Gate status

- Reviewed commit: `f047c861bc8bf4b2c881cf70bd38045ca77879f2`
- Round marker: valid and stamped with the reviewed commit
- Focused archive/worklist tests: `33 passed`
- Full quality gate: `538 passed, 35 subtests passed`; actionlint/Ruff/format green
- Working tree: clean before this orchestrator-authored review note

## Required changes

### Atomic slice 3 — validate allowlist repository scope at load time

`load_allowlist()` validates required fields and hashes but does not validate or canonicalize each
entry's `repository`. Parsing is deferred until `apply_allowlist()` sees a finding, so malformed or
non-GitHub scope such as `https://evil.example/owner/repo` can pass startup and remain latent when a
release has no findings. Security configuration must fail closed independently of corpus contents.

Required implementation:

1. Validate every allowlist `repository` during `load_allowlist()` before returning any entries.
2. Accept only the same strict GitHub repository URL forms supported by
   `plugin_release_utils.parse_github_repository_url()` or an exact `owner/repo` shorthand with two
   valid decoded GitHub path atoms. Reuse the shared atom/canonicalization logic rather than
   creating a weaker parser.
3. Normalize the stored internal scope to one canonical `owner/repo` form so URL/shorthand case and
   trailing-slash variants cannot create different comparison behavior. Detect and reject entries
   that collide after canonicalization when their remaining identity is the same.
4. Reject other hosts, malformed URLs, extra segments, `.git`, credentials, ports, query/fragment,
   decoded delimiters/traversal, and malformed shorthand while loading—even when the audited
   release has zero findings.
5. Add focused load-time negative tests, a no-findings regression, accepted URL/shorthand controls,
   trailing-slash canonicalization, and collision coverage.
6. Run focused allowlist tests and the full orchestration quality gate. Record exact totals, commit
   only this slice, leave the tree clean, and mark the round finished.

Do not address any other review-inventory item in this round.

STATUS: CHANGES_REQUESTED
