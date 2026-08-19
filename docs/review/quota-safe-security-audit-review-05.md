# Review — quota-safe-security-audit (round 05)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested. The strict payload, stale-target invalidation, empty-selection integration,
and prior mutation cases now pass independent review. Two producer inputs were made stricter than
the existing GitHub/catalog contract, however, and base resolution proves only a 40-hex Git object
rather than a commit. This is a small Task 2 compatibility correction; do not start later tasks.

## Gate status

- `uv run pytest -q tests/test_audit_worklist.py tests/test_audit_plugins.py` passed with
  `302 passed, 36 subtests passed`; focused Ruff passed.
- A direct producer probe with an API-shaped `digest=sha256:<64 hex>` fails with `Invalid zip asset
  digest`. A second probe with `PLUGIN.ZIP` fails `Each worklist item must have exactly one zip
  asset`, although `plugin_release_utils.get_zip_asset()` deliberately treats the suffix
  case-insensitively.
- A direct `_resolve_base_ref_to_commit("HEAD:README.md", 5)` probe returned the README blob SHA as
  a valid base commit. Terra also reproduced acceptance of leading/trailing whitespace and duplicate
  newlines in successful resolver stdout.
- The tree is clean, the marker is valid at `a49990fbe09ba94fc7187eb7e1db563c77b69d71`, and
  `security-verdicts.json` is unchanged. Required implementer red/green artifacts remain absent.

## Required changes

1. Restore the existing digest boundary. GitHub API input is `sha256:<64 hex>` and may contain
   uppercase hex; normalize it with the shared `normalize_github_sha256_digest()` contract to the
   worklist's lowercase bare hash. Missing or malformed upstream digests must follow the existing
   digestless behavior, while a loaded worklist remains strict (`null` or bare lowercase hash only).
   Replace the new test that rejects a valid prefixed GitHub digest with producer tests proving
   lowercase and uppercase valid prefixes normalize, missing/malformed input becomes canonical
   null as today, and a re-fingerprinted prefixed/uppercase worklist field is rejected.
2. Restore the shared ZIP eligibility semantics. Producer parsing and worklist loading must accept
   `.zip` case-insensitively, just like `has_exactly_one_zip()`/`get_zip_asset()`, while still
   rejecting a non-ZIP or multiple ZIP assets. Prefer the shared selector instead of duplicating a
   conflicting filter. Add uppercase-suffix producer round-trip and loaded-document coverage.
3. Make base resolution prove a commit object with an unambiguous argv-only command such as
   `git rev-parse --verify --quiet --end-of-options <ref>^{commit}`. Require stdout to be exactly one
   lowercase 40-hex SHA plus its single normal line ending; do not `.strip()` arbitrary whitespace.
   Add exact-argv/no-shell assertions and rejection tests for a blob ref, leading/trailing spaces,
   duplicate lines/newlines, missing newline, uppercase, timeout, and nonzero exit.
4. Add these tests first and capture their genuine failing run at
   `/tmp/decky-plugins-extended/quota-safe-security-audit-red.log`; preserve focused/full green
   output at `/tmp/decky-plugins-extended/quota-safe-security-audit-green.log`. Run the complete
   quality gate, keep `security-verdicts.json` unchanged, commit, clean the tree, recreate the marker,
   and stop after this compatibility correction.

STATUS: CHANGES_REQUESTED
