# Review — close-audit-coverage-and-verdict-integrity-gaps (round 23)

Branch: `feat/close-audit-coverage-and-verdict-integrity-gaps`
Reviewed against: `docs/plans/2026-08-08_close-audit-coverage-and-verdict-integrity-gaps.md`

## Verdict

CHANGES_REQUESTED. The corrected source-inventory proof independently
reconciles, but the documentation regression mostly compares stored summary
constants with other stored constants. Strengthen only that test so future
proof drift cannot silently leave the plan gate marked verified.

## Gate status

- Reviewed commit: `6979ca568070bc6536f8a535bf43074861e12d8b`.
- The round-complete marker is valid and the feature worktree is clean.
- The corrected proof reconciles independently: 579 unique release mappings,
  555 unique repository/commit streams, 24 aliases, 1,950,543,831 physical
  bytes, 2,003,669,460 mapped bytes, 555 source helper successes, 1,323 API
  requests, zero errors, and zero limit violations.
- Corpus/inventory digests, policy/verdict/checkpoint checksums, numeric release
  and asset IDs, all mapping joins, and the empty artifact directory reproduce.
- The complete local gate passed with `646 passed, 61 subtests passed`; focused
  documentation tests passed (`6 passed`). No inventory rerun is required.

## Required changes

1. Strengthen the source-inventory documentation test to derive from the proof
   detail records, rather than trusting summary fields: unique
   repository/commit identities, unique release identities, mapping coverage
   and joins, alias count, physical and mapped byte totals, maximum size and
   identity, numeric GitHub release/asset IDs, canonical tag@asset identities,
   corpus digest, and inventory digest.
2. Hash the tracked `security-policy.yml` in the test and compare it with the
   proof policy checksum and effective recorded source limit/timeouts; do not
   merely compare two evidence-file checksum strings.
3. Reconcile cumulative API/source/helper success and error counters with the
   detail records, and assert zero errors and zero limit violations.
4. Assert the proof's explicit result/status is verified/successful and equals
   the fourteen-shard projection's source-inventory status/path linkage. Keep
   warm and hosted-runner validation explicitly deferred.
5. Keep this round test-only apart from its review note. Do not alter the proof,
   plan, projection, production code, workflows, policy, or limits, and do not
   rerun the inventory or full audit.
6. Run the focused documentation test and complete local quality gate, commit
   the atomic test change, and write a new round-complete marker.

STATUS: CHANGES_REQUESTED
