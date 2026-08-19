# Review — repository-rename-resilience (round 1)

Branch: `feat/repository-rename-resilience`
Reviewed against: `docs/plans/2026-08-18_repository-rename-resilience.md`
Reviewed commits: `2446b8c`, `35bd7cf`, `235e0f6`, `5498610`

## Verdict

Every task the plan named is implemented correctly, and the verification
evidence is real rather than asserted.  The defect below is a gap in the plan I
wrote, not a failure to follow it: Task 3 named only the metadata-identity path,
so only that path was fixed.  Three sibling conditions still produce exactly the
run-global outage this plan exists to eliminate.

What is right and should be preserved unchanged:

- The strict identity comparison is intact and the redirect target is never
  adopted.  The mutation control proves it: a patch that rewrites the configured
  URL to the redirect target is caught by
  `test_worklist_prepare_records_metadata_identity_mismatch_without_adopting_redirect`.
- `repository_errors` is fingerprint-covered, canonically ordered, duplicate-
  free, bounded to a slug-shaped reason, and rejected when it names a repository
  outside the selection or one that also contributed items.  A zero-error
  document omits the key entirely, so existing fingerprints do not churn.
- Aggregation renders each entry as an `AUDIT_ERROR` report with no release
  identity, so the run exits 4, no verdict-delta record is produced, and the
  verdict store is not written for that repository.
- `35bd7cf` correctly repoints the stale URL and records the ownership and
  release-continuity evidence in its message.

## Gate status

`scripts/orchestration/run-quality-gates` passed at `5498610`: actionlint
verified with all three mutation negative controls rejected, Ruff check and
format clean, Pytest `983 passed, 63 subtests passed`.  Review notes not
deleted, `git diff --check` clean, worktree clean, and `security-verdicts.json`
unchanged from `git merge-base dev HEAD`.

Verification artifacts are present and genuine: the red log records 7 failing
new tests before implementation, and
`/tmp/decky-plugins-extended/repository-rename-resilience-mutation.patch` is a
real behavioral mutation detected by the intended test and cleanly reversed.

## Required changes

### 1. Widen per-repository isolation to the whole class

I verified three conditions that still abort preparation for the entire corpus.
Each was probed directly against the current branch with a two-repository
fixture in which only the first repository is broken:

```text
git ls-remote failure      -> RuntimeError; no worklist written
release enumeration raises -> RuntimeError; no worklist written
zero eligible releases     -> ValueError: No eligible release found for ...
```

Every one of these is a single stale or unlucky entry in
`additional_plugins.txt` taking down the other 40 repositories — the same
failure shape as the rename that motivated this plan.  A deleted repository, a
repository made private, a transient 404 on one repository's release
enumeration, and a newly added plugin that has not cut a release yet are all
ordinary conditions, not systemic ones.

Extend the per-repository error path to cover them, with distinct slug reasons
in the existing bounded vocabulary — for example
`repository-tags-unresolvable`, `repository-releases-unavailable`, and
`repository-no-eligible-release`.  Keep the current structure: the repository
contributes no items, gets one `repository_errors` entry, is logged by name at
warning level, and surfaces as `AUDIT_ERROR` with exit 4.

The plan's Verification section says a Git transport failure during tag
resolution stays run-global.  That sentence is what I got wrong, and it is
superseded by this note: a *single repository's* tag resolution failure is a
repository error.  Genuinely systemic failure must still be run-global, and the
clean discriminator is outcome rather than cause — if every selected repository
fails, preparation must produce no worklist and exit 1 rather than publishing a
worklist with zero items and 41 errors.  Implement that guard explicitly and
test it.

An exhausted API budget, a malformed or unserializable payload, and a failure to
write the document atomically all remain run-global exactly as they are today.

### 2. Validate identity before spending the tag-resolution budget

`prepare_audit_worklist()` calls `tag_resolver()` before it fetches metadata, so
a repository that is about to be rejected for identity mismatch still consumes a
full `git ls-remote` and the monotonic budget that call is clipped against.
Reorder so metadata identity is validated first and a repository headed for
`repository_errors` never pays for tag resolution.  This also makes the budget
accounting honest when several repositories are stale at once.

### 3. Test the observed production failure end to end

The current tests use synthetic owner/repo fixtures.  Add one case that
reproduces run `32219524259` in the shape it actually occurred: the configured
URL `https://github.com/danielcopper/decky-romm-sync` with metadata returning
`full_name` of `danielcopper/romm-tender`, asserting one
`repository-metadata-identity-mismatch` entry, zero items for that repository,
no identity anywhere referencing the redirect target, and the remaining corpus
producing its normal items.

Name the run id in the test docstring so the regression stays traceable to the
incident.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note.  Do not
modify `security-verdicts.json`.  Do not start hosted workflows.  Deferred
verification remains deferred: no run has yet exercised the fourteen-shard path
end to end, so both the rename fix and the underlying quota fix are still
unproven on hosted infrastructure.

STATUS: CHANGES_REQUESTED
