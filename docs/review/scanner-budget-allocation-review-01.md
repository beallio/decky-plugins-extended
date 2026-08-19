# Review — scanner-budget-allocation (round 1)

Branch: `feat/scanner-budget-allocation`
Reviewed against: `docs/plans/2026-08-19_scanner-budget-allocation.md`
Reviewed commits: `d7e78d3`, `5243cf2`

## Verdict

The allocator is well built.  Reserves are derived backwards from the declared
minimums rather than hand-maintained, the table is validated at startup and
exits 1 when inconsistent, budget exhaustion has its own status `125` distinct
from a `124` timeout, and the published table shows `install base packages`
receiving 240 seconds on a full budget against the 90 that was failing.

One defect blocks acceptance, and it undoes the specific recovery this branch
was written to protect.

## Gate status

`scripts/orchestration/run-quality-gates` passed at `5243cf2`: actionlint
verified with all three mutation negative controls rejected, Ruff check and
format clean, Pytest `1004 passed, 63 subtests passed`.  Review notes not
deleted, worktree clean, `security-verdicts.json` unchanged from
`git merge-base dev HEAD`.

Verification evidence is genuine: the red log records six failing new tests
before implementation, the allocation table is saved as required, and the
mutation patch replaces the derived allocation with a hard-coded `90` and is
caught by `test_scanner_bootstrap_allows_apt_phase_to_use_remaining_budget`.

## Required changes

### 1. A full-length first attempt leaves no budget for the retry

The allocator gives `install-base-packages` a 240-second maximum against a
320-second reserve.  When the first attempt uses its whole allocation, the
retry cannot be afforded.  Evaluated directly against the committed script:

```text
reserve(install-base-packages)=320 min=30 max=240
remaining=599 -> allocated=240s
remaining=340 -> BUDGET_EXHAUSTED
remaining=320 -> BUDGET_EXHAUSTED
remaining=300 -> BUDGET_EXHAUSTED
```

After a 240-second attempt plus teardown and the 10-second APT backoff,
remaining sits near 325–340, which is already below the exhaustion threshold.
`NETWORK_ATTEMPTS=2` is nominal for this phase: in the slow-mirror case that
motivated the plan, there is exactly one attempt.

That is the wrong trade for the evidence we have.  Run `32275727649` shows the
retry doing real work — three of the four surviving shards were saved by it,
and in every case the retry was *fast*, which means the first attempt was stuck
rather than merely slow:

```text
shard 0  install base packages 95s/124 -> retry 83s/0 -> success
shard 1  install base packages 95s/124 -> retry 47s/0 -> success
shard 4  install Trivy         95s/124 -> retry 52s/0 -> success
```

A single 240-second attempt would have absorbed the stall and then failed the
shard with no second try, where two attempts of the old 90 seconds recovered.
The plan asked for a phase to draw on remaining budget; it did not ask for
retries to become unaffordable, and its Task 2 explicitly says retries continue
to draw from the same budget.

Make retry capacity part of the allocation rather than a leftover.  For a phase
with more than one attempt, the per-attempt ceiling must leave at least one
further attempt affordable at a useful size — not merely at the phase minimum,
which would reintroduce a too-short retry.  Splitting the phase's available
budget across its declared attempts is the straightforward form.

Add a test that fails if a retryable phase can consume the budget its own retry
needs: run a phase whose first attempt always times out and whose second would
succeed, and require the bootstrap to complete.

### 2. Skipping the base install also skips the full index refresh

The base-package step now runs `dpkg-query` per package and, when none are
missing, prints `outcome=skipped reason=all-packages-present` and runs nothing —
including the `apt-get update` that previously always ran.  The later Trivy
phase refreshes only the Trivy source list (`Dir::Etc::sourcelist`,
`sourceparts="-"`), by design, so on the skip path no full index refresh happens
at all before `apt-get install trivy` resolves against every configured source.

This is latent rather than live: `clamav` is not present on the runner image, so
`missing_base_packages` is never empty in production today and the full refresh
always runs.  But the code couples two different conditions — "no base packages
to install" and "no package index refresh needed" — and the fake-tool harness
cannot distinguish them.  If the image ever ships `clamav`, or the package list
changes, `install Trivy` starts resolving dependencies against whatever indices
happen to be on disk, and the failure will be remote from its cause.

Decouple them: decide the index refresh on its own terms rather than as a side
effect of the install decision, and cover the all-present path with a test that
asserts the indices Trivy needs are available.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note.  Do not
modify `security-verdicts.json`.  Do not start hosted workflows.  Do not raise
`BOOTSTRAP_TIMEOUT_SECONDS` or the twelve-minute step cap.

Deferred verification stands, and note the plan's own caution: mirror throughput
varies by hours, so a single green run is not evidence the budget is sufficient.
Aggregation has still never published on fourteen triples.

STATUS: CHANGES_REQUESTED
