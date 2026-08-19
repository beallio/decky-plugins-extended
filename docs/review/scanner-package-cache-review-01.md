# Review — scanner-package-cache (round 1)

Branch: `feat/scanner-package-cache`
Reviewed against: `docs/plans/2026-08-19_scanner-package-cache.md`
Reviewed commits: `7dddea7`, `ad22d99`

## Verdict

The integrity property the plan was gated on is correctly implemented.
Installation still goes through `apt-get` with `Dir::Cache::archives`, so every
archive is verified against the signed index before use. There is no `dpkg -i`
anywhere in the script, and no option permitting unauthenticated or unverified
packages. The cache key binds the runner image, the package set, and the
bootstrap script's own hash; restore is `continue-on-error`; and saving is
restricted so fourteen shards do not race.

One defect blocks acceptance: the handling of a hash mismatch turns a routine
event into a shard outage, and it does so in the name of a security property
that `apt` already provides unconditionally.

## Gate status

`scripts/orchestration/run-quality-gates` passed at `ad22d99`: actionlint
verified with all three mutation negative controls rejected, Ruff check and
format clean, Pytest `1015 passed, 63 subtests passed`. Review notes not
deleted, worktree clean, `security-verdicts.json` unchanged from
`git merge-base dev HEAD`.

The integrity transcript is saved and shows the four cache cases passing,
including tamper rejection and the assertion that archive verification is never
weakened.

## Required changes

### 1. A hash mismatch must discard the cache, not fail the shard

The warm path treats `Hash Sum mismatch` as tampering and exits without
falling back:

```bash
if grep -Fq "Hash Sum mismatch" "$apt_output"; then
  # A cached archive with bytes that do not match the signed package
  # index is untrusted input. Never turn that into a mirror fallback.
  exit "$warm_status"
fi
```

The reasoning does not hold, because the fallback was never the thing keeping
the tampered bytes out. `apt-get` verifies every archive against the signed
index in both paths: on the warm path it refuses the bad file, and on a cold
install it re-downloads and verifies from the mirror. A tampered archive cannot
be installed either way. Failing hard therefore buys no security — it only
removes the recovery.

What it does buy is a new way to lose a shard. The restore key is deliberately
permissive:

```text
restore_key=scanner-package-cache-v1-${runner_image}-
```

That prefix matches entries saved under a *different* package set or bootstrap
hash, which is the intended behavior for partial warming. It also means a shard
can routinely restore archives that no longer match the current index. When that
produces a hash mismatch — an honest staleness event, not an attack — the shard
now dies with no retry and no cold fallback, and aggregation refuses to publish
for the whole corpus. That is the exact failure shape this plan exists to remove.

Discard the offending archives and continue with a cold install. Log the
mismatch loudly, naming the archive, so a genuine poisoning attempt is still
visible in the job log rather than silently absorbed — detection is worth
keeping, the outage is not.

While changing this, reduce the dependence on matching apt's English output.
`LC_ALL=C` pins the locale, but keying behavior on the exact phrase
`Hash Sum mismatch` will silently change meaning if that wording ever moves.
Prefer treating any warm-path failure as "cache unusable, fall back", and use
the message only to decide how loudly to report it.

### 2. Do not leave the cache directory untracked in the working tree

`BASE_APT_ARCHIVE_DIR` defaults to `$PWD/.scanner-package-cache/apt-archives`,
and `.scanner-package-cache` is not in `.gitignore`:

```text
git check-ignore -v .scanner-package-cache  ->  path not ignored
```

Every local run of the bootstrap, and every CI shard, now leaves an untracked
directory in the repository working tree. The plan's own Verification section
requires `git status --porcelain` to be empty, and any future step that checks a
clean tree on a shard would break on it. Add the path to `.gitignore`.

### 3. Reconsider tying cache population to shard 0

Saving is gated on `success() && matrix.shard_index == 0`. Single-writer
discipline is right, but it makes cache population depend on one specific shard
succeeding. Shard 0 has the same chance as any other of drawing the slow runner,
and while the cache is cold that is precisely when a shard is most likely to
fail — so the run that most needs to populate the cache is the run most able to
fail to. In run `32285669639` the unlucky shard was 13; had it been 0, the cache
would not have been written.

Allow any shard to save under the identical key and let the first writer win, or
choose another single writer that does not depend on the outcome of the work
being cached. A redundant save attempt logs a benign "already exists" and is
already `continue-on-error`.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note. Do not
modify `security-verdicts.json`. Do not start hosted workflows. Do not change
the twelve-minute scanner step cap, the 600-second bootstrap budget, or the
phase allocation model.

Deferred verification stands. Aggregation has still never published on fourteen
triples: runs `32222340066`, `32275727649`, and `32285669639` reached it with
thirteen, four, and thirteen shards and all three correctly refused.

STATUS: CHANGES_REQUESTED
