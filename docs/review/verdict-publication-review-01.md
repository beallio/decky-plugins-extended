# Review — verdict-publication (round 01)

Branch: `feat/verdict-publication`
Reviewed against: `docs/plans/2026-08-03_verdict-publication.md`
Reviewed commit: `949ea35`

## Verdict

The production code is right, and the workflow step is better than I asked for. The problem is
that the two tests carrying the most weight do not test what they appear to, and one of them
was load-bearing before this branch and no longer is.

What is genuinely good:

- The store moves to a tracked `security-verdicts.json` while `.audit-cache/` stays ignored for
  ephemeral reports. That separation is the right one.
- `test_fresh_clone_reads_tracked_verdicts_and_blocks_release` is the correct *shape*: it
  removes `.audit-cache`, `chdir`s to a clean directory, runs the real `generate_json.main()`,
  and asserts on normalised version **and** artifact hash across both catalogs, with the
  fallback at `versions[0]`. Nothing mocked where it matters.
- The workflow step guards on `git diff --quiet`, stages only `security-verdicts.json`, uses a
  bot identity, and rebases-and-retries once without force-pushing. The changed-count message
  is a nice touch.

## Gate status

`scripts/orchestration/run-quality-gates` -> pass. Run by me on `949ea35`.

## Required changes

### 1. The fresh-clone test passes on `dev`, so it does not demonstrate the bug

Verification step 1 was explicit: *"Run this test against `dev`'s code first. It must fail
there — that failure is the bug this sub-plan fixes, and a test that cannot demonstrate it is
not evidence of anything."*

I ran it. In a clean worktree of `dev`, with this branch's `tests/test_catalog_gate.py` and
`tests/conftest.py` copied in, `-k fresh_clone` reports **1 passed**. The entire premise of this
sub-plan is that `dev` cannot see verdicts from a fresh clone, and the test that is supposed to
prove it is green against `dev`.

The cause is the new autouse fixture in `tests/conftest.py`:

```python
monkeypatch.setattr(
    audit_plugins, "VERDICTS_FILE", str(tmp_path / "security-verdicts.json")
)
```

It sets `VERDICTS_FILE` to an **absolute** path. On `dev`, `load_verdicts()` computes
`os.path.join(cache_dir, VERDICTS_FILE)`, and `os.path.join` discards the first argument when
the second is absolute:

```
os.path.join('.audit-cache', '/tmp/x/security-verdicts.json') -> '/tmp/x/security-verdicts.json'
```

So on `dev` the lookup silently reads the tracked file too, and the distinction this branch
exists to create is erased by the test harness.

Fix the fixture so it isolates without neutralising. Keep `VERDICTS_FILE` a **relative**
filename and isolate via `monkeypatch.chdir(tmp_path)`, which is what the fresh-clone test
already does anyway. Then re-run against `dev` and record the failure before re-running on the
branch.

### 2. `test_atomic_write_failure_preserves_prior_verdict_file` is now vacuous

`tests/test_audit_verdicts.py:258-281`. The call site was updated for the new signature, which
is correct, but the fixture path was not:

- `_seed_pass_verdict()` writes `tmp_path/verdicts.json` (line 102);
- `_write_verdicts_atomic(replacement)` now writes `VERDICTS_FILE`, which the autouse fixture
  points at `tmp_path/security-verdicts.json`;
- the final assertion reads `tmp_path/verdicts.json` — a file the writer never touches.

Proved rather than inferred: I added a line that writes `"CORRUPTED"` directly to the real
destination immediately before `os.replace`, leaving the monkeypatched `OSError` intact. The
test still reports **1 passed**. It would pass against a writer that destroys the store on
every failure.

This test was mutation-verified as load-bearing when `audit-verdicts` merged — replacing
`os.replace` with truncate-then-move turned it red. This branch silently removed that
protection. Point the seed and the assertion at the same path the writer uses, then confirm the
truncate-then-move mutation turns it red again.

### 3. Re-run the plan's verification once 1 and 2 are fixed

Steps 1, 5 and 6 of the plan all depend on the fresh-clone test being able to fail. Their
recorded results are not currently meaningful. In particular step 6 — pointing `load_verdicts()`
back at `.audit-cache/verdicts.json` only, and confirming the fresh-clone test goes red — cannot
have been a real signal while the fixture was overriding the path.

## Note on the autouse fixture

An `autouse=True` fixture that rewrites a module constant for the entire suite is a large
blast radius for a test-isolation problem. It is what defeated both findings above. Consider
scoping it to the tests that need it, or dropping it in favour of `monkeypatch.chdir` plus a
relative filename, which isolates just as well and cannot mask a path bug.

STATUS: CHANGES_REQUESTED
