# Review — env-harvest-precision (round 1)

Branch: `feat/env-harvest-precision`
Reviewed against: `docs/plans/2026-08-21_env-harvest-precision.md`
Reviewed commits: `ba4501b`, `1bb7c7c`, `23a7b29`, `427f8f4`

## Verdict

The retargeting is correct and it fixes more than expected: whole-environment
harvesting was **not detected at all** before this branch. Verified directly
against `dev`:

```text
                          dev (before)                  branch (after)
dict(os.environ)          NO FINDING                     HARVEST / MANUAL_REVIEW
os.environ.items() loop   NO FINDING                     HARVEST / MANUAL_REVIEW
def get(key): ...environ.get(key)   MANUAL_REVIEW        NO FINDING
```

The old pattern required one of five keywords on the line, so the actual
exfiltration-shaped construct — copying the environment — slipped through while
a parameter named `key` was escalated. That inversion is now resolved, and the
84-of-143 corpus figure is independently reproduced in the detection log.

One change blocks acceptance: it demotes third-party credential reads, which the
plan explicitly required preserving.

## Gate status

`run-quality-gates` passed at `427f8f4`: actionlint verified with all three
mutation negative controls rejected, Ruff check and format clean, Pytest
`1023 passed, 78 subtests passed`. Worktree clean, `security-verdicts.json`
unchanged. Both required mutations are present and each fails its intended
direction.

## Required changes

### 1. Reading someone else's credentials is no longer distinguished from reading your own

`SENSITIVE_ENV_READ` is emitted unconditionally at `PASS_WITH_WARNINGS` for any
credential-shaped name (`audit_plugins.py:1952`). Measured on this branch:

```text
os.environ.get("AWS_SECRET_ACCESS_KEY")   dev: MANUAL_REVIEW  ->  now: PASS_WITH_WARNINGS
os.environ["GITHUB_TOKEN"]                dev: MANUAL_REVIEW  ->  now: PASS_WITH_WARNINGS
os.environ.get("DEPLOY_PRIVATE_KEY")      dev: MANUAL_REVIEW  ->  now: PASS_WITH_WARNINGS
os.environ.get("SYNCTHING_API_KEY")       dev: MANUAL_REVIEW  ->  now: PASS_WITH_WARNINGS
```

A Steam Deck plugin reading `SYNCTHING_API_KEY` is doing its job. A plugin
reading `AWS_SECRET_ACCESS_KEY` or `GITHUB_TOKEN` is reaching for credentials
that are not its business. Those now receive identical verdicts.

`_PROTECTED_ENV_PREFIXES` (`AWS_`, `CF_`, `CLOUDFLARE_`, `GITHUB_`, `SSH_`,
`STEAM_`, ...) and the `PRIVATE_KEY` suffix encoded exactly that distinction,
and both were deleted. `1bb7c7c` argues they are unnecessary because named reads
"now begin at PASS_WITH_WARNINGS" — but their purpose was never to guard a
demotion path. They marked a class of variables as not-ordinary-plugin-business.
Starting everything at warning level does not make that judgment redundant; it
discards it.

The plan's Task 3 required these to "keep their protective effect either way",
and Verification step 4 required a protected-prefix read and a `PRIVATE_KEY`
read not to be demoted. Neither holds.

Restore the distinction: a credential-shaped read whose name carries a protected
prefix or the `PRIVATE_KEY` suffix stays `MANUAL_REVIEW`; everything else is the
new warning. Add tests asserting both halves, and a mutation that removes the
protected list must fail one of them.

### 2. Re-examine whether plugin-namespacing should return

Retiring `_downgrade_plugin_namespaced_env_findings()` is defensible once
targeted reads start at warning level, and removing an overlapping verdict path
was the right instinct. But with change 1 applied, some reads become
`MANUAL_REVIEW` again, and the question of whether a plugin reading its *own*
namespaced variable should be demoted returns with it.

Decide deliberately and record the reasoning: either namespacing is no longer
needed because the protected list already carves out the risky names, or it
returns for the protected-prefix cases. Do not reintroduce two overlapping
mechanisms whose interaction must be traced to predict a verdict.

### 3. State the JS gap in the detection log

`_JS_ENV_HARVEST_PATTERN` covers spread, `Object.keys/values/entries`, and
`JSON.stringify`. The Python side additionally catches `list(os.environ)` and
`.items()/.keys()/.values()`; the JS side has no equivalent for
`Array.from(process.env)` or `for (const k in process.env)`.

Verification step 2 required any construct a reasonable reader would call
harvesting but the pattern does not catch to be listed explicitly as a known
gap. Add these to the detection log, or cover them.

## Scope boundary

No merge, push, release, or GitHub mutation is authorized by this note. Do not
modify `security-verdicts.json`, re-run the audit, or edit preserved evidence.

STATUS: CHANGES_REQUESTED
