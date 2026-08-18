# Review — quota-safe-security-audit (round 08)

Branch: `feat/quota-safe-security-audit`
Reviewed against: `docs/plans/2026-08-18_quota-safe-security-audit.md`

## Verdict

Changes requested on Task 3A primitives. Expected-worklist loading, shard assignment, v1 separation,
atomic writers, and scope discipline are correct. Progress identity and shard-manifest validation
still accept or rewrite noncanonical evidence, so Task 3A is not yet closed. Do not start Task 4.

## Gate status

- `tests/test_audit_worker_snapshot.py`: `14 passed`; the prior full repository gate remains green.
- Root reproduced `resume_identity_matches()` returning true when candidate and expected worklist
  fingerprints differ because the fingerprint is absent from `_RESUME_IDENTITY_FIELDS`.
- Root reproduced a manifest accepting `attempted=[A]`, `report=[]`; reversed worklist order was
  silently sorted; and mixed-case repository plus whitespace IDs were normalized and accepted.
- Terra additionally found malformed v2 entries are not validated when the root fingerprint differs:
  the loader returns an empty resume set before validating the document.
- The tree is clean, marker valid at `748904122fc0311aa38f71de67e0bb3aca29d59c`, and no
  identifiable Task-3A genuine-red log was preserved; existing red/green logs are from Task 2.

## Required changes

1. Add `worklist_fingerprint` to the resume identity fence. Preserve legacy behavior by allowing
   v1 caller expectations/candidates to both omit it, while a worklist caller must supply the exact
   fingerprint in both. Add a direct `resume_identity_matches()` mismatch test in addition to loader
   tests.
2. Validate an entire v2 progress document before treating a valid different fingerprint as
   non-resumable. Require exact v2 root and entry keys/types, canonical fingerprint syntax at root
   and entry, one consistent root/entry fingerprint, an identity key equal to the entry's canonical
   repository/release/asset identity, and an object report. Make the v2 writer validate what it is
   about to persist. Only after structural validation may a different valid root fingerprint return
   `{}`. Add malformed-entry plus different-fingerprint cases and writer rejection cases.
3. Make manifest identities strictly canonical: the repository input must already equal its
   canonical URL, and both IDs must match positive ASCII decimal strings without whitespace,
   leading zeros, sign, Unicode digits, or zero. Apply the same strict identity seam in
   `audit_worklist.py`. Add negatives for each alias family and for two textual aliases of the same
   underlying identity.
4. Preserve supplied worklist/report order instead of lexically sorting identities. Reject or
   preserve canonical input; never rewrite it into another ordering. Require
   `attempted_identities == report_identities` as ordered lists for every valid manifest, including a
   partial checkpoint; both remain unique subsets of assigned. Add a two-release case whose payload
   order differs from lexical ID order plus the partial attempted/report mismatch reproduced above.
5. Add an expected-manifest validation seam usable by later worker/aggregation code. Given a
   validated worklist and shard index, compare exact fingerprint, source revision, shard count,
   shard index, and the ordered assigned identity list computed by `select_worklist_shard()`; reject
   valid-shape but wrong values. Cover each mismatch separately and keep empty-shard support.
6. Add the tests first and preserve their genuine failure output in a Task-3A-specific file under
   `/tmp/decky-plugins-extended/`. Run focused tests and the complete quality gate, preserve green
   evidence, keep `security-verdicts.json` unchanged, commit only this correction, clean the tree,
   recreate the marker, and stop after Task 3A.

STATUS: CHANGES_REQUESTED
