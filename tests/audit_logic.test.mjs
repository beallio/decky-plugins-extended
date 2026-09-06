import assert from "node:assert/strict";
import test from "node:test";

import {
  auditEnforcementCopy,
  groupAuditRecords,
  groupId,
  repositorySlug,
  summarizeAudit,
} from "../static/audit.js";

function record(repository, release, classification, extra = {}) {
  return { repository, release, classification, ...extra };
}

test("enforcement copy follows the published mode", () => {
  assert.match(auditEnforcementCopy("enforce"), /are excluded from the catalogs/);
  assert.match(auditEnforcementCopy("report-only"), /No releases are currently excluded/);
  assert.match(auditEnforcementCopy("something-else"), /Consult the repository policy/);
  // Never render an empty mode as if it were a known one.
  assert.match(auditEnforcementCopy(""), /unknown/);
});

test("repository slugs and fragment ids survive the URL forms in the record", () => {
  for (const value of [
    "https://github.com/Example/Plugin",
    "https://www.github.com/example/plugin/",
    "https://github.com/example/plugin.git",
  ]) {
    assert.equal(repositorySlug(value), "example/plugin");
  }
  assert.equal(groupId("https://github.com/example/plugin"), "plugin-example-plugin");
});

test("records group by plugin with blocked plugins first", () => {
  const groups = groupAuditRecords([
    record("https://github.com/example/manual", "v2.0.0@2", "MANUAL_REVIEW"),
    record("https://github.com/example/manual", "v1.0.0@1", "PASS"),
    record("https://github.com/example/blocked", "v1.0.0@1", "PASS"),
    record("https://github.com/example/blocked", "v2.0.0@2", "BLOCK"),
  ]);

  assert.deepEqual(groups.map((group) => group.slug), [
    "example/blocked",
    "example/manual",
  ]);
  // One BLOCK release makes the plugin blocked however many others passed.
  assert.equal(groups[0].blocked, true);
  assert.equal(groups[0].classification, "BLOCK");
  assert.equal(groups[1].blocked, false);
  assert.equal(groups[1].classification, "MANUAL_REVIEW, PASS");
  assert.deepEqual(groups[1].records.map((entry) => entry.release), [
    "v1.0.0@1",
    "v2.0.0@2",
  ]);
});

test("grouping ignores records with no repository and tolerates junk", () => {
  const groups = groupAuditRecords([
    record("", "v1.0.0@1", "PASS"),
    null,
    "not a record",
    record("https://github.com/example/plugin", "v1.0.0@1", "PASS"),
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groupAuditRecords(undefined), []);
});

test("the summary counts every tier, including ones it does not name", () => {
  const counts = summarizeAudit([
    record("https://github.com/a/a", "1", "BLOCK"),
    record("https://github.com/a/a", "2", "AUDIT_ERROR"),
    record("https://github.com/a/a", "3", "MANUAL_REVIEW"),
    record("https://github.com/a/a", "4", "PASS"),
    record("https://github.com/a/a", "5", "PASS_WITH_WARNINGS"),
  ]);
  assert.deepEqual(counts, {
    BLOCK: 1,
    AUDIT_ERROR: 1,
    MANUAL_REVIEW: 1,
    other: 2,
  });
});
