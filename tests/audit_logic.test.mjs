import assert from "node:assert/strict";
import test from "node:test";

import {
  auditEnforcementCopy,
  auditFilterOptions,
  filterAuditRecords,
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

const FILTER_RECORDS = [
  record("https://github.com/owner/alpha", "v1.0.0@1", "MANUAL_REVIEW", {
    rule_ids: ["ROOT_ACCESS", "EXEC_EXEC"],
  }),
  record("https://github.com/owner/alpha", "v2.0.0@2", "PASS", { rule_ids: [] }),
  record("https://github.com/other/beta", "v1.0.0@1", "MANUAL_REVIEW", {
    rule_ids: ["ROOT_ACCESS"],
  }),
  record("https://github.com/other/gamma", "v1.0.0@1", "AUDIT_ERROR"),
];

test("search matches the repository slug a reader can see and link to", () => {
  const bySlug = filterAuditRecords(FILTER_RECORDS, { query: "owner/" });
  assert.deepEqual([...new Set(bySlug.map((r) => repositorySlug(r.repository)))], [
    "owner/alpha",
  ]);
  // Case-insensitive, and matches a fragment of either half of the slug.
  assert.equal(filterAuditRecords(FILTER_RECORDS, { query: "GAMMA" }).length, 1);
  assert.equal(filterAuditRecords(FILTER_RECORDS, { query: "" }).length, 4);
  assert.equal(filterAuditRecords(FILTER_RECORDS, { query: "nothing" }).length, 0);
});

test("classification and rule filters narrow to matching releases, not whole plugins", () => {
  const manual = filterAuditRecords(FILTER_RECORDS, { classification: "MANUAL_REVIEW" });
  assert.equal(manual.length, 2);
  // alpha keeps only its MANUAL_REVIEW release, not its PASS one.
  assert.deepEqual(
    groupAuditRecords(manual).map((group) => [group.slug, group.records.length]),
    [["other/beta", 1], ["owner/alpha", 1]],
  );

  const rooted = filterAuditRecords(FILTER_RECORDS, { rule: "EXEC_EXEC" });
  assert.deepEqual(rooted.map((r) => r.release), ["v1.0.0@1"]);
  assert.equal(filterAuditRecords(FILTER_RECORDS, { rule: "ROOT_ACCESS" }).length, 2);

  // Filters compose.
  assert.equal(
    filterAuditRecords(FILTER_RECORDS, {
      query: "owner/alpha",
      classification: "MANUAL_REVIEW",
      rule: "ROOT_ACCESS",
    }).length,
    1,
  );
  assert.equal(
    filterAuditRecords(FILTER_RECORDS, {
      query: "other/beta",
      rule: "EXEC_EXEC",
    }).length,
    0,
  );
});

test("filter options come from the record, sorted and deduplicated", () => {
  assert.deepEqual(auditFilterOptions(FILTER_RECORDS), {
    classifications: ["AUDIT_ERROR", "MANUAL_REVIEW", "PASS"],
    rules: ["EXEC_EXEC", "ROOT_ACCESS"],
  });
  assert.deepEqual(auditFilterOptions([]), { classifications: [], rules: [] });
  assert.deepEqual(auditFilterOptions(undefined), { classifications: [], rules: [] });
});
