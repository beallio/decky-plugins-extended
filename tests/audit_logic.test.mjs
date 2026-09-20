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
import { auditGroupId } from "../static/storefront.js";

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
    record("https://github.com/example/manual", "v2.0.0@2", "MANUAL_REVIEW", {
      asset_id: "2",
    }),
    record("https://github.com/example/manual", "v1.0.0@1", "PASS", {
      asset_id: "1",
    }),
    record("https://github.com/example/blocked", "v1.0.0@1", "PASS", {
      asset_id: "1",
    }),
    record("https://github.com/example/blocked", "v2.0.0@2", "BLOCK", {
      asset_id: "2",
    }),
  ]);

  assert.deepEqual(groups.map((group) => group.key), [
    "example/blocked",
    "example/manual",
  ]);
  // One BLOCK release makes the plugin blocked however many others passed.
  assert.equal(groups[0].blocked, true);
  assert.equal(groups[0].classification, "BLOCK");
  assert.equal(groups[1].blocked, false);
  assert.equal(groups[1].classification, "MANUAL_REVIEW, PASS");
  assert.deepEqual(groups[1].records.map((entry) => entry.release), [
    "v2.0.0@2",
    "v1.0.0@1",
  ]);
});

test("releases order newest first by asset id, not by version string", () => {
  // Asset ids are monotonic, so they order releases chronologically without
  // parsing a version. Comparing release strings put v2.0.10 before v2.0.2.
  const [group] = groupAuditRecords([
    record("https://github.com/morwy/hltb", "v2.0.2@216560670", "PASS", {
      asset_id: "216560670",
    }),
    record("https://github.com/morwy/hltb", "v2.0.10@545769966", "PASS", {
      asset_id: "545769966",
    }),
    record("https://github.com/morwy/hltb", "v2.0.3@216795668", "PASS", {
      asset_id: "216795668",
    }),
  ]);
  assert.deepEqual(group.records.map((entry) => entry.tag ?? entry.release), [
    "v2.0.10@545769966",
    "v2.0.3@216795668",
    "v2.0.2@216560670",
  ]);
  // Exactly one release is marked, and it is the newest.
  assert.deepEqual(group.records.map((entry) => entry.newestAudited === true), [
    true,
    false,
    false,
  ]);

  // Tags that differ only by a git hash still order, where a version cannot.
  const [dev] = groupAuditRecords([
    record("https://github.com/a/b", "v0.3.0-dev.gaaa@442903821", "PASS", {
      asset_id: "442903821",
    }),
    record("https://github.com/a/b", "v0.3.0-dev.gbbb@447779786", "PASS", {
      asset_id: "447779786",
    }),
  ]);
  assert.equal(dev.records[0].asset_id, "447779786");

  // A missing or unparseable asset id must not throw or win.
  const [mixed] = groupAuditRecords([
    record("https://github.com/a/c", "v1@1", "PASS", { asset_id: "5" }),
    record("https://github.com/a/c", "v2@2", "PASS"),
  ]);
  assert.equal(mixed.records[0].asset_id, "5");
});

test("a group takes the plugin name from its records and keeps every repository", () => {
  const [named] = groupAuditRecords([
    record("https://github.com/owner/plugin", "v1@1", "PASS", {
      plugin_name: "Nice Plugin",
    }),
    record("https://github.com/owner/plugin", "v2@2", "PASS"),
  ]);
  assert.equal(named.name, "Nice Plugin");
  assert.deepEqual(named.repositories, ["owner/plugin"]);

  // A record with no name falls back to the repository as its identity.
  const [unnamed] = groupAuditRecords([
    record("https://github.com/owner/other", "v1@1", "PASS"),
  ]);
  assert.equal(unnamed.name, "");
  assert.equal(unnamed.key, "owner/other");
  // Still addressable, just by repository -- the catalog links by name, so an
  // unnamed group is simply not linked to rather than linked to wrongly.
  assert.equal(unnamed.id, groupId("https://github.com/owner/other"));
});

test("one plugin with two repositories is one group, not two", () => {
  // A fork and its upstream, and an old URL left behind by a rename, both
  // produced two rows with the same name when groups were keyed by repository.
  const groups = groupAuditRecords([
    record("https://github.com/beallio/sdh-playtime-beallio-remix", "v3@3", "PASS", {
      plugin_name: "PlayTime",
      asset_id: "3",
    }),
    record("https://github.com/0u73r-h34v3n/sdh-playtime", "v1@1", "PASS", {
      plugin_name: "PlayTime",
      asset_id: "1",
    }),
    record("https://github.com/danielcopper/decky-romm-sync", "v1@1", "PASS", {
      plugin_name: "Tender",
      asset_id: "1",
    }),
    record("https://github.com/danielcopper/romm-tender", "v2@2", "PASS", {
      plugin_name: "Tender",
      asset_id: "2",
    }),
  ]);

  assert.equal(groups.length, 2);
  // Sorted by the displayed name, not by a slug the reader never sees.
  assert.deepEqual(groups.map((group) => group.name), ["PlayTime", "Tender"]);
  const [playtime] = groups;
  assert.equal(playtime.records.length, 2);
  assert.deepEqual(playtime.repositories, [
    "0u73r-h34v3n/sdh-playtime",
    "beallio/sdh-playtime-beallio-remix",
  ]);
  // The anchor follows the plugin, so the catalog can link to it by name.
  assert.equal(playtime.id, groupId("PlayTime"));
  // Newest across both repositories, not within one of them.
  assert.equal(playtime.records[0].asset_id, "3");
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

test("search matches the plugin name as well as the repository slug", () => {
  const named = [
    record("https://github.com/owner/alpha", "v1@1", "PASS", {
      plugin_name: "Alpha Tool",
    }),
    record("https://github.com/other/beta", "v1@1", "PASS", {
      plugin_name: "Beta Thing",
    }),
  ];
  assert.equal(filterAuditRecords(named, { query: "alpha tool" }).length, 1);
  assert.equal(filterAuditRecords(named, { query: "BETA" }).length, 1);
  assert.equal(filterAuditRecords(named, { query: "other/" }).length, 1);
});

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
    groupAuditRecords(manual).map((group) => [group.key, group.records.length]),
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

test("the catalog builds the same fragment the audit page answers to", () => {
  // storefront.js duplicates this transform so the catalog page does not have
  // to fetch audit.js. If they ever disagree, every "Open audit log" link
  // lands on the top of the page instead of the plugin, silently.
  for (const repository of [
    "https://github.com/owner/plugin",
    "https://github.com/Owner/Plugin.git",
    "https://www.github.com/owner/plugin/",
    "owner/plugin",
    "https://github.com/0u73r-h34v3n/sdh-playtime",
    "https://github.com/beallio/SDH-PlayTime-beallio-remix",
    "",
  ]) {
    assert.equal(auditGroupId(repository), groupId(repository), repository);
  }
  // It carries a plugin name now, since that is what a group is keyed on.
  for (const name of ["PlayTime", "HLTB for Deck", "Decky-Framegen", "steam-achievements"]) {
    assert.equal(auditGroupId(name), groupId(name), name);
  }
  assert.equal(auditGroupId("HLTB for Deck"), "plugin-hltb-for-deck");
});
