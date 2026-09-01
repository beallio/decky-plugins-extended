import assert from "node:assert/strict";
import test from "node:test";

import {
  auditRecordsFrom,
  buildDetailViewModel,
  CATALOG_ENDPOINTS,
  catalogForChannel,
  channelCounts,
  classifyPrimaryBadge,
  filterCatalog,
  normalizeAuditTag,
  normalizeCatalogEntry,
  normalizeVersionName,
  parseOfficialVersionNote,
  shouldAcceptChannelResponse,
  sortCatalog,
} from "../static/storefront.js";

// Keep test entries close to the Decky catalog shape that the browser receives.
function plugin(overrides = {}) {
  return normalizeCatalogEntry({
    name: "Example Plugin",
    author: "Decky Author",
    description: "A useful utility.",
    tags: ["utility"],
    versions: [{ name: "2.0.0", hash: "a".repeat(64) }],
    visible: true,
    updated: "2026-08-30T00:00:00Z",
    downloads: 8,
    updates: 2,
    ...overrides,
  });
}

test("official version notes are removed from card descriptions", () => {
  assert.deepEqual(
    parseOfficialVersionNote(
      "Official store has 1.0.0; this store has 2.0.0. A useful utility.",
    ),
    {
      description: "A useful utility.",
      officialVersion: "1.0.0",
      storeVersion: "2.0.0",
    },
  );
  assert.deepEqual(parseOfficialVersionNote("No generated note."), {
    description: "No generated note.",
    officialVersion: "",
    storeVersion: "",
  });
});

test("audit badge precedence requires an exact current artifact identity", () => {
  const entry = plugin({
    description: "Official store has 1.0.0; this store has 2.0.0. Useful.",
  });
  const metadata = {
    plugins: {
      "example plugin": {
        name: "Example Plugin",
        provenance: "extended",
        versions: [
          {
            name: "2.0.0",
            hash: "a".repeat(64),
            tag: "2.0.0",
            repository: "owner/example",
            source_url: "https://github.com/owner/example",
          },
        ],
      },
    },
  };
  const invalidAudit = {
    repository: "https://github.com/owner/example",
    tag: "v2.0.0",
    identity_status: "CURRENT",
    outcome: "APPLIED",
    current_artifact_sha256: "b".repeat(64),
    classification: "BLOCK",
  };
  assert.deepEqual(
    classifyPrimaryBadge(entry, buildDetailViewModel(entry, metadata, []), "testing"),
    { kind: "newer", label: "Newer than official" },
  );
  assert.equal(buildDetailViewModel(entry, metadata, [invalidAudit]).audit, null);

  const validAudit = { ...invalidAudit, current_artifact_sha256: "a".repeat(64) };
  const detail = buildDetailViewModel(entry, metadata, [validAudit]);
  assert.equal(detail.audit, validAudit);
  assert.deepEqual(classifyPrimaryBadge(entry, detail, "testing"), {
    kind: "warning",
    label: "Audit block",
  });
});

test("large release warnings are channel-aware and explicit", () => {
  const entry = plugin();
  const metadata = {
    schema_version: 1,
    plugins: {
      "example plugin": {
        name: "Example Plugin",
        provenance: "extended",
        versions: [],
        warnings: [
          {
            kind: "large-plugin",
            name: "2.0.0",
            tag: "v2.0.0",
            repository: "owner/example",
            size_bytes: 157_248_535,
            limit_bytes: 67_108_864,
            included: true,
            prerelease: false,
          },
          {
            kind: "large-plugin",
            name: "3.0.0-beta.1",
            tag: "v3.0.0-beta.1",
            repository: "owner/example",
            size_bytes: 80_000_000,
            limit_bytes: 67_108_864,
            included: false,
            prerelease: true,
          },
          { kind: "large-plugin", size_bytes: "invalid" },
        ],
      },
    },
  };

  const stableDetail = buildDetailViewModel(entry, metadata, [], "stable");
  assert.deepEqual(
    stableDetail.largePluginWarnings.map((warning) => warning.tag),
    ["v2.0.0"],
  );
  assert.deepEqual(classifyPrimaryBadge(entry, stableDetail, "stable"), {
    kind: "warning",
    label: "Large release",
  });

  const testingDetail = buildDetailViewModel(entry, metadata, [], "testing");
  assert.deepEqual(
    testingDetail.largePluginWarnings.map((warning) => warning.tag),
    ["v2.0.0", "v3.0.0-beta.1"],
  );
});

test("audit envelopes and producer-normalized tags retain exact current identities", () => {
  const entry = plugin({
    name: "Release Notes",
    versions: [{ name: "1.2.3", hash: "d".repeat(64) }],
  });
  const source = {
    name: "1.2.3",
    hash: "d".repeat(64),
    tag: "v1.2.3.4",
    repository: "owner/release-notes",
    source_url: "https://github.com/owner/release-notes",
  };
  const audit = {
    repository: "owner/release-notes",
    tag: "v1.2.3.4",
    identity_status: "CURRENT",
    outcome: "APPLIED",
    current_artifact_sha256: "d".repeat(64),
    classification: "MANUAL_REVIEW",
  };
  const detail = buildDetailViewModel(
    entry,
    { schema_version: 1, plugins: { "release notes": { name: "Release Notes", provenance: "official", versions: [source] } } },
    auditRecordsFrom({ enforcement_mode: "enforce", releases: [audit] }),
  );
  assert.equal(normalizeVersionName("v1.2.3.4"), "1.2.3");
  assert.equal(detail.source, source);
  assert.equal(detail.audit, audit);
  assert.deepEqual(classifyPrimaryBadge(entry, detail, "stable"), {
    kind: "warning",
    label: "Manual review",
  });
  assert.deepEqual(auditRecordsFrom({ records: [audit] }), [audit]);
  assert.deepEqual(auditRecordsFrom({ releases: [audit] }), [audit]);
  assert.deepEqual(auditRecordsFrom({ payload: { releases: [audit] } }), [audit]);
});

test("audit tags retain producer case and reject case-distinct aliases", () => {
  const entry = plugin({
    name: "Case Tags",
    versions: [{ name: "1.2.3-BETA", hash: "c".repeat(64) }],
  });
  const source = {
    name: "1.2.3-BETA",
    hash: "c".repeat(64),
    tag: "1.2.3-BETA",
    repository: "owner/case-tags",
    source_url: "https://github.com/owner/case-tags",
  };
  const metadata = {
    plugins: {
      "case tags": {
        name: "Case Tags",
        provenance: "official",
        versions: [source],
      },
    },
  };
  const wrongCase = {
    repository: "owner/case-tags",
    tag: "v1.2.3-beta",
    identity_status: "CURRENT",
    outcome: "APPLIED",
    current_artifact_sha256: "c".repeat(64),
    classification: "BLOCK",
  };
  const exactCase = { ...wrongCase, tag: "v1.2.3-BETA" };

  assert.equal(normalizeAuditTag("release-v1.2.3-BETA"), "1.2.3-BETA");
  assert.equal(buildDetailViewModel(entry, metadata, [wrongCase]).audit, null);
  assert.equal(buildDetailViewModel(entry, metadata, [exactCase]).audit, exactCase);
  assert.equal(
    buildDetailViewModel(entry, metadata, [wrongCase, exactCase]).audit,
    exactCase,
  );
});

test("stable and testing endpoint selection and metadata counts are channel-specific", () => {
  assert.equal(catalogForChannel("stable"), "/plugins.json");
  assert.equal(catalogForChannel("testing"), "/testing_plugins.json");
  assert.equal(catalogForChannel("unknown"), "/plugins.json");
  assert.deepEqual(CATALOG_ENDPOINTS, {
    stable: "/plugins.json",
    testing: "/testing_plugins.json",
  });
  assert.deepEqual(
    channelCounts(
      {
        stable_count: 2,
        testing_count: 3,
        stable_extended_count: 1,
        testing_extended_count: 2,
      },
      "testing",
      [],
    ),
    { available: 3, extended: 2 },
  );
});

test("text and category filters are case-insensitive and direct tags still match", () => {
  const library = plugin({ name: "Library Shelf", tags: ["Library", "Games"] });
  const media = plugin({ name: "Radio", author: "Sound Maker", tags: ["Audio"] });
  const hidden = plugin({ name: "Hidden", visible: false });
  const results = filterCatalog([library, media, hidden], "SOUND", "media");
  assert.deepEqual(results.map((entry) => entry.name), ["Radio"]);
  assert.deepEqual(
    filterCatalog([library, media], "", "library").map((entry) => entry.name),
    ["Library Shelf"],
  );
  assert.deepEqual(
    filterCatalog([library, media], "", "games").map((entry) => entry.name),
    ["Library Shelf"],
  );
});

test("catalog sorting does not mutate source entries", () => {
  const entries = [
    plugin({ name: "Zulu", updated: "2026-01-01T00:00:00Z", downloads: 1 }),
    plugin({ name: "Alpha", updated: "2026-08-01T00:00:00Z", downloads: 40 }),
  ];
  const original = entries.map((entry) => entry.name);
  assert.deepEqual(sortCatalog(entries, "name").map((entry) => entry.name), ["Alpha", "Zulu"]);
  assert.deepEqual(sortCatalog(entries, "updated").map((entry) => entry.name), ["Alpha", "Zulu"]);
  assert.deepEqual(sortCatalog(entries, "installs").map((entry) => entry.name), ["Alpha", "Zulu"]);
  assert.deepEqual(entries.map((entry) => entry.name), original);
});

test("detail models keep exact source provenance and reject same-version collisions", () => {
  const entry = plugin();
  const matching = {
    name: "2.0.0",
    hash: "a".repeat(64),
    tag: "2.0.0",
    repository: "owner/one",
    source_url: "https://github.com/owner/one",
  };
  const metadata = {
    plugins: { "example plugin": { name: "Example Plugin", provenance: "extended", versions: [matching] } },
  };
  assert.equal(buildDetailViewModel(entry, metadata).source.source_url, matching.source_url);

  const collision = structuredClone(metadata);
  collision.plugins["example plugin"].versions.push({ ...matching, repository: "owner/two" });
  const detail = buildDetailViewModel(entry, collision);
  assert.equal(detail.source, null);
  assert.equal(detail.sourceAmbiguous, true);
});

test("catalog lookup names preserve Unicode provenance without lower-case guessing", () => {
  const entry = plugin({
    name: "Straße",
    versions: [{ name: "1.0.0", hash: "e".repeat(64) }],
  });
  const source = {
    name: "1.0.0",
    hash: "e".repeat(64),
    tag: "v1.0.0",
    repository: "owner/strasse",
    source_url: "https://github.com/owner/strasse",
  };
  const audit = {
    repository: "owner/strasse",
    tag: "1.0.0",
    identity_status: "CURRENT",
    outcome: "APPLIED",
    current_artifact_sha256: "e".repeat(64),
    classification: "PASS",
  };
  const metadata = {
    schema_version: 1,
    plugins: {
      strasse: {
        name: "STRASSE",
        catalog_names: ["Straße"],
        provenance: "extended",
        versions: [source],
      },
    },
  };
  const detail = buildDetailViewModel(entry, metadata, [audit]);
  assert.equal(detail.source, source);
  assert.equal(detail.audit, audit);
  assert.equal(detail.provenance, "extended");
  assert.deepEqual(classifyPrimaryBadge(entry, detail, "stable"), {
    kind: "extended",
    label: "Extended only",
  });
  assert.deepEqual(filterCatalog([entry], "", "extended", metadata.plugins), [entry]);
});

test("catalog lookup names preserve ordinary case-only producer merges", () => {
  const entry = plugin({
    name: "Shared Plugin",
    versions: [{ name: "1.0.0", hash: "f".repeat(64) }],
  });
  const source = {
    name: "1.0.0",
    hash: "f".repeat(64),
    tag: "1.0.0",
    repository: "owner/shared-plugin",
    source_url: "https://github.com/owner/shared-plugin",
  };
  const metadata = {
    schema_version: 1,
    plugins: {
      "shared plugin": {
        name: "shared plugin",
        catalog_names: ["Shared Plugin"],
        provenance: "extended",
        versions: [source],
      },
    },
  };

  const detail = buildDetailViewModel(entry, metadata);
  assert.equal(detail.source, source);
  assert.equal(detail.provenance, "extended");
  assert.deepEqual(filterCatalog([entry], "", "extended", metadata.plugins), [entry]);
});

test("missing provenance metadata is unavailable or unknown, never official", () => {
  const entry = plugin();
  assert.equal(buildDetailViewModel(entry, null).provenanceLabel, "Unavailable");
  assert.equal(buildDetailViewModel(entry, { schema_version: 1, plugins: {} }).provenanceLabel, "Unknown");
});

test("malformed catalog data is normalized defensively", () => {
  assert.deepEqual(normalizeCatalogEntry(null), {
    id: undefined,
    name: "Unnamed plugin",
    author: "Unknown author",
    description: "",
    officialVersion: "",
    storeVersion: "",
    tags: [],
    versions: [],
    visible: true,
    imageUrl: "",
    created: "",
    updated: "",
    downloads: 0,
    updates: 0,
  });
});

test("only the latest channel request may update the rendered state", () => {
  assert.equal(shouldAcceptChannelResponse(4, 4), true);
  assert.equal(shouldAcceptChannelResponse(5, 4), false);
});
