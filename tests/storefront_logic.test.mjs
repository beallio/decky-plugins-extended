import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDetailViewModel,
  CATALOG_ENDPOINTS,
  catalogForChannel,
  channelCounts,
  classifyPrimaryBadge,
  filterCatalog,
  normalizeCatalogEntry,
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
    plugins: { "example plugin": { provenance: "extended", versions: [matching] } },
  };
  assert.equal(buildDetailViewModel(entry, metadata).source.source_url, matching.source_url);

  const collision = structuredClone(metadata);
  collision.plugins["example plugin"].versions.push({ ...matching, repository: "owner/two" });
  const detail = buildDetailViewModel(entry, collision);
  assert.equal(detail.source, null);
  assert.equal(detail.sourceAmbiguous, true);
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
