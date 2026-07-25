// Decky sorts the store server-side: the frontend appends
// ?sort_by=<name|date|downloads>&sort_direction=<asc|desc> to the store URL and
// renders the response array in the order it arrives. A static JSON file ignores
// those params, so the sort dropdown does nothing. Reorder the catalog here to
// match what plugins.deckbrew.xyz returns for the same query.
//
// Install counts live in D1 (see schema.sql) rather than in the JSON, because
// the catalogs are regenerated from scratch on every deploy. They are folded
// into the response before sorting so sort_by=downloads sees real numbers.
// Everything degrades to the previous behaviour when the DB binding is absent.

const SORTABLE_PATHS = new Set(["/plugins.json", "/testing_plugins.json"]);

// After downloading a plugin, Decky POSTs <store-url>/<name>/versions/<ver>/increment
// ?isUpdate=<True|False> to bump the install counter.
const INCREMENT_PATH = /^\/(?:plugins|testing_plugins)\.json\/([^/]+)\/versions\/([^/]+)\/increment$/;

function timestamp(value) {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

// Upstream compares names by code point, not locale or case-insensitively:
// descending yields vibrantDeck, steamdeck-input-disabler, XR Gaming, XIVOmega.
function getComparator(sortBy) {
  switch (sortBy) {
    case "name":
      return (a, b) => {
        const left = String(a.name ?? "");
        const right = String(b.name ?? "");
        return left < right ? -1 : left > right ? 1 : 0;
      };
    case "date":
      return (a, b) => timestamp(a.created) - timestamp(b.created);
    case "downloads":
      return (a, b) => (Number(a.downloads) || 0) - (Number(b.downloads) || 0);
    default:
      return null;
  }
}

async function loadCounts(env) {
  if (!env?.DB) return null;
  try {
    const { results } = await env.DB.prepare(
      "SELECT plugin, version, downloads, updates FROM counts",
    ).all();
    if (!results?.length) return null;

    const counts = new Map();
    for (const row of results) {
      if (!counts.has(row.plugin)) counts.set(row.plugin, new Map());
      counts.get(row.plugin).set(row.version, {
        downloads: Number(row.downloads) || 0,
        updates: Number(row.updates) || 0,
      });
    }
    return counts;
  } catch (e) {
    // A counter is not worth failing the catalog over.
    console.error("Could not read install counts:", e);
    return null;
  }
}

// Counts are added to whatever the catalog already carries: entries merged with
// an upstream plugin keep Deckbrew's totals and gain the installs made here.
function applyCounts(plugins, counts) {
  for (const plugin of plugins) {
    const perVersion = counts.get(plugin.name);
    if (!perVersion) continue;

    let downloads = 0;
    let updates = 0;
    for (const version of plugin.versions ?? []) {
      const row = perVersion.get(version.name);
      if (!row) continue;
      version.downloads = (Number(version.downloads) || 0) + row.downloads;
      version.updates = (Number(version.updates) || 0) + row.updates;
      downloads += row.downloads;
      updates += row.updates;
    }
    plugin.downloads = (Number(plugin.downloads) || 0) + downloads;
    plugin.updates = (Number(plugin.updates) || 0) + updates;
  }
}

async function recordInstall(env, plugin, version, isUpdate) {
  if (!env?.DB) return;
  try {
    await env.DB.prepare(
      `INSERT INTO counts (plugin, version, downloads, updates) VALUES (?, ?, ?, ?)
       ON CONFLICT(plugin, version) DO UPDATE SET
         downloads = downloads + excluded.downloads,
         updates   = updates   + excluded.updates`,
    )
      .bind(plugin, version, isUpdate ? 0 : 1, isUpdate ? 1 : 0)
      .run();
  } catch (e) {
    // Never fail the install over a counter; Decky only checks the status code.
    console.error("Could not record install:", e);
  }
}

async function transformCatalog(response, url, counts) {
  const comparator = getComparator(url.searchParams.get("sort_by"));
  if (!comparator && !counts) return response;

  let plugins;
  try {
    plugins = await response.clone().json();
  } catch {
    return response;
  }
  if (!Array.isArray(plugins)) return response;

  if (counts) applyCounts(plugins, counts);
  if (comparator) {
    const direction = url.searchParams.get("sort_direction") === "desc" ? -1 : 1;
    plugins.sort((a, b) => comparator(a, b) * direction);
  }

  const headers = new Headers(response.headers);
  headers.delete("etag");
  headers.delete("content-length");
  headers.set("content-type", "application/json; charset=utf-8");

  return new Response(JSON.stringify(plugins), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export async function onRequestOptions(context) {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "X-Decky-Version",
      "Access-Control-Max-Age": "86400",
    },
  });
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const increment = context.request.method === "POST" && INCREMENT_PATH.exec(url.pathname);

  let response;
  if (increment) {
    // Decky sends Python's str(bool): "True" or "False".
    const isUpdate = (url.searchParams.get("isUpdate") || "").toLowerCase() === "true";
    await recordInstall(
      context.env,
      decodeURIComponent(increment[1]),
      decodeURIComponent(increment[2]),
      isUpdate,
    );
    response = new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  } else {
    response = await context.next();
    if (response.ok && SORTABLE_PATHS.has(url.pathname)) {
      response = await transformCatalog(response, url, await loadCounts(context.env));
    }
  }

  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set("Access-Control-Allow-Headers", "X-Decky-Version");
  return response;
}
