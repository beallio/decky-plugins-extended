// Decky Loader sorts the store server-side: the frontend appends
// ?sort_by=<name|date|downloads>&sort_direction=<asc|desc> to the store URL and
// renders the response array in the order it arrives. A static JSON file ignores
// those params, so the sort dropdown does nothing. Reorder the catalog here to
// match what plugins.deckbrew.xyz returns for the same query.

const SORTABLE_PATHS = new Set(["/plugins.json", "/testing_plugins.json"]);

// After downloading a plugin, Decky POSTs <store-url>/<name>/versions/<ver>/increment
// to bump the install counter. Cloudflare answers non-GET on a static asset with
// 405, which Decky logs as "Server did not accept install count increment
// request" -- harmless, the install continues, but it fills the journal. There is
// nowhere to record a count here, so acknowledge it and move on.
const INCREMENT_PATH = /^\/(?:plugins|testing_plugins)\.json\/[^/]+\/versions\/[^/]+\/increment$/;

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

async function sortCatalog(response, url) {
  const comparator = getComparator(url.searchParams.get("sort_by"));
  if (!comparator) return response;

  let plugins;
  try {
    plugins = await response.clone().json();
  } catch {
    return response;
  }
  if (!Array.isArray(plugins)) return response;

  const direction = url.searchParams.get("sort_direction") === "desc" ? -1 : 1;
  plugins.sort((a, b) => comparator(a, b) * direction);

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

  let response;
  if (context.request.method === "POST" && INCREMENT_PATH.test(url.pathname)) {
    response = new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json; charset=utf-8" },
    });
  } else {
    response = await context.next();
    if (response.ok && SORTABLE_PATHS.has(url.pathname)) {
      response = await sortCatalog(response, url);
    }
  }

  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set("Access-Control-Allow-Headers", "X-Decky-Version");
  return response;
}
