// Decky Loader sorts the store server-side: the frontend appends
// ?sort_by=<name|date|downloads>&sort_direction=<asc|desc> to the store URL and
// renders the response array in the order it arrives. A static JSON file ignores
// those params, so the sort dropdown does nothing. Reorder the catalog here to
// match what plugins.deckbrew.xyz returns for the same query.

const SORTABLE_PATHS = new Set(["/plugins.json", "/testing_plugins.json"]);

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
  let response = await context.next();

  const url = new URL(context.request.url);
  if (response.ok && SORTABLE_PATHS.has(url.pathname)) {
    response = await sortCatalog(response, url);
  }

  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set("Access-Control-Allow-Headers", "X-Decky-Version");
  return response;
}
