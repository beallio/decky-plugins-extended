import assert from "node:assert/strict";
import test from "node:test";

import { onRequest } from "../functions/_middleware.js";

const SITE_FALLBACK = "<!doctype html><title>Decky Extended Plugins</title>";

function context(path, method = "GET") {
  const fetched = [];
  return {
    fetched,
    request: new Request(`https://store.test${path}`, { method }),
    env: {
      ASSETS: {
        async fetch(url) {
          fetched.push(new URL(url).pathname);
          return new Response(JSON.stringify({ [new URL(url).pathname]: ["1.0", "h"] }), {
            headers: { "content-type": "application/json" },
          });
        },
      },
    },
    // Pages answers unknown paths with the landing page, which Decky cannot parse.
    next: async () => new Response(SITE_FALLBACK, { headers: { "content-type": "text/html" } }),
  };
}

test("Decky's version-list addresses return the generated JSON for each channel", async () => {
  for (const [catalog, file] of [
    ["/plugins.json", "/plugins_versions.json"],
    ["/testing_plugins.json", "/testing_plugins_versions.json"],
  ]) {
    const request = context(`${catalog}/versions`);
    const response = await onRequest(request);

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { [file]: ["1.0", "h"] });
    assert.equal(response.headers.get("access-control-allow-origin"), "*");
    assert.deepEqual(request.fetched, [file]);
  }
});

test("other addresses below the store keep the site's normal response", async () => {
  for (const [path, method] of [
    ["/versions", "GET"],
    ["/plugins.json/versions", "POST"],
  ]) {
    const request = context(path, method);
    const response = await onRequest(request);

    assert.equal(await response.text(), SITE_FALLBACK);
    assert.deepEqual(request.fetched, []);
  }
});
