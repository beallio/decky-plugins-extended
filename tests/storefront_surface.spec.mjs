import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const STATIC = join(ROOT, "static");
const SCREENSHOT_DIR = "/tmp/decky-plugins-extended/storefront-redesign";
const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const HASH_D = "d".repeat(64);

const stableCatalog = [
  {
    id: 1,
    name: "Alpha Tool",
    author: "Decky Author",
    description: "Official store has 1.0.0; this store has 2.0.0. A library utility.",
    tags: ["library", "utility"],
    versions: [
      {
        name: "2.0.0",
        hash: HASH_A,
        created: "2026-08-30T00:00:00Z",
        downloads: 17,
        updates: 4,
      },
      {
        name: "1.0.0",
        hash: HASH_D,
        created: "2026-07-01T00:00:00Z",
        downloads: 0,
        updates: 0,
      },
    ],
    image_url: "/broken.png",
    visible: true,
    updated: "2026-08-30T00:00:00Z",
    downloads: 10,
    updates: 2,
  },
  {
    id: 2,
    name: "Radio Deck",
    author: "Sound Maker",
    description: "Listen to game music.",
    tags: ["audio", "media"],
    versions: [
      {
        name: "1.0.0",
        hash: HASH_B,
        artifact: "https://github.com/owner/radio/releases/download/v1.0.0/radio.zip",
      },
    ],
    image_url: "/radio.svg",
    visible: true,
    updated: "2026-07-30T00:00:00Z",
    downloads: 40,
    updates: 1,
  },
];

const testingCatalog = [
  ...stableCatalog,
  {
    id: 3,
    name: "Testing Preview",
    author: "Preview Author",
    description: "A prerelease utility.",
    tags: ["utility"],
    versions: [{ name: "3.0.0-beta.1", hash: HASH_C }],
    visible: true,
    updated: "2026-08-31T00:00:00Z",
    downloads: 1,
    updates: 0,
  },
];

const storefrontMetadata = {
  schema_version: 1,
  enforcement_mode: "enforce",
  stable_count: 2,
  testing_count: 3,
  stable_extended_count: 1,
  testing_extended_count: 1,
  plugins: {
    "alpha tool": {
      name: "Alpha Tool",
      provenance: "official",
      source_urls: ["https://github.com/owner/alpha"],
      versions: [
        {
          name: "2.0.0",
          hash: HASH_A,
          tag: "2.0.0",
          repository: "owner/alpha",
          source_url: "https://github.com/owner/alpha",
          release_url: "https://github.com/owner/alpha/releases/tag/v2.0.0",
        },
      ],
    },
    "radio deck": {
      name: "Radio Deck",
      source_urls: ["https://github.com/owner/radio"],
      provenance: "extended",
      versions: [
        {
          name: "1.0.0",
          hash: HASH_B,
          tag: "1.0.0",
          repository: "owner/radio",
          source_url: "https://github.com/owner/radio",
          release_url: "https://github.com/owner/radio/releases/tag/v1.0.0",
        },
      ],
      warnings: [
        {
          kind: "large-plugin",
          name: "1.0.0",
          tag: "v1.0.0",
          repository: "owner/radio",
          size_bytes: 157_248_535,
          limit_bytes: 67_108_864,
          included: true,
          prerelease: false,
        },
      ],
    },
    "testing preview": {
      name: "Testing Preview",
      provenance: "official",
      source_urls: ["https://github.com/owner/testing-preview"],
      versions: [
        {
          name: "3.0.0-beta.1",
          hash: HASH_C,
          tag: "3.0.0-beta.1",
          repository: "owner/testing-preview",
          source_url: "https://github.com/owner/testing-preview",
          release_url:
            "https://github.com/owner/testing-preview/releases/tag/v3.0.0-beta.1",
        },
      ],
    },
  },
};

const auditRecords = [
  {
    repository: "https://github.com/owner/alpha",
    tag: "v2.0.0",
    identity_status: "CURRENT",
    outcome: "APPLIED",
    current_artifact_sha256: HASH_A,
    classification: "MANUAL_REVIEW",
  },
];
const auditPayload = { enforcement_mode: "enforce", releases: auditRecords };

let server;
let baseUrl;
let stableFailures = 0;
let stableDelay = 0;
let optionalDelay = 0;
let storefrontFailures = 0;

function json(response, value, status = 200) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function serveStatic(response, file) {
  try {
    const body = await readFile(join(STATIC, file));
    const type = file.endsWith(".css")
      ? "text/css"
      : file.endsWith(".js")
        ? "text/javascript"
        : "text/html";
    response.writeHead(200, { "content-type": type });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
}

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  await mkdir(SCREENSHOT_DIR, { recursive: true });
  server = createServer(async (request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/plugins.json") {
      if (stableDelay) await new Promise((resolveDelay) => setTimeout(resolveDelay, stableDelay));
      if (stableFailures > 0) {
        stableFailures -= 1;
        json(response, { error: "temporary" }, 503);
      } else {
        json(response, stableCatalog);
      }
      return;
    }
    if (path === "/testing_plugins.json") return json(response, testingCatalog);
    if (path === "/storefront.json") {
      if (storefrontFailures > 0) {
        storefrontFailures -= 1;
        return json(response, { error: "temporary" }, 503);
      }
      if (optionalDelay) await new Promise((resolveDelay) => setTimeout(resolveDelay, optionalDelay));
      return json(response, storefrontMetadata);
    }
    if (path === "/audit.json") {
      if (optionalDelay) await new Promise((resolveDelay) => setTimeout(resolveDelay, optionalDelay));
      return json(response, auditPayload);
    }
    if (path === "/broken.png") {
      response.writeHead(404);
      response.end("Missing image");
      return;
    }
    if (path === "/radio.svg") {
      response.writeHead(200, { "content-type": "image/svg+xml" });
      response.end(
        '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="80"><rect width="128" height="80" fill="#31e6f2"/></svg>',
      );
      return;
    }
    await serveStatic(response, path === "/" ? "index.html" : path.slice(1));
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

test.afterAll(async () => {
  await new Promise((resolveClose, rejectClose) =>
    server.close((error) => (error ? rejectClose(error) : resolveClose())),
  );
});

async function loadStorefront(page, suffix = "") {
  await page.goto(`${baseUrl}/${suffix}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("#plugin-grid [data-plugin-key]").first()).toBeVisible();
}

test("actual static assets load over HTTP and publish every direct artifact", async ({ page }) => {
  await loadStorefront(page);
  await expect(page.getByText("Alpha Tool", { exact: true })).toBeVisible();
  await expect(page.locator("#catalog-status-value")).toContainText("Operational");
  await expect(page.locator("[data-plugin-key='alpha tool'] .badge")).toHaveText("Manual review");
  await expect(page.locator("[data-plugin-key='radio deck'] .badge")).toHaveText(
    "Large release",
  );
  const alphaCard = page.locator("[data-plugin-key='alpha tool']");
  await expect(alphaCard.locator(".card-downloads")).toHaveText("10 downloads");
  await expect(alphaCard.locator(".card-downloads [data-icon='download']")).toHaveCount(1);
  await expect(page.locator(".install-panel a[href$='.json']")).toHaveCount(0);
  await expect(page.locator(".install-panel")).not.toContainText(".json");
  const responses = await page.evaluate(async () =>
    Promise.all(
      [
        "/index.html",
        "/storefront.css",
        "/storefront.js",
        "/plugins.json",
        "/testing_plugins.json",
        "/storefront.json",
        "/audit.json",
      ].map(async (path) => {
        const response = await fetch(path);
        const text = await response.text();
        if (path.endsWith(".json")) JSON.parse(text);
        return { path, status: response.status };
      }),
    ),
  );
  assert.deepEqual(responses.map((entry) => entry.status), Array(7).fill(200));
});

test("large release warnings explain the skipped automated audit", async ({ page }) => {
  await loadStorefront(page);
  await page.getByRole("button", { name: "View Radio Deck details" }).click();
  await expect(page.locator("#detail-backdrop")).toBeVisible();
  await expect(
    page.getByText(
      "Release v1.0.0 is 150.0 MiB, above the 64 MiB download and automated-audit limit. It is listed using GitHub's SHA-256 digest, but automated security scanning was skipped.",
      { exact: true },
    ),
  ).toBeVisible();
});

test("a catalog failure is visible and the retry control recovers", async ({ page }) => {
  stableFailures = 1;
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await expect(page.locator("#catalog-error")).toBeVisible();
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.getByText("Alpha Tool", { exact: true })).toBeVisible();
  await expect(page.locator("#catalog-error")).toBeHidden();
});

test("extended artifacts never appear official when provenance metadata rejects", async ({ page }) => {
  storefrontFailures = 1;
  try {
    await loadStorefront(page);
    await page.getByRole("button", { name: "View Radio Deck details" }).click();
    const versionHistory = page.getByRole("table", { name: "Version history" });
    await expect(versionHistory.getByText("Source unavailable", { exact: true })).toBeVisible();
    await expect(versionHistory.getByText("Official catalog", { exact: true })).toHaveCount(0);
  } finally {
    storefrontFailures = 0;
  }
});

test("a fast channel switch ignores a stale stable response", async ({ page }) => {
  stableDelay = 220;
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: "Testing" }).click();
  await expect(page.getByText("Testing Preview", { exact: true })).toBeVisible();
  await page.waitForTimeout(260);
  await expect(page.getByText("Testing Preview", { exact: true })).toBeVisible();
  await expect(page.locator("#result-total")).toContainText("3 plugins");
  stableDelay = 0;
});

test("search, categories, sorting, fallback image, URL state, copy, and dialogs work", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    document.execCommand = () => true;
  });
  await loadStorefront(page, "?query=Alpha&category=newer&sort=name");
  await expect(page.locator("#search")).toHaveValue("Alpha");
  await expect(page.locator("#sort")).toHaveValue("name");
  await expect(page.getByText("Alpha Tool", { exact: true })).toBeVisible();
  await expect(page.locator("[data-plugin-key='alpha tool'] .monogram")).toBeVisible();
  await expect(page.locator("#sort-direction")).toHaveValue("asc");
  await page.locator("#search").fill("");
  await page.getByRole("button", { name: "All" }).click();
  await page.locator("#sort-direction").selectOption("desc");
  await expect(page.locator(".plugin-card .card-title")).toHaveText([
    "Radio Deck",
    "Alpha Tool",
  ]);
  await expect(page).toHaveURL(/direction=desc/);
  await page.locator("#sort-direction").selectOption("asc");
  await expect(page.locator(".plugin-card .card-title")).toHaveText([
    "Alpha Tool",
    "Radio Deck",
  ]);

  await page.locator("#search").fill("Radio");
  await page.getByRole("button", { name: "Media" }).click();
  await page.locator("#sort").selectOption("installs");
  await expect(page.locator("#sort-direction")).toHaveValue("desc");
  await page.locator("#sort-direction").selectOption("asc");
  await expect(page.getByText("Radio Deck", { exact: true })).toBeVisible();
  await expect(page).toHaveURL(/query=Radio/);
  await expect(page).toHaveURL(/category=media/);
  await expect(page).toHaveURL(/sort=installs/);
  await expect(page).toHaveURL(/direction=asc/);

  await page.getByRole("button", { name: /Copy Stable URL/ }).click();
  await expect(page.locator("#copy-status")).toContainText("Stable catalog URL copied");

  await page.getByRole("button", { name: "Show setup steps" }).click();
  await expect(page.locator("#setup-backdrop")).toBeVisible();
  await expect(page.getByRole("button", { name: "Close setup instructions" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.locator("#copy-setup")).toBeFocused();
  await page.locator("#copy-setup").click();
  await expect(page.locator("#setup-copy-status")).toContainText("Stable catalog URL copied");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Close setup instructions" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.locator("#setup-backdrop")).toBeHidden();
  await expect(page.getByRole("button", { name: "Show setup steps" })).toBeFocused();

  await page.locator("#search").fill("Alpha");
  await page.getByRole("button", { name: "All" }).click();
  const detailButton = page.getByRole("button", { name: "View Alpha Tool details" });
  await detailButton.focus();
  const focusStyle = await page.locator("[data-plugin-key='alpha tool']").evaluate((button) => {
    const card = button.closest(".plugin-card");
    const style = getComputedStyle(card);
    return { borderColor: style.borderColor, boxShadow: style.boxShadow };
  });
  assert.equal(focusStyle.borderColor, "rgb(49, 230, 242)");
  assert.match(focusStyle.boxShadow, /49, 230, 242/);
  await detailButton.click();
  await expect(page.locator("#detail-backdrop")).toBeVisible();
  await expect(page.locator("#detail-name")).toHaveText("Alpha Tool");
  await expect(page.locator(".detail-meta")).toHaveText(
    "by Decky Author · Latest v2.0.0 · Updated 2026-08-30",
  );
  const detailMeta = page.locator(".detail-meta");
  const description = page.locator(".detail-description");
  const officialNote = page.getByText(
    "Official store has 1.0.0; this store has 2.0.0.",
    { exact: true },
  );
  await expect(officialNote).toBeVisible();
  assert.equal(
    await detailMeta.evaluate((meta) =>
      Boolean(
        document
          .querySelector("#detail-dialog .modal-head")
          .compareDocumentPosition(meta) & Node.DOCUMENT_POSITION_FOLLOWING,
      ),
    ),
    true,
  );
  assert.equal(
    await detailMeta.evaluate(
      (meta) =>
        Boolean(
          meta.compareDocumentPosition(document.querySelector(".detail-art")) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ),
    ),
    true,
  );
  assert.equal(
    await description.evaluate(
      (element) =>
        Boolean(
          element.compareDocumentPosition(
            [...document.querySelectorAll(".warning")].find((warning) =>
              warning.textContent.startsWith("Official store has"),
            ),
          ) & Node.DOCUMENT_POSITION_FOLLOWING,
        ),
    ),
    true,
  );
  assert.equal(
    await officialNote.evaluate(
      (note) =>
        Boolean(
          note.compareDocumentPosition(
            document.querySelector(".detail-primary-actions a"),
          ) & Node.DOCUMENT_POSITION_FOLLOWING,
        ),
    ),
    true,
  );
  const repositoryLink = page.getByRole("link", { name: "View repository" });
  await expect(repositoryLink).toHaveAttribute("href", "https://github.com/owner/alpha");
  const versionHistory = page.getByRole("table", { name: "Version history" });
  assert.equal(
    await repositoryLink.evaluate(
      (link) =>
        Boolean(
          link.compareDocumentPosition(document.querySelector(".version-history")) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ),
    ),
    true,
  );
  const totals = page.locator(".detail-totals");
  await expect(totals.locator(".detail-total-value")).toHaveText(["10", "2"]);
  await expect(totals.locator("[data-icon='download']")).toHaveCount(1);
  await expect(totals.locator("[data-icon='updates']")).toHaveCount(1);
  await expect(versionHistory).toBeVisible();
  await expect(versionHistory.getByRole("columnheader")).toHaveText([
    "Version",
    "Released",
    "Downloads",
    "Updates",
    "Source",
  ]);
  await expect(versionHistory.getByRole("row")).toHaveCount(3);
  await expect(versionHistory.getByRole("cell", { name: "17", exact: true })).toBeVisible();
  await expect(versionHistory.getByRole("cell", { name: "4", exact: true })).toBeVisible();
  await expect(versionHistory.getByRole("cell", { name: "0", exact: true })).toHaveCount(2);
  await expect(versionHistory.getByRole("link", { name: "View 2.0.0 source" })).toHaveAttribute(
    "href",
    "https://github.com/owner/alpha/releases/tag/v2.0.0",
  );
  await expect(versionHistory.getByText("Official catalog", { exact: true })).toBeVisible();
  await expect(versionHistory.getByRole("columnheader", { name: "Audit" })).toHaveCount(0);
  const auditBox = page.locator(".detail-box").filter({ hasText: "Audit outcome" });
  await expect(auditBox.getByRole("link", { name: "Open audit log" })).toHaveAttribute(
    "href",
    "audit.html",
  );
  const hashBox = page.locator(".detail-box").filter({ hasText: "Latest hash" });
  await expect(hashBox.getByRole("button", { name: "Copy latest SHA-256" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy SHA-256", exact: true })).toHaveCount(0);
  await hashBox.getByRole("button", { name: "Copy latest SHA-256" }).click();
  await expect(page.locator("#detail-copy-status")).toContainText("SHA-256 hash copied");
  await page
    .locator("#detail-dialog")
    .screenshot({ path: join(SCREENSHOT_DIR, "storefront-detail-modal.png") });
  await page.keyboard.press("Escape");
  await expect(page.locator("#detail-backdrop")).toBeHidden();
  await expect(detailButton).toBeFocused();
});

test("dialog copy failures are announced inside the active dialog", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    document.execCommand = () => false;
  });
  await loadStorefront(page);
  await page.getByRole("button", { name: "Show setup steps" }).click();
  await page.locator("#copy-setup").click();
  await expect(page.locator("#setup-copy-status")).toContainText("Could not copy the catalog URL");
  await expect(page.locator("#copy-status")).toBeEmpty();
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "View Alpha Tool details" }).click();
  await page.getByRole("button", { name: "Copy latest SHA-256" }).click();
  await expect(page.locator("#detail-copy-status")).toContainText(
    "Could not copy the SHA-256 hash",
  );
});

test("open detail refreshes source links after delayed metadata without resetting focus", async ({ page }) => {
  optionalDelay = 800;
  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    const detailButton = page.getByRole("button", { name: "View Radio Deck details" });
    await expect(detailButton).toBeVisible();
    const originalButton = await detailButton.elementHandle();
    await detailButton.click();
    await expect(page.locator("#detail-backdrop")).toBeVisible();
    const versionHistory = page.getByRole("table", { name: "Version history" });
    const detailImage = page.locator(".detail-art img");
    await expect(detailImage).toHaveAttribute("src", "/radio.svg");
    await expect
      .poll(() => detailImage.evaluate((image) => image.complete && image.naturalWidth))
      .toBeGreaterThan(0);
    const artLayout = await page.locator(".detail-art").evaluate((art) => {
      const body = art.closest(".modal-body");
      const artRect = art.getBoundingClientRect();
      const bodyRect = body.getBoundingClientRect();
      return {
        leftPadding: artRect.left - bodyRect.left,
        rightPadding: bodyRect.right - artRect.right,
        artWidth: artRect.width,
      };
    });
    assert.equal(artLayout.leftPadding, 22);
    assert.equal(artLayout.rightPadding, 22);
    assert.ok(artLayout.artWidth > 500);
    await expect(versionHistory.getByText("Source unavailable", { exact: true })).toBeVisible();
    const copyHash = page.getByRole("button", { name: "Copy latest SHA-256" });
    await copyHash.focus();
    await expect(copyHash).toBeFocused();
    await page.waitForTimeout(900);
    assert.equal(await originalButton.evaluate((button) => button.isConnected), false);
    await expect(versionHistory.getByRole("link", { name: "View 1.0.0 source" })).toHaveAttribute(
      "href",
      "https://github.com/owner/radio/releases/tag/v1.0.0",
    );
    await expect(copyHash).toBeFocused();
    await expect(page.getByRole("link", { name: "Open audit log" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "View repository" })).toHaveAttribute(
      "href",
      "https://github.com/owner/radio",
    );
    await expect(page.locator("#detail-backdrop")).toBeVisible();
    await expect(page.locator("body")).toHaveCSS("overflow", "hidden");
    await page.keyboard.press("Escape");
    await expect(page.locator("#detail-backdrop")).toBeHidden();
    await expect(page.locator("[data-plugin-name='Radio Deck']")).toBeFocused();
  } finally {
    optionalDelay = 0;
  }
});

test("detail view ranks related plugins by shared tags and downloads", async ({ page }) => {
  await loadStorefront(page, "?channel=testing&query=Alpha");
  await page.getByRole("button", { name: "View Alpha Tool details" }).click();
  const related = page.locator(".related-plugins");
  await expect(related.getByRole("heading", { name: "Related plugins" })).toBeVisible();
  await expect(
    related.getByRole("button", { name: "View Testing Preview details" }),
  ).toBeVisible();
  assert.equal(
    await related.evaluate(
      (section) =>
        Boolean(
          section.compareDocumentPosition(document.querySelector(".version-history")) &
            Node.DOCUMENT_POSITION_FOLLOWING,
        ),
    ),
    true,
  );
  await related.screenshot({ path: join(SCREENSHOT_DIR, "storefront-related-plugins.png") });
  await related.getByRole("button", { name: "View Testing Preview details" }).click();
  await expect(page.locator("#detail-name")).toHaveText("Testing Preview");
  const provenance = page.locator(".detail-box").filter({ hasText: "Provenance" });
  await expect(provenance).toContainText("Official catalog");
  await expect(provenance).not.toContainText("Unknown");
});

test("status cells stay centered and the mobile and desktop surfaces do not overflow", async ({ page }) => {
  await loadStorefront(page);
  const screenshots = [];
  for (const viewport of [
    { width: 1440, height: 1000, name: "desktop" },
    { width: 390, height: 844, name: "mobile" },
  ]) {
    await page.setViewportSize(viewport);
    await page.waitForTimeout(50);
    const geometry = await page.locator(".status-item").evaluateAll((cells) =>
      cells.map((cell) => {
        const rect = cell.getBoundingClientRect();
        const value = cell.querySelector(".status-value");
        const label = cell.querySelector(".status-label");
        const valueContent = cell.querySelector(".status-content");
        const labelContent = cell.querySelector(".status-label-content");
        const valueRect = valueContent.getBoundingClientRect();
        const labelRect = labelContent.getBoundingClientRect();
        return {
          cellMidpoint: rect.left + rect.width / 2,
          valueMidpoint: valueRect.left + valueRect.width / 2,
          labelMidpoint: labelRect.left + labelRect.width / 2,
          valueJustify: getComputedStyle(value).justifyContent,
          labelJustify: getComputedStyle(label).justifyContent,
        };
      }),
    );
    geometry.forEach((cell) => {
      assert.equal(cell.valueJustify, "center");
      assert.equal(cell.labelJustify, "center");
      assert.ok(Math.abs(cell.valueMidpoint - cell.cellMidpoint) <= 2);
      assert.ok(Math.abs(cell.labelMidpoint - cell.cellMidpoint) <= 2);
    });
    const noOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    );
    assert.equal(noOverflow, true);
    if (viewport.name === "mobile") {
      const mobileHierarchy = await page.evaluate(() => {
        const brand = document.querySelector(".brand");
        const heading = document.querySelector(".catalog-heading");
        return {
          brandText: brand.innerText,
          brandFits: brand.scrollWidth <= brand.clientWidth,
          auditDisplay: getComputedStyle(document.querySelector(".nav a[href='audit.html']")).display,
          githubDisplay: getComputedStyle(document.querySelector(".github-link")).display,
          headingGap: getComputedStyle(heading).gap,
        };
      });
      assert.equal(mobileHierarchy.brandText, "Decky Plugins");
      assert.equal(mobileHierarchy.brandFits, true);
      assert.equal(mobileHierarchy.auditDisplay, "none");
      assert.equal(mobileHierarchy.githubDisplay, "none");
      assert.equal(mobileHierarchy.headingGap, "8px");
    }
    const path = join(SCREENSHOT_DIR, `storefront-${viewport.name}.png`);
    await page.screenshot({ path, fullPage: true });
    screenshots.push(path);
  }
  console.log(`storefront screenshots: ${screenshots.join(", ")}`);
});
