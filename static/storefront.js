export const CATALOG_ENDPOINTS = Object.freeze({
  stable: "/plugins.json",
  testing: "/testing_plugins.json",
});

export const STORE_URLS = Object.freeze({
  stable: "https://decky-extended-plugins.beallio.com/plugins.json",
  testing: "https://decky-extended-plugins.beallio.com/testing_plugins.json",
});

const CATEGORY_TAGS = Object.freeze({
  library: ["library", "collection", "games", "game"],
  utilities: ["utility", "utilities", "tool", "tools", "system"],
  media: ["media", "music", "video", "audio", "artwork"],
});

function stringValue(value) {
  return typeof value === "string" ? value.trim() : "";
}

function numberValue(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

export function normalizeVersionName(value) {
  const text = stringValue(value);
  const match = text.match(/(?:^|[^0-9])v?(\d+(?:\.\d+)*(?:-[0-9a-z.-]+)?)/i);
  return (match?.[1] || text).toLowerCase();
}

export function parseOfficialVersionNote(description) {
  const original = stringValue(description);
  const match = original.match(
    /^Official store has\s+([^;]+);\s*this store has\s+(.+?)\.(?:\s+|$)/i,
  );
  if (!match) {
    return { description: original, officialVersion: "", storeVersion: "" };
  }
  return {
    description: original.slice(match[0].length).trim(),
    officialVersion: stringValue(match[1]),
    storeVersion: stringValue(match[2]),
  };
}

export function normalizeCatalogEntry(entry) {
  const source = entry && typeof entry === "object" ? entry : {};
  const note = parseOfficialVersionNote(source.description);
  const versions = Array.isArray(source.versions)
    ? source.versions
        .filter((version) => version && typeof version === "object")
        .map((version) => ({
          name: stringValue(version.name),
          hash: stringValue(version.hash).toLowerCase(),
          artifact: stringValue(version.artifact),
          created: stringValue(version.created),
        }))
        .filter((version) => version.name || version.hash)
    : [];
  const tags = Array.isArray(source.tags)
    ? source.tags.map(stringValue).filter(Boolean)
    : typeof source.tags === "string"
      ? [stringValue(source.tags)].filter(Boolean)
      : [];

  return {
    id: source.id,
    name: stringValue(source.name) || "Unnamed plugin",
    author: stringValue(source.author) || "Unknown author",
    description: note.description,
    officialVersion: note.officialVersion,
    storeVersion: note.storeVersion,
    tags,
    versions,
    visible: source.visible !== false,
    imageUrl: stringValue(source.image_url),
    created: stringValue(source.created),
    updated: stringValue(source.updated),
    downloads: numberValue(source.downloads),
    updates: numberValue(source.updates),
  };
}

export function catalogForChannel(channel) {
  return CATALOG_ENDPOINTS[channel] || CATALOG_ENDPOINTS.stable;
}

export function channelCounts(metadata, channel, catalog = []) {
  const testing = channel === "testing";
  const visibleCount = (catalog || []).filter((plugin) => plugin.visible !== false).length;
  return {
    available: metadata?.[testing ? "testing_count" : "stable_count"] ?? visibleCount,
    extended: metadata?.[testing ? "testing_extended_count" : "stable_extended_count"] ?? null,
  };
}

export function primaryCategoryForTags(tags) {
  const normalized = new Set((tags || []).map((tag) => stringValue(tag).toLowerCase()));
  for (const [category, categoryTags] of Object.entries(CATEGORY_TAGS)) {
    if (categoryTags.some((tag) => normalized.has(tag))) {
      return category;
    }
  }
  return "";
}

export function matchesCategory(plugin, category, provenance = "") {
  if (!category || category === "all") {
    return true;
  }
  if (category === "newer") {
    return Boolean(plugin.officialVersion && plugin.storeVersion);
  }
  if (category === "extended") {
    return provenance === "extended";
  }
  const normalizedTags = new Set(
    (plugin.tags || []).map((tag) => stringValue(tag).toLowerCase()),
  );
  return (
    normalizedTags.has(category) ||
    CATEGORY_TAGS[category]?.some((tag) => normalizedTags.has(tag)) ||
    primaryCategoryForTags(plugin.tags) === category
  );
}

export function filterCatalog(catalog, query = "", category = "all", provenanceByName = {}) {
  const needle = stringValue(query).toLowerCase();
  return (catalog || []).filter((plugin) => {
    if (!plugin.visible) {
      return false;
    }
    const provenance = provenanceByName[plugin.name.toLowerCase()]?.provenance || "";
    if (!matchesCategory(plugin, category, provenance)) {
      return false;
    }
    if (!needle) {
      return true;
    }
    return [plugin.name, plugin.author, plugin.description, ...(plugin.tags || [])]
      .join(" ")
      .toLowerCase()
      .includes(needle);
  });
}

export function sortCatalog(catalog, sort = "updated") {
  const ordered = [...(catalog || [])];
  return ordered.sort((left, right) => {
    if (sort === "name") {
      return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
    }
    if (sort === "installs") {
      return (
        right.downloads + right.updates - (left.downloads + left.updates) ||
        left.name.localeCompare(right.name, undefined, { sensitivity: "base" })
      );
    }
    return (
      Date.parse(right.updated || right.created || 0) -
        Date.parse(left.updated || left.created || 0) ||
      left.name.localeCompare(right.name, undefined, { sensitivity: "base" })
    );
  });
}

function repositorySlug(value) {
  const source = stringValue(value).replace(/\/$/, "");
  const match = source.match(/github\.com[/:]([^/]+)\/([^/#]+)/i);
  if (match) {
    return `${match[1]}/${match[2].replace(/\.git$/, "")}`.toLowerCase();
  }
  return source.toLowerCase();
}

export function findSourceVersions(plugin, metadata) {
  const latest = plugin?.versions?.[0] || {};
  const records = metadata?.plugins?.[stringValue(plugin?.name).toLowerCase()]?.versions;
  if (!Array.isArray(records) || !latest.name || !latest.hash) {
    return [];
  }
  return records.filter(
    (record) =>
      normalizeVersionName(record?.name) === normalizeVersionName(latest.name) &&
      stringValue(record?.hash).toLowerCase() === latest.hash.toLowerCase(),
  );
}

export function findMatchingAuditRecord(source, version, auditRecords) {
  if (!source || !version?.hash || !Array.isArray(auditRecords)) {
    return null;
  }
  const matches = auditRecords.filter(
    (record) =>
      repositorySlug(record?.repository) === repositorySlug(source.repository) &&
      normalizeVersionName(record?.tag) === normalizeVersionName(source.tag) &&
      stringValue(record?.identity_status) === "CURRENT" &&
      stringValue(record?.outcome) === "APPLIED" &&
      stringValue(record?.current_artifact_sha256).toLowerCase() ===
        stringValue(version.hash).toLowerCase(),
  );
  return matches.length === 1 ? matches[0] : null;
}

export function buildDetailViewModel(plugin, metadata, auditRecords = []) {
  const latest = plugin?.versions?.[0] || null;
  const sources = findSourceVersions(plugin, metadata);
  const source = sources.length === 1 ? sources[0] : null;
  const audit = source && latest ? findMatchingAuditRecord(source, latest, auditRecords) : null;
  const provenance = metadata?.plugins?.[stringValue(plugin?.name).toLowerCase()]?.provenance || "";
  return {
    plugin,
    latest,
    source,
    sourceAmbiguous: sources.length > 1,
    provenance,
    audit,
    officialNote:
      plugin?.officialVersion && plugin?.storeVersion
        ? `Official store has ${plugin.officialVersion}; this store has ${plugin.storeVersion}.`
        : "",
  };
}

export function classifyPrimaryBadge(plugin, detail, channel) {
  const classification = stringValue(detail?.audit?.classification).toUpperCase();
  if (classification === "BLOCK" || classification === "MANUAL_REVIEW") {
    return { kind: "warning", label: classification === "BLOCK" ? "Audit block" : "Manual review" };
  }
  if (channel === "testing" && /-/.test(detail?.latest?.name || "")) {
    return { kind: "testing", label: "Testing prerelease" };
  }
  if (plugin?.officialVersion && plugin?.storeVersion) {
    return { kind: "newer", label: "Newer than official" };
  }
  if (detail?.provenance === "extended") {
    return { kind: "extended", label: "Extended only" };
  }
  return null;
}

export function shouldAcceptChannelResponse(currentGeneration, responseGeneration) {
  return currentGeneration === responseGeneration;
}

function createElement(name, className, text) {
  const element = document.createElement(name);
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
}

function monogram(name) {
  return stringValue(name)
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase() || "?";
}

function auditRecordsFrom(data) {
  return Array.isArray(data) ? data : Array.isArray(data?.records) ? data.records : [];
}

async function requestJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}`);
  }
  return response.json();
}

function startStorefront() {
  const elements = {
    channelButtons: [...document.querySelectorAll("[data-channel]")],
    categoryButtons: [...document.querySelectorAll("[data-category]")],
    search: document.getElementById("search"),
    sort: document.getElementById("sort"),
    grid: document.getElementById("plugin-grid"),
    loading: document.getElementById("catalog-loading"),
    error: document.getElementById("catalog-error"),
    empty: document.getElementById("empty-state"),
    resultTotal: document.getElementById("result-total"),
    retry: document.getElementById("retry-catalog"),
    copyStore: document.getElementById("copy-store"),
    copySetup: document.getElementById("copy-setup"),
    copyStatus: document.getElementById("copy-status"),
    setupButton: document.getElementById("open-setup"),
    channelDescription: document.getElementById("channel-description"),
    setupUrl: document.getElementById("setup-url"),
    setupWarning: document.getElementById("setup-warning"),
    catalogStatus: document.getElementById("catalog-status-value"),
    availableCount: document.getElementById("available-count"),
    extendedCount: document.getElementById("extended-count"),
    securityPolicy: document.getElementById("security-policy"),
    setupBackdrop: document.getElementById("setup-backdrop"),
    setupDialog: document.getElementById("setup-dialog"),
    detailBackdrop: document.getElementById("detail-backdrop"),
    detailDialog: document.getElementById("detail-dialog"),
    detailContent: document.getElementById("detail-content"),
  };
  if (!elements.grid || !elements.search || !elements.sort) {
    return;
  }

  const params = new URLSearchParams(window.location.search);
  const initialChannel = params.get("channel") === "testing" ? "testing" : "stable";
  const initialCategory = stringValue(params.get("category")) || "all";
  const initialSort = ["updated", "name", "installs"].includes(params.get("sort"))
    ? params.get("sort")
    : "updated";
  const state = {
    channel: initialChannel,
    category: initialCategory,
    query: stringValue(params.get("query")),
    sort: initialSort,
    catalogByChannel: new Map(),
    metadata: null,
    auditRecords: [],
    requestGeneration: 0,
    lastFocused: new Map(),
    previousOverflow: "",
  };
  elements.search.value = state.query;
  elements.sort.value = state.sort;

  function updateUrl() {
    const next = new URLSearchParams();
    if (state.channel !== "stable") next.set("channel", state.channel);
    if (state.query) next.set("query", state.query);
    if (state.category !== "all") next.set("category", state.category);
    if (state.sort !== "updated") next.set("sort", state.sort);
    const query = next.toString();
    const url = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
    window.history.replaceState(null, "", url);
  }

  function updateChannelControls() {
    const testing = state.channel === "testing";
    elements.channelButtons.forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.channel === state.channel));
    });
    elements.categoryButtons.forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.category === state.category));
    });
    elements.channelDescription.textContent = testing
      ? "Testing includes prereleases. Use Stable for normal daily use."
      : "Stable releases only. This channel is recommended for daily use.";
    elements.copyStore.textContent = `Copy ${testing ? "Testing" : "Stable"} URL`;
    elements.setupUrl.textContent = STORE_URLS[state.channel];
    elements.setupWarning.textContent = testing
      ? "Testing can include prereleases. Switch back to Stable whenever you prefer."
      : "Stable contains normal releases. Testing can include prereleases.";
  }

  function setCatalogStatus(text, stateName = "loading") {
    elements.catalogStatus.replaceChildren();
    const dot = createElement("span", "status-dot");
    dot.setAttribute("aria-hidden", "true");
    if (stateName === "error") dot.style.background = "var(--red)";
    if (stateName === "ready") dot.style.background = "var(--green)";
    elements.catalogStatus.append(dot, createElement("span", "", text));
  }

  function visibleCatalog() {
    const catalog = state.catalogByChannel.get(state.channel) || [];
    const provenance = state.metadata?.plugins || {};
    return sortCatalog(filterCatalog(catalog, state.query, state.category, provenance), state.sort);
  }

  function updateStatusCounts(catalog) {
    const metadata = state.metadata;
    const counts = channelCounts(metadata, state.channel, catalog);
    elements.availableCount.textContent = `${counts.available} plugins`;
    elements.extendedCount.textContent = counts.extended === null ? "Not available" : `${counts.extended} extended`;
    elements.securityPolicy.textContent = metadata?.enforcement_mode
      ? String(metadata.enforcement_mode).replace(/^./, (letter) => letter.toUpperCase())
      : "Available";
  }

  function addMonogram(art, name) {
    art.append(createElement("span", "monogram", monogram(name)));
  }

  function renderCard(plugin) {
    const detail = buildDetailViewModel(plugin, state.metadata, state.auditRecords);
    const badge = classifyPrimaryBadge(plugin, detail, state.channel);
    const card = createElement("article", "plugin-card");
    const button = createElement("button", "card-button");
    button.type = "button";
    button.dataset.pluginKey = plugin.name.toLowerCase();
    button.setAttribute("aria-label", `View ${plugin.name} details`);
    const art = createElement("div", "card-art");
    if (plugin.imageUrl) {
      const image = document.createElement("img");
      image.loading = "lazy";
      image.alt = "";
      image.src = plugin.imageUrl;
      image.addEventListener("error", () => {
        image.remove();
        if (!art.querySelector(".monogram")) addMonogram(art, plugin.name);
      });
      art.append(image);
    } else {
      addMonogram(art, plugin.name);
    }
    if (badge) art.append(createElement("span", `badge badge-${badge.kind}`, badge.label));

    const body = createElement("div", "card-body");
    const titleRow = createElement("div", "card-title-row");
    titleRow.append(createElement("h3", "card-title", plugin.name));
    titleRow.append(createElement("span", "version", detail.latest?.name ? `v${detail.latest.name}` : ""));
    body.append(titleRow, createElement("div", "author", `by ${plugin.author}`));
    body.append(createElement("p", "description", plugin.description || "No description provided."));
    const footer = createElement("div", "card-footer");
    const tags = createElement("div", "tag-list");
    plugin.tags.slice(0, 2).forEach((tag) => tags.append(createElement("span", "tag", tag)));
    footer.append(tags, createElement("span", "updated", plugin.updated ? `Updated ${plugin.updated.slice(0, 10)}` : ""));
    body.append(footer);
    button.append(art, body);
    button.addEventListener("click", () => openDetail(plugin, button));
    card.append(button);
    return card;
  }

  function render() {
    const catalog = state.catalogByChannel.get(state.channel);
    if (!catalog) return;
    const plugins = visibleCatalog();
    elements.grid.replaceChildren(...plugins.map(renderCard));
    elements.grid.setAttribute("aria-busy", "false");
    elements.empty.hidden = plugins.length !== 0;
    elements.resultTotal.textContent = `${plugins.length} ${plugins.length === 1 ? "plugin" : "plugins"}`;
    updateStatusCounts(catalog);
  }

  function setLoading(loading) {
    elements.loading.hidden = !loading;
    elements.error.hidden = true;
    elements.grid.setAttribute("aria-busy", String(loading));
  }

  function setError() {
    elements.loading.hidden = true;
    elements.error.hidden = false;
    elements.empty.hidden = true;
    elements.grid.replaceChildren();
    elements.grid.setAttribute("aria-busy", "false");
    elements.resultTotal.textContent = "Catalog unavailable";
    setCatalogStatus("Unavailable", "error");
  }

  async function loadChannel(channel, force = false) {
    const generation = ++state.requestGeneration;
    state.channel = channel;
    updateChannelControls();
    updateUrl();
    const cached = state.catalogByChannel.get(channel);
    if (cached && !force) {
      setLoading(false);
      setCatalogStatus("Operational", "ready");
      render();
      return true;
    }
    setLoading(true);
    elements.loading.textContent = `Loading the ${channel === "testing" ? "Testing" : "Stable"} catalog.`;
    setCatalogStatus("Loading", "loading");
    try {
      const data = await requestJson(catalogForChannel(channel));
      if (!shouldAcceptChannelResponse(state.requestGeneration, generation)) return false;
      if (!Array.isArray(data)) throw new Error("Catalog response is not an array");
      const catalog = data.map(normalizeCatalogEntry);
      state.catalogByChannel.set(channel, catalog);
      setLoading(false);
      setCatalogStatus("Operational", "ready");
      render();
      return true;
    } catch (error) {
      if (!shouldAcceptChannelResponse(state.requestGeneration, generation)) return false;
      setError();
      return false;
    }
  }

  async function loadOptionalData() {
    const [metadataResult, auditResult] = await Promise.allSettled([
      requestJson("/storefront.json"),
      requestJson("/audit.json"),
    ]);
    if (metadataResult.status === "fulfilled" && metadataResult.value?.schema_version === 1) {
      state.metadata = metadataResult.value;
    }
    if (auditResult.status === "fulfilled") {
      state.auditRecords = auditRecordsFrom(auditResult.value);
    }
    if (state.catalogByChannel.has(state.channel)) render();
  }

  async function copyText(value) {
    try {
      if (navigator.clipboard?.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.append(textarea);
        textarea.select();
        const copied = document.execCommand("copy");
        textarea.remove();
        if (!copied) throw new Error("Browser copy command failed");
      }
      elements.copyStatus.textContent = "URL copied to the clipboard.";
      return true;
    } catch (error) {
      elements.copyStatus.textContent = "Copy failed. Use the visible URL instead.";
      return false;
    }
  }

  function focusable(dialog) {
    return [...dialog.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])')];
  }

  function openDialog(name, trigger) {
    const backdrop = name === "setup" ? elements.setupBackdrop : elements.detailBackdrop;
    const dialog = name === "setup" ? elements.setupDialog : elements.detailDialog;
    state.lastFocused.set(name, trigger || document.activeElement);
    state.previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    backdrop.hidden = false;
    window.requestAnimationFrame(() => (focusable(dialog)[0] || dialog).focus());
  }

  function closeDialog(name) {
    const backdrop = name === "setup" ? elements.setupBackdrop : elements.detailBackdrop;
    backdrop.hidden = true;
    document.body.style.overflow = state.previousOverflow;
    const trigger = state.lastFocused.get(name);
    if (trigger?.isConnected) trigger.focus();
  }

  function detailBox(label, value) {
    const box = createElement("div", "detail-box");
    box.append(createElement("div", "detail-label", label), createElement("div", "detail-value", value || "Not available"));
    return box;
  }

  function openDetail(plugin, trigger) {
    const detail = buildDetailViewModel(plugin, state.metadata, state.auditRecords);
    const badge = classifyPrimaryBadge(plugin, detail, state.channel);
    elements.detailContent.replaceChildren();
    const hero = createElement("div", "detail-hero");
    hero.append(createElement("div", "detail-art", monogram(plugin.name)));
    const title = document.createElement("h2");
    title.id = "detail-name";
    title.textContent = plugin.name;
    const titleGroup = document.createElement("div");
    titleGroup.append(title, createElement("p", "detail-meta", `by ${plugin.author}${detail.latest?.name ? ` · v${detail.latest.name}` : ""}`));
    hero.append(titleGroup);
    elements.detailContent.append(hero, createElement("p", "detail-description", plugin.description || "No description provided."));
    const grid = createElement("div", "detail-grid");
    grid.append(
      detailBox("Catalog status", badge?.label || "Catalog entry"),
      detailBox("Provenance", detail.provenance || "Official catalog"),
      detailBox("Latest hash", detail.latest?.hash || ""),
      detailBox("Audit outcome", detail.audit?.classification || "No matching audit record"),
    );
    elements.detailContent.append(grid);
    if (detail.officialNote) elements.detailContent.append(createElement("p", "warning", detail.officialNote));
    if (detail.sourceAmbiguous) elements.detailContent.append(createElement("p", "warning", "Multiple source records match this artifact, so no source-specific audit result is shown."));
    const actions = createElement("div", "detail-actions");
    if (detail.source?.source_url) {
      const source = createElement("a", "btn btn-secondary", "View source");
      source.href = detail.source.source_url;
      source.target = "_blank";
      source.rel = "noopener";
      actions.append(source);
    }
    if (detail.latest?.hash) {
      const copyHash = createElement("button", "btn btn-secondary", "Copy SHA-256");
      copyHash.type = "button";
      copyHash.addEventListener("click", () => copyText(detail.latest.hash));
      actions.append(copyHash);
    }
    if (detail.audit) {
      const audit = createElement("a", "btn btn-secondary", "Open audit result");
      audit.href = "audit.html";
      actions.append(audit);
    }
    if (actions.childElementCount) elements.detailContent.append(actions);
    openDialog("detail", trigger);
  }

  elements.channelButtons.forEach((button) => {
    button.addEventListener("click", () => loadChannel(button.dataset.channel));
  });
  elements.categoryButtons.forEach((button) => {
    button.addEventListener("click", () => {
      state.category = button.dataset.category || "all";
      updateUrl();
      updateChannelControls();
      render();
    });
  });
  elements.search.addEventListener("input", (event) => {
    state.query = event.target.value;
    updateUrl();
    render();
  });
  elements.sort.addEventListener("change", (event) => {
    state.sort = event.target.value;
    updateUrl();
    render();
  });
  elements.retry.addEventListener("click", () => loadChannel(state.channel, true));
  elements.copyStore.addEventListener("click", () => copyText(STORE_URLS[state.channel]));
  elements.copySetup.addEventListener("click", () => copyText(STORE_URLS[state.channel]));
  elements.setupButton.addEventListener("click", () => openDialog("setup", elements.setupButton));
  document.querySelectorAll("[data-close]").forEach((button) => {
    button.addEventListener("click", () => closeDialog(button.dataset.close));
  });
  [elements.setupBackdrop, elements.detailBackdrop].forEach((backdrop) => {
    backdrop.addEventListener("click", (event) => {
      if (event.target !== backdrop) return;
      closeDialog(backdrop === elements.setupBackdrop ? "setup" : "detail");
    });
  });
  document.addEventListener("keydown", (event) => {
    const openName = !elements.setupBackdrop.hidden ? "setup" : !elements.detailBackdrop.hidden ? "detail" : "";
    if (!openName) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeDialog(openName);
      return;
    }
    if (event.key !== "Tab") return;
    const dialog = openName === "setup" ? elements.setupDialog : elements.detailDialog;
    const controls = focusable(dialog);
    if (!controls.length) return;
    const first = controls[0];
    const last = controls.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  updateChannelControls();
  loadOptionalData();
  loadChannel(state.channel);
}

if (typeof document !== "undefined") {
  startStorefront();
}
