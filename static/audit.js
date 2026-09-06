// The audit page renders from audit.json rather than baking its records into
// HTML. The published record is the same file the storefront already fetches
// for its detail pane, so the page stays a few KB instead of 1.5 MB.

const AUDIT_ENDPOINT = "audit.json";

function stringValue(value) {
  return typeof value === "string" ? value.trim() : "";
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

export function auditEnforcementCopy(enforcementMode) {
  const mode = stringValue(enforcementMode) || "unknown";
  if (mode === "enforce") {
    return `Current enforcement mode: ${mode}. Releases with a BLOCK verdict are excluded from the catalogs.`;
  }
  if (mode === "report-only") {
    return `Current enforcement mode: ${mode}. No releases are currently excluded from the catalogs because of audit verdicts; BLOCK results are reported only.`;
  }
  return `Current enforcement mode: ${mode}. Consult the repository policy for how this mode affects the catalogs.`;
}

export function repositorySlug(repository) {
  return stringValue(repository)
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
}

// A fragment has to survive being typed and linked, so keep it to characters
// that need no escaping. Two repositories cannot collide here: the slug is
// already unique and only its separators are rewritten.
export function groupId(repository) {
  return `plugin-${repositorySlug(repository).replace(/[^a-z0-9]+/g, "-")}`;
}

function assetOrder(assetId) {
  // Published as a string, so compare it as a number.
  const value = Number.parseInt(stringValue(assetId), 10);
  return Number.isFinite(value) ? value : -1;
}

export function groupAuditRecords(records) {
  const groups = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    if (!record || typeof record !== "object") continue;
    const slug = repositorySlug(record.repository);
    if (!slug) continue;
    if (!groups.has(slug)) {
      groups.set(slug, {
        slug,
        id: groupId(record.repository),
        repository: stringValue(record.repository),
        name: "",
        records: [],
      });
    }
    const group = groups.get(slug);
    group.name = group.name || stringValue(record.plugin_name);
    group.records.push(record);
  }

  for (const group of groups.values()) {
    // BLOCK is the only tier that can remove a release, so a group holding one
    // is a blocked plugin however many other releases passed.
    group.blocked = group.records.some(
      (record) => stringValue(record.classification) === "BLOCK",
    );
    group.classification = group.blocked
      ? "BLOCK"
      : [...new Set(group.records.map((record) => stringValue(record.classification)))]
          .sort()
          .join(", ");
    // Newest first, by GitHub asset id. Those are monotonic, so they order
    // releases chronologically without parsing a version -- which matters for
    // repositories whose tags differ only by a git hash. Comparing the release
    // string instead put v2.0.10 before v2.0.2.
    group.records.sort(
      (left, right) => assetOrder(right.asset_id) - assetOrder(left.asset_id),
    );
    group.records.forEach((record, index) => {
      record.newestAudited = index === 0;
    });
  }

  // Same ordering rule the generator used: blocked first, then alphabetical.
  return [...groups.values()].sort(
    (left, right) =>
      Number(right.blocked) - Number(left.blocked) ||
      left.slug.localeCompare(right.slug),
  );
}

export function summarizeAudit(records) {
  const counts = { BLOCK: 0, AUDIT_ERROR: 0, MANUAL_REVIEW: 0, other: 0 };
  for (const record of Array.isArray(records) ? records : []) {
    const classification = stringValue(record?.classification);
    if (classification in counts) {
      counts[classification] += 1;
    } else {
      counts.other += 1;
    }
  }
  return counts;
}

export function filterAuditRecords(records, filters = {}) {
  const query = stringValue(filters.query).toLowerCase();
  const classification = stringValue(filters.classification);
  const rule = stringValue(filters.rule);
  return (Array.isArray(records) ? records : []).filter((record) => {
    if (!record || typeof record !== "object") return false;
    if (classification && stringValue(record.classification) !== classification) {
      return false;
    }
    if (rule) {
      const ruleIds = Array.isArray(record.rule_ids) ? record.rule_ids : [];
      if (!ruleIds.some((value) => stringValue(value) === rule)) return false;
    }
    if (!query) return true;
    // Match either half of what the row shows.
    return (
      repositorySlug(record.repository).includes(query) ||
      stringValue(record.plugin_name).toLowerCase().includes(query)
    );
  });
}

export function auditFilterOptions(records) {
  const classifications = new Set();
  const rules = new Set();
  for (const record of Array.isArray(records) ? records : []) {
    const classification = stringValue(record?.classification);
    if (classification) classifications.add(classification);
    for (const value of Array.isArray(record?.rule_ids) ? record.rule_ids : []) {
      const rule = stringValue(value);
      if (rule) rules.add(rule);
    }
  }
  return {
    classifications: [...classifications].sort(),
    rules: [...rules].sort(),
  };
}

function renderSummary(target, records, groupCount) {
  const counts = summarizeAudit(records);
  target.replaceChildren();
  const parts = [
    ["blocked", counts.BLOCK, true],
    ["could not be audited", counts.AUDIT_ERROR, false],
    ["need review", counts.MANUAL_REVIEW, false],
    ["passed", counts.other, false],
  ];
  parts.forEach(([label, value, isBlock], index) => {
    if (index > 0) target.append(document.createTextNode(" · "));
    target.append(createElement("span", `count${isBlock ? " block" : ""}`, String(value)));
    target.append(document.createTextNode(` ${label}`));
  });
  target.append(document.createTextNode(` · across ${groupCount} plugins`));
}

function renderRecord(record) {
  const classification = stringValue(record.classification);
  const stored = stringValue(record.stored_classification);
  const article = createElement("article", "verdict");
  if (record.newestAudited) {
    // "Newest audited", not "latest": a blocked release is audited but kept
    // out of the catalogs, and versions the official store publishes are
    // deferred and never audited here at all.
    article.append(createElement("p", "newest", "Newest audited release"));
  }
  article.append(
    createElement(
      "div",
      `classification${classification === "BLOCK" ? " block" : ""}`,
      `Effective classification: ${classification}`,
    ),
  );

  if (stored && stored !== classification) {
    const note = createElement("p", "policy-disagreement");
    note.append(createElement("strong", "", `Stored verdict: ${stored}.`));
    note.append(
      document.createTextNode(
        " This verdict predates the current policy; its recorded blocking rule IDs are not currently blockable.",
      ),
    );
    article.append(note);
  }

  const list = createElement("dl");
  const rows = [
    ["Release", stringValue(record.release)],
    ["Tag / asset", `${stringValue(record.tag)} / ${stringValue(record.asset_id)}`],
    [
      "Identity",
      `${stringValue(record.identity_status)} — ${stringValue(record.outcome)}`,
    ],
    ["Current hash", stringValue(record.current_artifact_sha256) || "Not verified"],
    ["Stored hash", stringValue(record.stored_artifact_sha256) || "Not recorded"],
  ];
  for (const [label, value] of rows) {
    list.append(createElement("dt", "", label));
    list.append(createElement("dd", "", value));
  }

  list.append(createElement("dt", "", "Rule IDs"));
  const rules = createElement("dd", "rules");
  const ruleIds = Array.isArray(record.rule_ids) ? record.rule_ids : [];
  if (ruleIds.length) {
    for (const ruleId of ruleIds) {
      rules.append(createElement("code", "", stringValue(ruleId)));
    }
  } else {
    rules.append(createElement("span", "none-recorded", "None recorded"));
  }
  list.append(rules);

  list.append(createElement("dt", "", "Audited"));
  list.append(createElement("dd", "", stringValue(record.audited_at) || "Not recorded"));
  article.append(list);
  return article;
}

function renderGroup(group) {
  const details = createElement("details", `plugin-group${group.blocked ? " block" : ""}`);
  details.id = group.id;
  const summary = createElement("summary");
  const heading = createElement("span", "group-heading");
  // The name is what a reader recognises; the slug is what identifies it.
  heading.append(createElement("span", "group-name", group.name || group.repository));
  if (group.name) {
    heading.append(createElement("span", "group-repository", group.repository));
  }
  summary.append(heading);
  summary.append(
    createElement(
      "span",
      `classification${group.blocked ? " block" : ""}`,
      group.classification,
    ),
  );
  summary.append(
    createElement(
      "span",
      "group-count",
      `${group.records.length} release${group.records.length === 1 ? "" : "s"}`,
    ),
  );
  details.append(summary);

  const body = createElement("div", "group-body");
  for (const record of group.records) {
    body.append(renderRecord(record));
  }
  details.append(body);
  // A blocked plugin is the one thing nobody should have to click to find.
  details.open = group.blocked;
  return details;
}

export function renderAudit(payload, elements, filters = {}) {
  const records = Array.isArray(payload?.releases) ? payload.releases : [];
  const matched = filterAuditRecords(records, filters);
  const groups = groupAuditRecords(matched);
  const allGroups = groupAuditRecords(records);
  elements.enforcement.textContent = auditEnforcementCopy(payload?.enforcement_mode);
  // The summary describes the whole published record, not the current view, so
  // the filtered count gets its own line rather than rewriting the totals.
  renderSummary(elements.summary, records, allGroups.length);

  const filtered =
    stringValue(filters.query) ||
    stringValue(filters.classification) ||
    stringValue(filters.rule);
  if (elements.results) {
    elements.results.hidden = !filtered;
    elements.results.textContent = filtered
      ? `Showing ${groups.length} of ${allGroups.length} plugins`
      : "";
  }

  elements.groups.replaceChildren();
  if (!groups.length) {
    elements.groups.append(
      createElement(
        "p",
        "empty",
        filtered
          ? "No plugins match these filters."
          : "No releases have been audited yet.",
      ),
    );
    return groups;
  }
  for (const group of groups) {
    elements.groups.append(renderGroup(group));
  }
  return groups;
}

function focusFragmentGroup() {
  const id = decodeURIComponent(window.location.hash.replace(/^#/, ""));
  if (!id) return null;
  const group = document.getElementById(id);
  // A filter carried in the URL can hide the target; say nothing rather than
  // scrolling somewhere arbitrary.
  if (!group) return null;
  group.open = true;
  group.scrollIntoView({ block: "start" });
  return group;
}

function fillOptions(select, values) {
  // Keep the leading "all" option and rebuild the rest from the record.
  const all = select.options[0];
  select.replaceChildren(all);
  for (const value of values) {
    select.append(new Option(value, value));
  }
}

async function startAuditLog() {
  const elements = {
    enforcement: document.getElementById("enforcement"),
    summary: document.getElementById("summary"),
    groups: document.getElementById("audit-groups"),
    error: document.getElementById("audit-error"),
    results: document.getElementById("audit-results"),
    search: document.getElementById("audit-search"),
    searchClear: document.getElementById("audit-search-clear"),
    classification: document.getElementById("audit-classification"),
    rule: document.getElementById("audit-rule"),
  };
  if (!elements.enforcement || !elements.summary || !elements.groups) {
    return;
  }

  const params = new URLSearchParams(window.location.search);
  const filters = {
    query: stringValue(params.get("query")),
    classification: stringValue(params.get("classification")),
    rule: stringValue(params.get("rule")),
  };

  let payload = null;

  function updateUrl() {
    const next = new URLSearchParams();
    for (const key of ["query", "classification", "rule"]) {
      if (filters[key]) next.set(key, filters[key]);
    }
    const query = next.toString();
    window.history.replaceState(
      {},
      "",
      `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`,
    );
  }

  function apply() {
    if (elements.searchClear) {
      elements.searchClear.hidden = !filters.query;
    }
    renderAudit(payload, elements, filters);
  }

  try {
    const response = await fetch(AUDIT_ENDPOINT, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`Request failed with ${response.status}`);
    }
    payload = await response.json();
  } catch {
    elements.summary.textContent = "";
    elements.enforcement.textContent = "The current policy could not be loaded.";
    if (elements.error) elements.error.hidden = false;
    return;
  }

  const options = auditFilterOptions(payload?.releases);
  if (elements.classification) {
    fillOptions(elements.classification, options.classifications);
    elements.classification.value = filters.classification;
    // A value carried in from the URL that the record does not contain would
    // leave the select blank while still filtering; drop it instead.
    filters.classification = elements.classification.value;
    elements.classification.addEventListener("change", (event) => {
      filters.classification = event.target.value;
      updateUrl();
      apply();
    });
  }
  if (elements.rule) {
    fillOptions(elements.rule, options.rules);
    elements.rule.value = filters.rule;
    filters.rule = elements.rule.value;
    elements.rule.addEventListener("change", (event) => {
      filters.rule = event.target.value;
      updateUrl();
      apply();
    });
  }
  if (elements.search) {
    elements.search.value = filters.query;
    elements.search.addEventListener("input", (event) => {
      filters.query = event.target.value;
      updateUrl();
      apply();
    });
  }
  elements.searchClear?.addEventListener("click", () => {
    elements.search.value = "";
    filters.query = "";
    updateUrl();
    apply();
    elements.search.focus();
  });

  updateUrl();
  apply();
  focusFragmentGroup();
  // A link from a plugin card can arrive while the page is already open.
  window.addEventListener("hashchange", focusFragmentGroup);
}

if (typeof document !== "undefined") {
  startAuditLog();
}
