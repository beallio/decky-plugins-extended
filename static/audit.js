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
        records: [],
      });
    }
    groups.get(slug).records.push(record);
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
    group.records.sort((left, right) =>
      stringValue(left.release).toLowerCase().localeCompare(
        stringValue(right.release).toLowerCase(),
      ),
    );
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
  summary.append(createElement("span", "group-name", group.repository));
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

export function renderAudit(payload, elements) {
  const records = Array.isArray(payload?.releases) ? payload.releases : [];
  const groups = groupAuditRecords(records);
  elements.enforcement.textContent = auditEnforcementCopy(payload?.enforcement_mode);
  renderSummary(elements.summary, records, groups.length);

  elements.groups.replaceChildren();
  if (!groups.length) {
    elements.groups.append(
      createElement("p", "empty", "No releases have been audited yet."),
    );
    return groups;
  }
  for (const group of groups) {
    elements.groups.append(renderGroup(group));
  }
  return groups;
}

async function startAuditLog() {
  const elements = {
    enforcement: document.getElementById("enforcement"),
    summary: document.getElementById("summary"),
    groups: document.getElementById("audit-groups"),
    error: document.getElementById("audit-error"),
  };
  if (!elements.enforcement || !elements.summary || !elements.groups) {
    return;
  }

  try {
    const response = await fetch(AUDIT_ENDPOINT, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`Request failed with ${response.status}`);
    }
    renderAudit(await response.json(), elements);
  } catch {
    elements.summary.textContent = "";
    elements.enforcement.textContent = "The current policy could not be loaded.";
    if (elements.error) elements.error.hidden = false;
  }
}

if (typeof document !== "undefined") {
  startAuditLog();
}
