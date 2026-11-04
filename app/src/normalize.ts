// Turns whatever the Rust side sent into a `Reply`. Every field has a default, so a log record
// with a missing field shows less, and never throws.

import type { Access, Evidence, Finding, Fix, Gap, Limit, Reply, Window } from "./types";

type Bag = Record<string, unknown>;

const isBag = (value: unknown): value is Bag =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const text = (value: unknown): string =>
  typeof value === "string" ? value : typeof value === "number" ? String(value) : "";

const textOrNull = (value: unknown): string | null => {
  const t = text(value);
  return t === "" ? null : t;
};

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

function evidence(raw: unknown): Evidence {
  const e = isBag(raw) ? raw : {};
  const fields = isBag(e["fields"]) ? Object.entries(e["fields"]) : [];
  return {
    source: text(e["source"]),
    recordId: textOrNull(e["record_id"]),
    timestamp: textOrNull(e["timestamp"]),
    fields: fields.map(([name, value]) => [name, text(value)]),
  };
}

function gap(raw: unknown): Gap | null {
  if (!isBag(raw)) return null;
  return { what: text(raw["what"]), wouldCapture: text(raw["would_capture"]) };
}

function fix(raw: unknown): Fix | null {
  if (!isBag(raw)) return null;
  const command = textOrNull(raw["command"]);
  return {
    command,
    withheld: raw["withheld"] === true || command === null,
    explanation: text(raw["explanation"]),
    needsAdmin: raw["needs_admin"] === true,
  };
}

function finding(raw: unknown): Finding {
  const f = isBag(raw) ? raw : {};
  return {
    id: text(f["id"]),
    time: textOrNull(f["time"]),
    headline: text(f["headline"]) || "(no headline)",
    explanation: text(f["explanation"]),
    confidence: text(f["confidence"]),
    evidence: list(f["evidence"]).map(evidence),
    gap: gap(f["not_recorded"]),
    fix: fix(f["fix"]),
  };
}

function access(raw: unknown): Access {
  const a = isBag(raw) ? raw : {};
  return {
    kind: text(a["kind"]),
    message: text(a["message"]),
    code: typeof a["code"] === "number" ? a["code"] : null,
  };
}

function limit(raw: unknown): Limit {
  const l = isBag(raw) ? raw : {};
  return { source: text(l["source"]), access: access(l["access"]), adds: textOrNull(l["adds"]) };
}

function window(raw: unknown): Window | null {
  if (!isBag(raw)) return null;
  const since = textOrNull(raw["since"]);
  const limit = typeof raw["limit"] === "number" ? raw["limit"] : 0;
  // A window with no readable start or no limit is not worth describing.
  if (since === null || Number.isNaN(Date.parse(since)) || limit <= 0) return null;
  return {
    since,
    limit,
    sinceIsDefault: raw["since_is_default"] === true,
    limitIsDefault: raw["limit_is_default"] === true,
  };
}

export function normalize(raw: unknown): Reply {
  const reply = isBag(raw) ? raw : {};
  const answer = isBag(reply["answer"]) ? reply["answer"] : {};
  const labels: Record<string, string> = {};
  if (isBag(reply["labels"])) {
    for (const [id, label] of Object.entries(reply["labels"])) labels[id] = text(label);
  }
  return {
    question: text(answer["question"]),
    generatedAt: text(answer["generated_at"]),
    findings: list(answer["findings"]).map(finding),
    limits: list(answer["limits"]).map(limit),
    labels,
    window: window(reply["window"]),
    notice: textOrNull(reply["notice"]),
  };
}
