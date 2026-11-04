// Builds the page from a `Reply`. Every piece of text goes through `el`, so it is a text node.

import { el } from "./dom";
import type { Evidence, Finding, Limit, Reply } from "./types";
import {
  QUESTIONS,
  accessWords,
  confidenceInfo,
  dayLabel,
  exactTime,
  plainTime,
  wholeDays,
} from "./words";

export interface Hooks {
  /** Put `command` on the clipboard. Resolves false if the system refused. */
  copy(command: string): Promise<boolean>;
  /** Run the shipped command line elevated. Called only from the admin button. */
  elevate(): void;
  /** Ask again without the default limit on dated findings. */
  showAll(): void;
}

let counter = 0;
const nextId = (prefix: string): string => `${prefix}-${++counter}`;

const isNote = (finding: Finding): boolean => finding.id.endsWith(".left_out");

const sep = (): HTMLElement => el("span", { class: "sr-only", text: ", " });

// ---- one finding ------------------------------------------------------------------------------

function evidenceItem(item: Evidence, reply: Reply): HTMLElement {
  const label = reply.labels[item.source] || item.source || "Unknown source";
  const facts: string[] = [];
  facts.push(item.recordId === null ? "No record id" : `Record ${item.recordId}`);
  facts.push(item.timestamp === null ? "no timestamp" : exactTime(item.timestamp));
  const li = el("li", { class: "evidence-item" }, [
    el("p", { class: "evidence-source", text: label }),
    el("p", { class: "fine", text: facts.join(" · ") }),
  ]);
  if (item.fields.length > 0) {
    const dl = el("dl", { class: "fields" });
    for (const [name, value] of item.fields) {
      dl.append(el("dt", { text: name }), el("dd", { text: value === "" ? "(empty)" : value }));
    }
    li.append(dl);
  }
  return li;
}

function fixBlock(finding: Finding, hooks: Hooks): HTMLElement | null {
  const fix = finding.fix;
  if (fix === null) return null;
  const block = el("section", { class: "fix", attrs: { "aria-label": "Suggested fix" } }, [
    el("h5", { text: "Suggested fix" }),
  ]);
  if (fix.explanation) block.append(el("p", { text: fix.explanation }));
  if (fix.command === null) {
    block.append(
      el("p", {
        class: "fine",
        text: "The command is hidden because it contained control or text-direction characters, so what you would see might not be what would run.",
      }),
    );
  } else {
    const command = fix.command;
    const copy = el("button", { class: "button", text: "Copy command", attrs: { type: "button" } });
    copy.addEventListener("click", () => {
      void hooks.copy(command).then((ok) => {
        copy.textContent = ok ? "Copied" : "Could not copy";
        setTimeout(() => (copy.textContent = "Copy command"), 2500);
      });
    });
    block.append(el("div", { class: "command" }, [el("code", { text: command }), copy]));
  }
  block.append(
    el("p", {
      class: "fine",
      text: `pcsleuth does not run this command. Copy it and run it yourself${
        fix.needsAdmin ? ", in a terminal opened as administrator" : ""
      }.`,
    }),
  );
  return block;
}

function body(finding: Finding, reply: Reply, hooks: Hooks): HTMLElement {
  const info = confidenceInfo(finding.confidence);
  const panel = el("div", { class: "finding-body" });
  if (finding.explanation) panel.append(el("p", { text: finding.explanation }));

  const facts = el("dl", { class: "facts" });
  facts.append(
    el("dt", { text: "When" }),
    el("dd", { text: finding.time === null ? "No time recorded" : exactTime(finding.time) }),
    el("dt", { text: "How sure" }),
    el("dd", { text: info.meaning ? `${info.label}. ${info.meaning}` : info.label }),
  );
  panel.append(facts);

  if (finding.gap !== null) {
    panel.append(
      el("section", { class: "gap", attrs: { "aria-label": "Not recorded" } }, [
        el("h5", { text: "Windows did not record this" }),
        el("p", { text: finding.gap.what }),
        el("p", { class: "label", text: "What would capture it" }),
        el("p", { text: finding.gap.wouldCapture }),
      ]),
    );
  }

  if (finding.evidence.length > 0) {
    const list = el("ol", { class: "evidence" });
    for (const item of finding.evidence) list.append(evidenceItem(item, reply));
    panel.append(
      el("section", { class: "evidence-block", attrs: { "aria-label": "Evidence" } }, [
        el("h5", { text: `Evidence (${finding.evidence.length})` }),
        list,
      ]),
    );
  } else if (finding.gap === null) {
    panel.append(el("p", { class: "fine", text: "This finding cites no records." }));
  }

  const fix = fixBlock(finding, hooks);
  if (fix !== null) panel.append(fix);
  return panel;
}

function card(finding: Finding, reply: Reply, now: Date, hooks: Hooks, level: "h3" | "h4"): HTMLElement {
  const info = confidenceInfo(finding.confidence);
  const panelId = nextId("evidence");
  const quiet = reply.question === "doctor";

  const meta = el("span", { class: "head-meta" });
  if (finding.time !== null) {
    const time = el("time", { text: plainTime(finding.time, now), attrs: { datetime: finding.time } });
    meta.append(time, sep());
  }
  if (!quiet) {
    meta.append(el("span", { class: `chip chip-${info.tone}`, text: info.label }));
  }

  const button = el(
    "button",
    {
      class: "finding-button",
      attrs: { type: "button", "aria-expanded": "false", "aria-controls": panelId },
    },
    [
      el("span", { class: "head-text", text: finding.headline }),
      sep(),
      meta,
      el("span", { class: "chev", attrs: { "aria-hidden": "true" } }),
    ],
  );

  const panel = body(finding, reply, hooks);
  panel.id = panelId;
  panel.hidden = true;

  button.addEventListener("click", () => {
    const open = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!open));
    panel.hidden = open;
  });

  return el("li", { class: `finding tone-${info.tone}` }, [el(level, { class: "finding-head" }, [button]), panel]);
}

function note(finding: Finding, hooks: Hooks): HTMLElement {
  const showAll = el("button", { class: "button", text: "Show all findings", attrs: { type: "button" } });
  showAll.addEventListener("click", () => hooks.showAll());
  return el("li", { class: "note" }, [
    el("p", { class: "note-head", text: finding.headline }),
    el("p", { class: "fine", text: finding.explanation }),
    showAll,
  ]);
}

// ---- the list ---------------------------------------------------------------------------------

function timeKey(finding: Finding): number {
  if (finding.time === null) return Number.NEGATIVE_INFINITY;
  const t = new Date(finding.time).getTime();
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

/** Findings with a time, newest first, grouped by day. Findings without one follow, in order. */
export function renderFindings(reply: Reply, now: Date, hooks: Hooks): HTMLElement {
  const notes = reply.findings.filter(isNote);
  const rest = reply.findings.filter((f) => !isNote(f));
  const dated = rest.filter((f) => timeKey(f) !== Number.NEGATIVE_INFINITY);
  const undated = rest.filter((f) => timeKey(f) === Number.NEGATIVE_INFINITY);
  dated.sort((a, b) => timeKey(b) - timeKey(a));

  const root = el("div", { class: "findings" });
  const grouped = dated.length > 0;
  const level = grouped ? "h4" : "h3";

  let currentDay = "";
  let list: HTMLElement | null = null;
  for (const finding of dated) {
    const day = dayLabel(finding.time, now) ?? "";
    if (list === null || day !== currentDay) {
      currentDay = day;
      root.append(el("h3", { class: "day", text: day }));
      list = el("ul", { class: "cards" });
      root.append(list);
    }
    list.append(card(finding, reply, now, hooks, level));
  }

  if (undated.length > 0) {
    if (grouped) root.append(el("h3", { class: "day", text: "No date" }));
    const plain = el("ul", { class: "cards" });
    for (const finding of undated) plain.append(card(finding, reply, now, hooks, level));
    root.append(plain);
  }

  if (notes.length > 0) {
    const plain = el("ul", { class: "cards notes" });
    for (const finding of notes) plain.append(note(finding, hooks));
    root.append(plain);
  }
  return root;
}

// ---- around the list --------------------------------------------------------------------------

/** "Looked back 7 days, to Tue 28 Oct (the default). Showing at most 50 dated findings." */
export function scopeLine(reply: Reply, now: Date): string | null {
  const w = reply.window;
  if (w === null) return null;
  const days = wholeDays(w.since, reply.generatedAt);
  const back = days === null ? `Looked back to ${w.since}` : `Looked back ${days} ${days === 1 ? "day" : "days"}, to ${plainTime(w.since, now)}`;
  const dflt = w.sinceIsDefault ? " (the default)" : "";
  return `${back}${dflt}. Showing at most ${w.limit} dated findings, the more serious kinds first and then the newest of each kind.`;
}

export function renderEmpty(reply: Reply): HTMLElement {
  const partial = reply.limits.length > 0;
  const what =
    reply.question === "doctor" || reply.question === "now"
      ? "Nothing to report."
      : "Windows logged nothing of this kind in this period.";
  return el("div", { class: "empty" }, [
    el("p", { class: "empty-head", text: what }),
    el("p", {
      text: partial
        ? "Some sources could not be read, so this may not be everything. They are listed below."
        : "Every source this question reads was readable, so this is a complete answer for the period.",
    }),
  ]);
}

export function renderLoading(title: string): HTMLElement {
  return el("p", { class: "loading", text: `Reading the Windows logs for “${title}”. This can take a few seconds.` });
}

export function renderFailure(message: string, retry: () => void): HTMLElement {
  const again = el("button", { class: "button", text: "Try again", attrs: { type: "button" } });
  again.addEventListener("click", retry);
  return el("div", { class: "failure", attrs: { role: "alert" } }, [
    el("p", { class: "failure-head", text: "This answer could not be read." }),
    el("p", { text: message }),
    el("p", { class: "fine", text: "Nothing was changed. Other questions may still work." }),
    again,
  ]);
}

function limitItem(limit: Limit, reply: Reply): HTMLElement {
  const label = reply.labels[limit.source] || limit.source || "Unknown source";
  const li = el("li", {}, [el("span", { class: "limit-name", text: label }), `: ${accessWords(limit.access)}.`]);
  if (limit.adds !== null) li.append(` Admin rights would add ${limit.adds}.`);
  return li;
}

/** What could not be read, and the one way to read more. `busy` while the permission prompt is up. */
export function renderLimits(reply: Reply, hooks: Hooks, busy: boolean): HTMLElement | null {
  if (reply.limits.length === 0) return null;
  const canElevate = reply.limits.some((limit) => limit.adds !== null);
  const id = nextId("limits");
  const section = el("section", { class: "limits", attrs: { "aria-labelledby": id } }, [
    el("h3", { text: "What could not be read", attrs: { id } }),
  ]);
  // `doctor` already lists every source as a finding.
  if (reply.question !== "doctor") {
    const list = el("ul", { class: "limit-list" });
    for (const limit of reply.limits) list.append(limitItem(limit, reply));
    section.append(list);
  }
  if (canElevate) {
    const button = el("button", {
      class: "button primary",
      text: busy ? "Waiting for the Windows permission prompt…" : "See more with admin",
      attrs: { type: "button", "aria-disabled": String(busy) },
    });
    button.addEventListener("click", () => {
      if (button.getAttribute("aria-disabled") !== "true") hooks.elevate();
    });
    section.append(
      el("div", { class: "admin" }, [
        button,
        el("p", {
          class: "fine",
          text: "Windows will ask for your permission first. pcsleuth then reads the same logs again with admin rights and shows what that adds. It changes nothing on this PC.",
        }),
      ]),
    );
  }
  return section;
}

export const questionTitle = (id: string): string => QUESTIONS.find((q) => q.id === id)?.title ?? id;
