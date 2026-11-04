// Wires the page: the questions as navigation, one answer at a time, and the states in between.

import "./style.css";

import { ask, askElevated, describeError } from "./api";
import { copyText } from "./clipboard";
import { clear, el } from "./dom";
import type { QuestionId, Reply } from "./types";
import {
  type Hooks,
  renderEmpty,
  renderFailure,
  renderFindings,
  renderLimits,
  renderLoading,
  scopeLine,
} from "./view";
import { QUESTIONS, plainTime } from "./words";

/** `Show all findings` asks for this many. The engine still orders them the same way. */
const SHOW_ALL = 1000;

const need = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (node === null) throw new Error(`index.html has no #${id}`);
  return node as T;
};

const nav = need<HTMLUListElement>("nav");
const title = need<HTMLHeadingElement>("title");
const about = need<HTMLParagraphElement>("about");
const results = need<HTMLDivElement>("results");
const refresh = need<HTMLButtonElement>("refresh");
const status = need<HTMLDivElement>("status");

let current: QuestionId = "timeline";
let limit: number | undefined;
let sequence = 0;
let elevating = false;
let shown: Reply | null = null;

const info = (id: QuestionId) => QUESTIONS.find((q) => q.id === id) ?? QUESTIONS[0]!;

/** Say something to a screen reader without moving focus. */
function announce(message: string): void {
  status.textContent = "";
  // A change of text is what is announced; clearing first makes a repeat message count.
  setTimeout(() => (status.textContent = message), 30);
}

const hooks: Hooks = {
  copy: async (command) => {
    const ok = await copyText(command);
    announce(ok ? "Command copied." : "The command could not be copied. Select it and copy it by hand.");
    return ok;
  },
  elevate: () => void elevate(),
  showAll: () => void load(current, SHOW_ALL, true),
};

function markCurrent(): void {
  for (const button of nav.querySelectorAll("button")) {
    if (button.dataset["question"] === current) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  title.textContent = info(current).title;
  about.textContent = info(current).about;
}

function summary(reply: Reply): string {
  const count = reply.findings.filter((f) => !f.id.endsWith(".left_out")).length;
  const found = count === 0 ? "nothing found" : `${count} ${count === 1 ? "finding" : "findings"}`;
  const unread =
    reply.limits.length === 0
      ? ""
      : `, ${reply.limits.length} ${reply.limits.length === 1 ? "source" : "sources"} could not be fully read`;
  return `${info(current).nav}: ${found}${unread}.`;
}

type Banner = { kind: "admin" } | { kind: "warning"; text: string } | null;

function paint(reply: Reply, banner: Banner): void {
  const now = new Date();
  clear(results);
  const scope = scopeLine(reply, now);
  if (scope !== null) results.append(el("p", { class: "scope", text: scope }));

  if (banner?.kind === "admin") {
    results.append(
      el("p", {
        class: "banner",
        text: `Read again with admin rights at ${plainTime(new Date().toISOString(), now)}. This includes what only admin can read.`,
      }),
    );
  } else if (banner?.kind === "warning") {
    results.append(el("p", { class: "banner warning", text: banner.text }));
  }
  if (reply.notice !== null) {
    results.append(el("p", { class: "banner warning", text: `${reply.notice} The answer below is the one without admin.` }));
  }

  if (reply.findings.length === 0) results.append(renderEmpty(reply));
  else results.append(renderFindings(reply, now, hooks));

  const limits = renderLimits(reply, hooks, elevating);
  if (limits !== null) results.append(limits);
  results.setAttribute("aria-busy", "false");
  shown = reply;
}

async function load(question: QuestionId, wanted?: number, focusTitle = false): Promise<void> {
  const mine = ++sequence;
  if (question !== current) elevating = false;
  current = question;
  limit = wanted;
  markCurrent();
  results.setAttribute("aria-busy", "true");
  clear(results);
  results.append(renderLoading(info(question).title));
  announce(`Loading ${info(question).nav}.`);
  if (focusTitle) title.focus();
  try {
    const reply = await ask(question, wanted);
    if (mine !== sequence) return;
    paint(reply, null);
    announce(summary(reply));
  } catch (error) {
    if (mine !== sequence) return;
    shown = null;
    results.setAttribute("aria-busy", "false");
    clear(results);
    results.append(renderFailure(describeError(error), () => void load(question, wanted, true)));
    announce(`${info(question).nav} could not be read.`);
  }
}

async function elevate(): Promise<void> {
  if (elevating || shown === null) return;
  const mine = ++sequence;
  const before = shown;
  elevating = true;
  const button = results.querySelector<HTMLButtonElement>(".admin button");
  button?.setAttribute("aria-disabled", "true");
  if (button) button.textContent = "Waiting for the Windows permission prompt…";
  announce("Waiting for the Windows permission prompt.");
  try {
    const reply = await askElevated(current, limit);
    if (mine !== sequence) return;
    elevating = false;
    paint(reply, reply.notice === null ? { kind: "admin" } : null);
    title.focus();
    announce(reply.notice === null ? `Read with admin rights. ${summary(reply)}` : "Admin rights were not granted. Showing the answer without admin.");
  } catch (error) {
    if (mine !== sequence) return;
    elevating = false;
    paint(before, { kind: "warning", text: `Could not read with admin rights: ${describeError(error)}` });
    title.focus();
    announce("Could not read with admin rights.");
  }
}

function buildNav(): void {
  for (const question of QUESTIONS) {
    const button = el("button", { class: "nav-button", text: question.nav, attrs: { type: "button" } });
    button.dataset["question"] = question.id;
    button.addEventListener("click", () => void load(question.id, undefined, true));
    nav.append(el("li", {}, [button]));
  }
}

refresh.addEventListener("click", () => void load(current, limit));
buildNav();
void load("timeline");
