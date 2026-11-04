import { beforeEach, describe, expect, it, vi } from "vitest";

import { normalize } from "../src/normalize";
import {
  type Hooks,
  renderEmpty,
  renderFindings,
  renderLimits,
  renderFailure,
  scopeLine,
} from "../src/view";
import { accessWords, confidenceInfo, dayLabel, plainTime } from "../src/words";

const NOW = new Date(2026, 10, 4, 12, 0, 0); // 4 Nov 2026, local time

/** An ISO time for a local date, so the tests do not depend on the machine's time zone. */
const local = (month: number, day: number, hour: number, minute = 0): string =>
  new Date(2026, month - 1, day, hour, minute).toISOString();

function hooks(over: Partial<Hooks> = {}): Hooks {
  return { copy: async () => true, elevate: () => {}, showAll: () => {}, ...over };
}

function finding(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "wake.power_button",
    question: "wake",
    time: local(11, 4, 9, 30),
    headline: "Woke from sleep: the power button was pressed",
    explanation: "Windows recorded it.",
    confidence: "recorded",
    evidence: [
      {
        source: "event_log_system",
        record_id: "360285",
        timestamp: local(11, 4, 9, 30),
        fields: { WakeSourceType: "1" },
      },
    ],
    not_recorded: null,
    fix: null,
    ...over,
  };
}

function reply(findings: unknown[], limits: unknown[] = [], question = "wake") {
  return normalize({
    answer: { question, generated_at: local(11, 4, 12, 0), findings, limits },
    labels: { event_log_system: "System event log", wake_timers: "Live wake timers" },
    window: { since: local(10, 28, 12, 0), limit: 20, since_is_default: true, limit_is_default: true },
    notice: null,
  });
}

function mount(node: Node): HTMLElement {
  document.body.replaceChildren(node);
  return document.body;
}

beforeEach(() => document.body.replaceChildren());

describe("text from logs is only ever text", () => {
  const hostile = "<img src=x onerror=alert(document.cookie)>";

  it("renders a hostile process name as text, in every place a log string can appear", () => {
    const body = mount(
      renderFindings(
        reply([
          finding({
            headline: `${hostile} hung`,
            explanation: `<script>alert(1)</script> ${hostile}`,
            evidence: [
              {
                source: "event_log_application",
                record_id: hostile,
                timestamp: null,
                fields: { [hostile]: hostile, process: hostile },
              },
            ],
            not_recorded: { what: hostile, would_capture: hostile },
            fix: { command: hostile, explanation: hostile, needs_admin: false },
          }),
        ]),
        NOW,
        hooks(),
      ),
    );

    // No element came out of the log text.
    expect(body.querySelector("img, script, svg, iframe, [onerror], [onload]")).toBeNull();
    // The characters are on the page as characters, and they are in the places they belong.
    expect(body.querySelector(".head-text")?.textContent).toBe(`${hostile} hung`);
    expect(body.querySelector("code")?.textContent).toBe(hostile);
    expect(body.querySelector(".fields dd")?.textContent).toBe(hostile);
    expect(body.querySelector(".fields dt")?.textContent).toBe(hostile);
    expect(body.textContent).toContain("<script>alert(1)</script>");
  });

  it("shows a hostile limit message and a hostile failure as text too", () => {
    const limits = renderLimits(
      reply([], [{ source: hostile, access: { kind: "failed", code: 5, message: hostile }, adds: null }]),
      hooks(),
      false,
    );
    const failure = renderFailure(hostile, () => {});
    mount(limits ?? document.createElement("div"));
    document.body.append(failure);
    expect(document.body.querySelector("img, [onerror]")).toBeNull();
    expect(document.body.textContent).toContain(hostile);
  });
});

describe("a finding is a disclosure that opens its evidence", () => {
  it("is a real button whose aria-expanded drives a hidden panel", () => {
    const body = mount(renderFindings(reply([finding()]), NOW, hooks()));
    const button = body.querySelector<HTMLButtonElement>("button.finding-button")!;
    const panel = document.getElementById(button.getAttribute("aria-controls")!)!;
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(panel.hidden).toBe(true);

    button.click();
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(panel.hidden).toBe(false);
    expect(panel.textContent).toContain("System event log");
    expect(panel.textContent).toContain("Record 360285");
    expect(panel.querySelector("dt")?.textContent).toBeTruthy();

    button.click();
    expect(panel.hidden).toBe(true);
  });

  it("names the confidence in words on the button, not by colour", () => {
    const body = mount(renderFindings(reply([finding()]), NOW, hooks()));
    expect(body.querySelector("button.finding-button")?.textContent).toContain("Recorded");
    expect(body.querySelector("button.finding-button")?.textContent).toContain("Today, 09:30");
  });

  it("gives each card a heading inside a day heading, newest first", () => {
    const body = mount(
      renderFindings(
        reply([
          finding({ id: "a", headline: "older", time: local(11, 2, 8) }),
          finding({ id: "b", headline: "newest", time: local(11, 4, 11) }),
          finding({ id: "c", headline: "yesterday", time: local(11, 3, 10) }),
        ]),
        NOW,
        hooks(),
      ),
    );
    const days = [...body.querySelectorAll("h3.day")].map((h) => h.textContent);
    expect(days).toEqual(["Today", "Yesterday", dayLabel(local(11, 2, 8), NOW)]);
    const order = [...body.querySelectorAll("h4 .head-text")].map((h) => h.textContent);
    expect(order).toEqual(["newest", "yesterday", "older"]);
  });

  it("reads a not recorded finding as an answer, with what would capture it", () => {
    const body = mount(
      renderFindings(
        reply([
          finding({
            id: "nosleep.past",
            time: null,
            confidence: "not_recorded",
            headline: "Past blockers are not recorded",
            evidence: [],
            not_recorded: { what: "Which program kept it awake", would_capture: "The pcsleuth recorder" },
          }),
        ]),
        NOW,
        hooks(),
      ),
    );
    const button = body.querySelector<HTMLButtonElement>("button.finding-button")!;
    expect(button.textContent).toContain("Not recorded");
    button.click();
    const text = body.textContent ?? "";
    expect(text).toContain("Windows did not record this");
    expect(text).toContain("Which program kept it awake");
    expect(text).toContain("The pcsleuth recorder");
    expect(body.querySelector("[role=alert]")).toBeNull();
    expect(body.querySelector(".chip-not-recorded")).not.toBeNull();
  });
});

describe("a fix is a command to copy, never to apply", () => {
  const withFix = (fix: Record<string, unknown>) =>
    reply([finding({ fix: { explanation: "Stops the wake.", needs_admin: true, ...fix } })]);

  it("shows the exact command, says pcsleuth does not run it, and copies it on click", async () => {
    const copy = vi.fn(async () => true);
    const body = mount(renderFindings(withFix({ command: "powercfg /devicedisablewake \"X\"" }), NOW, hooks({ copy })));
    expect(body.querySelector("code")?.textContent).toBe('powercfg /devicedisablewake "X"');
    expect(body.textContent).toContain("pcsleuth does not run this command");
    expect(body.textContent).toContain("administrator");
    const button = [...body.querySelectorAll("button")].find((b) => b.textContent === "Copy command")!;
    button.click();
    expect(copy).toHaveBeenCalledWith('powercfg /devicedisablewake "X"');
    // There is no button that applies, runs or fixes anything.
    const labels = [...body.querySelectorAll("button")].map((b) => b.textContent ?? "");
    expect(labels.filter((l) => /apply|run|fix now|execute/i.test(l))).toEqual([]);
  });

  it("withholds a command that carried hidden characters instead of showing a different one", () => {
    const body = mount(renderFindings(withFix({ command: null, withheld: true }), NOW, hooks()));
    expect(body.querySelector("code")).toBeNull();
    expect([...body.querySelectorAll("button")].some((b) => b.textContent === "Copy command")).toBe(false);
    expect(body.textContent).toContain("hidden");
  });
});

describe("states", () => {
  it("never throws on missing or wrong-typed fields", () => {
    const messy = normalize({
      answer: { findings: [{}, 5, null, { evidence: "x", fix: 3, headline: 7 }, { time: "not a date" }], limits: [{}, null] },
      labels: 4,
      window: { since: 3 },
    });
    expect(messy.findings).toHaveLength(5);
    const body = mount(renderFindings(messy, NOW, hooks()));
    for (const button of body.querySelectorAll<HTMLButtonElement>("button.finding-button")) button.click();
    expect(body.querySelectorAll("li.finding").length).toBe(5);
    expect(normalize(undefined).findings).toEqual([]);
    expect(normalize("x").limits).toEqual([]);
    expect(renderLimits(messy, hooks(), false)).not.toBeNull();
    expect(scopeLine(messy, NOW)).toBeNull();
  });

  it("says plainly when nothing was found, and whether every source was readable", () => {
    const clean = mount(renderEmpty(reply([])));
    expect(clean.textContent).toContain("Windows logged nothing of this kind");
    expect(clean.textContent).toContain("complete answer");

    const partial = mount(renderEmpty(reply([], [{ source: "wake_timers", access: { kind: "needs_admin" }, adds: "x" }])));
    expect(partial.textContent).toContain("may not be everything");
  });

  it("lists what could not be read and offers admin only where it adds something", () => {
    const needsAdmin = reply([], [
      { source: "wake_timers", access: { kind: "needs_admin" }, adds: "live wake timers" },
      { source: "event_log_system", access: { kind: "partial", message: "2 records unreadable" }, adds: null },
    ]);
    const section = mount(renderLimits(needsAdmin, hooks(), false)!);
    expect(section.textContent).toContain("Live wake timers: needs admin rights.");
    expect(section.textContent).toContain("Admin rights would add live wake timers.");
    expect(section.textContent).toContain("only partly readable (2 records unreadable)");
    expect(section.querySelector("button")?.textContent).toBe("See more with admin");

    const noAdmin = reply([], [{ source: "event_log_system", access: { kind: "missing" }, adds: null }]);
    expect(mount(renderLimits(noAdmin, hooks(), false)!).querySelector("button")).toBeNull();
    expect(renderLimits(reply([]), hooks(), false)).toBeNull();
  });

  it("calls elevate only on a click, and not again while the prompt is up", () => {
    const elevate = vi.fn();
    const limits = reply([], [{ source: "wake_timers", access: { kind: "needs_admin" }, adds: "x" }]);
    const idle = mount(renderLimits(limits, hooks({ elevate }), false)!);
    expect(elevate).not.toHaveBeenCalled();
    idle.querySelector("button")!.click();
    expect(elevate).toHaveBeenCalledTimes(1);

    const busy = mount(renderLimits(limits, hooks({ elevate }), true)!);
    const button = busy.querySelector("button")!;
    expect(button.getAttribute("aria-disabled")).toBe("true");
    button.click();
    expect(elevate).toHaveBeenCalledTimes(1);
  });

  it("describes the window it looked at", () => {
    expect(scopeLine(reply([]), NOW)).toContain("Looked back 7 days");
    expect(scopeLine(reply([]), NOW)).toContain("(the default)");
  });

  it("shows a failure as an alert with a way to try again", () => {
    const retry = vi.fn();
    const body = mount(renderFailure("The System log could not be opened.", retry));
    expect(body.querySelector("[role=alert]")?.textContent).toContain("could not be opened");
    body.querySelector("button")!.click();
    expect(retry).toHaveBeenCalled();
  });

  it("offers show all on the left out note instead of a card", () => {
    const showAll = vi.fn();
    const body = mount(
      renderFindings(
        reply([
          finding({ id: "timeline.left_out", time: null, headline: "5 more dated findings are not shown", confidence: "recorded" }),
        ]),
        NOW,
        hooks({ showAll }),
      ),
    );
    expect(body.querySelector("button.finding-button")).toBeNull();
    body.querySelector("button")!.click();
    expect(showAll).toHaveBeenCalled();
  });
});

describe("words", () => {
  it("names every confidence in words and keeps an unknown one visible", () => {
    expect(confidenceInfo("recorded").label).toBe("Recorded");
    expect(confidenceInfo("correlated").label).toContain("Likely");
    expect(confidenceInfo("sampled").label).toBe("Sampled");
    expect(confidenceInfo("not_recorded").label).toBe("Not recorded");
    expect(confidenceInfo("surprising").label).toBe("surprising");
    expect(confidenceInfo("").label).toBe("Unknown");
  });

  it("writes times plainly", () => {
    expect(dayLabel(local(11, 4, 1), NOW)).toBe("Today");
    expect(dayLabel(local(11, 3, 23), NOW)).toBe("Yesterday");
    expect(plainTime(local(11, 4, 9, 5), NOW)).toBe("Today, 09:05");
    expect(plainTime("garbage", NOW)).toBe("garbage");
    expect(plainTime(null, NOW)).toBe("no time recorded");
  });

  it("explains each kind of access", () => {
    expect(accessWords({ kind: "needs_admin", message: "", code: null })).toBe("needs admin rights");
    expect(accessWords({ kind: "failed", message: "denied", code: 5 })).toContain("0x00000005");
    expect(accessWords({ kind: "mystery", message: "", code: null })).toBe("could not be read");
  });
});
