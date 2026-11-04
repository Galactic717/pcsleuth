// Plain words and plain times. Pure functions: no DOM.

import type { Access, QuestionId } from "./types";

export interface Question {
  id: QuestionId;
  /** The navigation label. */
  nav: string;
  /** The heading above the answers. */
  title: string;
  /** One line under the heading. */
  about: string;
}

export const QUESTIONS: readonly Question[] = [
  {
    id: "timeline",
    nav: "Timeline",
    title: "Timeline",
    about: "Wakes, crashes, hangs and slowdowns that Windows logged, newest first.",
  },
  { id: "wake", nav: "Wake", title: "Why did it wake up?", about: "What woke the PC from sleep." },
  {
    id: "nosleep",
    nav: "Won’t sleep",
    title: "Why won’t it sleep?",
    about: "What keeps the PC awake, and what Windows recorded about it.",
  },
  {
    id: "battery",
    nav: "Battery",
    title: "What drained the battery?",
    about: "Battery use and wear from the Windows battery report.",
  },
  {
    id: "crash",
    nav: "Crashes",
    title: "What crashed or froze?",
    about: "Program crashes and hangs, unexpected restarts and blue screens.",
  },
  {
    id: "slow",
    nav: "Slow",
    title: "Why is it slow?",
    about: "Hangs, low memory, throttled processors and storage warnings.",
  },
  {
    id: "now",
    nav: "Right now",
    title: "What is it doing right now?",
    about: "Busiest programs, power source and what is armed to wake the PC.",
  },
  {
    id: "doctor",
    nav: "Doctor",
    title: "Which logs can be read?",
    about: "What pcsleuth can read on this PC, and what admin rights would add.",
  },
];

export interface ConfidenceInfo {
  label: string;
  meaning: string;
  /** A CSS class suffix. Each one differs in border style as well as colour. */
  tone: string;
}

export function confidenceInfo(confidence: string): ConfidenceInfo {
  switch (confidence) {
    case "recorded":
      return { label: "Recorded", meaning: "Windows states it directly.", tone: "recorded" };
    case "correlated":
      return {
        label: "Likely (correlated)",
        meaning: "Inferred from records near it in time. Not stated by Windows.",
        tone: "correlated",
      };
    case "sampled":
      return {
        label: "Sampled",
        meaning: "Seen by the recorder at an interval, so shorter events may be missed.",
        tone: "sampled",
      };
    case "not_recorded":
      return {
        label: "Not recorded",
        meaning: "Windows did not keep this.",
        tone: "not-recorded",
      };
    default:
      return { label: confidence || "Unknown", meaning: "", tone: "unknown" };
  }
}

/** What a source's access means, in words. */
export function accessWords(access: Access): string {
  switch (access.kind) {
    case "ok":
      return "can be read";
    case "needs_admin":
      return "needs admin rights";
    case "log_disabled":
      return "the log is switched off, so nothing was recorded";
    case "missing":
      return "not present on this PC";
    case "partial":
      return access.message ? `only partly readable (${access.message})` : "only partly readable";
    case "failed": {
      const code = access.code === null ? "" : ` 0x${(access.code >>> 0).toString(16).padStart(8, "0")}`;
      const why = access.message ? `: ${access.message}` : "";
      return `could not be read (error${code})${why}`;
    }
    default:
      return "could not be read";
  }
}

const dayFormat = new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short" });
const clockFormat = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});
const exactFormat = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZoneName: "shortOffset",
});

const dayStart = (date: Date): number =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();

function parse(iso: string | null): Date | null {
  if (iso === null) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "Today", "Yesterday" or "Tue 3 Nov", in the PC's time zone. `null` for no or unreadable time. */
export function dayLabel(iso: string | null, now: Date): string | null {
  const date = parse(iso);
  if (date === null) return null;
  const days = Math.round((dayStart(now) - dayStart(date)) / 86_400_000);
  if (days === 0) return "Today";
  if (days === 1) return "Yesterday";
  return dayFormat.format(date);
}

/** "Today, 14:33", "Yesterday, 09:05" or "Tue 3 Nov, 14:33". Unreadable text is shown as it is. */
export function plainTime(iso: string | null, now: Date): string {
  const date = parse(iso);
  if (date === null) return iso ?? "no time recorded";
  return `${dayLabel(iso, now)}, ${clockFormat.format(date)}`;
}

/** "3 Nov 2026, 14:33:08 GMT+2": the full time, for evidence. */
export function exactTime(iso: string | null): string {
  const date = parse(iso);
  if (date === null) return iso ?? "not given";
  return exactFormat.format(date);
}

/** Whole days between two instants, at least 0. */
export function wholeDays(fromIso: string, toIso: string): number | null {
  const from = parse(fromIso);
  const to = parse(toIso);
  if (from === null || to === null) return null;
  return Math.max(0, Math.round((to.getTime() - from.getTime()) / 86_400_000));
}
