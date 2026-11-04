// The only place the page talks to Rust. Each question is one Tauri command of the same name.

import { invoke } from "@tauri-apps/api/core";

import { normalize } from "./normalize";
import type { QuestionId, Reply } from "./types";

/** Ask one question. `limit` is the most dated findings to keep; leave it out for the default. */
export async function ask(question: QuestionId, limit?: number): Promise<Reply> {
  return normalize(await invoke(question, limit === undefined ? {} : { limit }));
}

/** Ask again through the shipped command line, which starts the Windows permission prompt. */
export async function askElevated(question: QuestionId, limit?: number): Promise<Reply> {
  return normalize(await invoke("elevated", limit === undefined ? { question } : { question, limit }));
}

/** An error from `invoke` is the string the Rust side returned, or an Error from the bridge. */
export function describeError(error: unknown): string {
  if (typeof error === "string" && error !== "") return error;
  if (error instanceof Error && error.message !== "") return error.message;
  return "Unknown error.";
}
