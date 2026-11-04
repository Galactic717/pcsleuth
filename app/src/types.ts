// The shape the Rust side sends. It mirrors the JSON of `pcsleuth_core::Answer` (schema_version 1)
// plus the words and window from `app/src-tauri/src/reply.rs`. Nothing here is trusted: `normalize`
// turns whatever arrives into this shape, so a missing field is a default, never a crash.

export type QuestionId =
  | "timeline"
  | "wake"
  | "nosleep"
  | "battery"
  | "crash"
  | "slow"
  | "now"
  | "doctor";

export interface Evidence {
  source: string;
  recordId: string | null;
  timestamp: string | null;
  fields: [string, string][];
}

export interface Gap {
  what: string;
  wouldCapture: string;
}

export interface Fix {
  /** `null` when the command was withheld because it held control or direction characters. */
  command: string | null;
  withheld: boolean;
  explanation: string;
  needsAdmin: boolean;
}

export interface Finding {
  id: string;
  time: string | null;
  headline: string;
  explanation: string;
  /** `recorded`, `correlated`, `sampled` or `not_recorded`; anything else is shown as it came. */
  confidence: string;
  evidence: Evidence[];
  gap: Gap | null;
  fix: Fix | null;
}

export interface Access {
  kind: string;
  message: string;
  code: number | null;
}

export interface Limit {
  source: string;
  access: Access;
  adds: string | null;
}

export interface Window {
  since: string;
  limit: number;
  sinceIsDefault: boolean;
  limitIsDefault: boolean;
}

export interface Reply {
  question: string;
  generatedAt: string;
  findings: Finding[];
  limits: Limit[];
  labels: Record<string, string>;
  window: Window | null;
  notice: string | null;
}
