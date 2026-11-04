import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const read = (...parts: string[]): string => readFileSync(join(import.meta.dirname, "..", ...parts), "utf8");
const sources = readdirSync(join(import.meta.dirname, "..", "src"))
  .filter((name) => name.endsWith(".ts"))
  .map((name) => [name, read("src", name)] as const);

describe("nothing can turn log text into markup", () => {
  it("uses no HTML-parsing API anywhere in src/", () => {
    const banned = /\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser|eval\(|new Function)/;
    for (const [name, text] of sources) {
      expect(banned.test(text), `${name} uses a markup-parsing API`).toBe(false);
    }
  });

  it("loads nothing from outside the app", () => {
    for (const [name, text] of sources) {
      expect(/https?:\/\/|fetch\(|XMLHttpRequest|WebSocket|sendBeacon|import\(/.test(text), `${name} reaches out`).toBe(false);
    }
    const css = read("src", "style.css");
    expect(/url\(|@import|https?:\/\//.test(css)).toBe(false);
  });
});

describe("the Tauri configuration is locked down", () => {
  const conf = JSON.parse(read("src-tauri", "tauri.conf.json"));
  const csp: string = conf.app.security.csp;

  it("has a strict content security policy with no remote origin and no eval", () => {
    expect(csp).toContain("default-src 'self'");
    // The one http origin is Tauri's own local bridge to the Rust side.
    expect(csp.replace("http://ipc.localhost", "")).not.toMatch(/unsafe-eval|unsafe-inline|https?:|\*/);
    expect(csp).toContain("object-src 'none'");
  });

  it("keeps the global Tauri object off", () => {
    expect(conf.app.withGlobalTauri).toBe(false);
  });

  it("grants the main window only the nine commands and no plugin", () => {
    const capability = JSON.parse(read("src-tauri", "capabilities", "default.json"));
    expect(capability.windows).toEqual(["main"]);
    for (const permission of capability.permissions as string[]) {
      expect(permission).toMatch(/^allow-(timeline|wake|nosleep|battery|crash|slow|now|doctor|elevated)$/);
    }
    expect(capability.permissions).toHaveLength(9);
    expect(conf.plugins ?? {}).toEqual({});
    const cargo = read("src-tauri", "Cargo.toml");
    expect(/tauri-plugin|updater|reqwest|hyper|ureq/.test(cargo)).toBe(false);
  });
});
